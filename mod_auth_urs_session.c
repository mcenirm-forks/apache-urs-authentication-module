/*
 * Copyright 2014 NASA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * mod_auth_urs_session.c: URS OAuth2 Module
 *
 * This file contains code relating to the management of
 * session files and the generation of cookies.
 *
 * Author: Peter Smith
 */


#include    "mod_auth_urs.h"


#include    "http_config.h"
#include    "http_log.h"

#include    "apr_sha1.h"
#include    "apr_strings.h"
#include    "apr_uuid.h"


/**
 * Internal method declarations.
 *
 */
static int write_session_pair(void *vdata, const char* key, const char* value );

/**
 * Internal structure used when packing session data.
 */
typedef struct session_packet_t
{
    apr_pool_t*     pool;
    unsigned char*  buffer;
    int             size;
    int             len;
} session_packet;



/************************************
 * Exported (external) methods
 ************************************/


/**
 * Constructs a data packet containing all the given session data.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param session pointer to the table containing the sessio data.
 * @param len used to return the size of the packet
 * @return a pointer to the packet (may contain embedded nulls)
 */
const unsigned char* session_pack(request_rec *r, apr_table_t *session, int *len)
{
    /* Set up an initial buffer for constructing the session packet */

    session_packet data = {
        r->pool,
        apr_pcalloc(r->pool, 2048),
        2048,
        0
    };

    apr_table_do(write_session_pair, &data, session, NULL);

    *len = data.len;
    return data.buffer;
}



/**
 * Reconstructs a session from a stored session packet.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param buffer the session packet buffer
 * @param len the lenght of the session packet
 * @param session pointer to the table into which the session data will be placed
 * @return APR_SUCCESS, or an error code
 */
apr_status_t session_unpack(request_rec *r, const unsigned char* buffer, int len, apr_table_t* session )
{
    const char*         key;
    const char*         value;
    int                 nbytes;


    /*
     * Process the data into key/value pairs and load into the session
     * table. This will use the tables assigned pool.
     */
    nbytes = 0;
    while( nbytes < len )
    {
        key = (const char*) buffer + nbytes;
        nbytes += strlen(key) + 1;
        value = (const char*) buffer + nbytes;
        nbytes += strlen(value) + 1;

        apr_table_set(session, key, value);
    }

    if( nbytes != len )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Failed to load session data - size mismatch");

        return APR_EGENERAL;
    }


    return APR_SUCCESS;
}



/**
 * Writes session data table to a session file.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param auth_cookie the cookie value. This is used to identify
 *          the session file.
 * @param session_data the current session data that should be stored.
 * @return APR_SUCCESS on success.
 */
apr_status_t session_write_file(request_rec *r, const char* session_id, const unsigned char* data, int len )
{
    auth_urs_svr_config*    conf;

    char*               session_file;
    apr_file_t*         fd;
    apr_status_t        result;
    apr_size_t          size = len;
    int                 open_flags = APR_READ | APR_WRITE | APR_CREATE;
    int                 open_perms = APR_FPROT_UREAD | APR_FPROT_UWRITE;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );

    /*
     * Build the session file name
     */
    if (conf->session_store_path == NULL) {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: No configured session storage path");

        return APR_EGENERAL;
    }
    session_file = apr_pstrcat(r->pool, conf->session_store_path, session_id, NULL);


    /*
     * Open the session file for writing
     */
    result = apr_file_open( &fd, session_file, open_flags, open_perms, r->pool );
    if( result != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Unable to open session file for output: %s", session_file );

        return result;
    }


    /*
     * Attempt to get an exclusive lock on the file to prevent a parallel request
     * from the same client from trying to do the same. If we fail, we pause for
     * 100 milliseconds and try again. A second failure is passed back.
     */
     if( apr_file_lock(fd, APR_FLOCK_EXCLUSIVE) != APR_SUCCESS )
     {
        apr_interval_time_t pause = 100000;
        apr_sleep(pause);

        if( apr_file_lock(fd, APR_FLOCK_EXCLUSIVE) != APR_SUCCESS )
        {
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to lock session file %s", session_file );

            apr_file_close(fd);
            return APR_EGENERAL;
        }
     }


    /*
     * Truncate the file. We cannot do this as part of the open, since we
     * do not have the lock at that point, and some other thread may be in
     * the process of writing to it.
     */
    apr_file_trunc(fd, 0);


    /*
     * Write the data packet to the session file.
     */
    result = apr_file_write(fd, data, &size);
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "Wrote %d bytes to session file %s", (int) size, session_file );


    /*
     * Release the lock and close the file.
     */
    apr_file_unlock(fd);

    apr_file_close(fd);

    return result;
}



/**
 * Reads a session file into a session data table.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param auth_cookie the cookie value. This is used to identify
 *          the session file.
 * @param session_data a table into which all the session data
 *          will be placed.
 * @return APR_SUCCESS on success.
 */
const unsigned char* session_read_file(request_rec *r, const char* session_id, int* len )
{
    auth_urs_svr_config*    conf;
    char*               session_file;
    unsigned char*      session_content;
    apr_file_t*         fd;
    apr_status_t        results;
    apr_finfo_t         finfo;
    apr_size_t          nbytes;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /* Build the session file name */

    session_file = apr_pstrcat(r->pool, conf->session_store_path, session_id, NULL);


    /*
     * Get the session file size so we can load it into a contiguous chunk
     * of memory. We place an upper limit on the size.
     */
    if( apr_stat(&finfo, session_file, APR_FINFO_SIZE, r->pool) != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Unable to test session file for input: %s", session_file );
        return NULL;
    }
    if( finfo.size > 2048 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Possible session file corruption: %s", session_file );
        return NULL;
    }


    /*
     * Open the session file
     */
    results = apr_file_open( &fd, session_file, APR_READ, APR_FPROT_UREAD, r->pool );
    if( results != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Unable to open session file for input: %s", session_file );

        return NULL;
    }


    /*
     * Allocate memory for loading the file contents
     */
    session_content = apr_pcalloc(r->pool, finfo.size );
    nbytes = finfo.size;

    if( apr_file_read(fd, session_content, &nbytes) != APR_SUCCESS
        || nbytes != finfo.size )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Failed to read session content: %s", session_file );

        apr_file_close(fd);
        return NULL;
    }
    apr_file_close(fd);

    *len = finfo.size;
    return session_content;
}



/**
 * Deletes a session file.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param auth_cookie the cookie value. This is used to identify
 *          the session file.
 *
 * @return APR_SUCCESS.
 */
apr_status_t session_destroy_file(request_rec *r, const char* session_id)
{
    auth_urs_svr_config*  conf;
    char*                 session_file;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /* Build the session file name */

    session_file = apr_pstrcat(r->pool, conf->session_store_path, session_id, NULL);


    /* Delete session file if it exists */

    if (apr_file_remove(session_file, r->pool) == APR_SUCCESS)
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Removed session file: %s", session_file );

    return APR_SUCCESS;
}



/**
 * Creates a unique cookie ID that can be used as a session
 * reference.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @return a pointer to the name of a new, unique, session
 */
const char* session_create_id(request_rec *r)
{
    auth_urs_svr_config*    conf;

    apr_uuid_t      uuid;
    apr_status_t    result;
    apr_file_t*     fd;

    char*           session_file;
    int             offset;
    int             i = 0;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /*
     * Check to see if mod_unique_id is running - it will provide a unique
     * identifier for every request (even across clusters). This is our
     * best case scenario.
     */
    if( apr_table_get(r->subprocess_env, "UNIQUE_ID") != NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Using UNIQUE_ID %s", apr_table_get(r->subprocess_env, "UNIQUE_ID"));
        return apr_table_get(r->subprocess_env, "UNIQUE_ID");
    }


    /*
     * Fall back to using a generated UUID for the session name. We test
     * this by attempting to create the session file.
     */
    offset = strlen(conf->session_store_path);
    session_file = apr_palloc(r->pool, offset + APR_UUID_FORMATTED_LENGTH + 10);
    strcpy(session_file,  conf->session_store_path );

    do
    {
        int open_flags = APR_WRITE | APR_CREATE | APR_EXCL;
        int open_perms = APR_FPROT_UREAD | APR_FPROT_UWRITE;

        if( ++i == 10 ) return NULL;

        /*
         * Generate a (hopefully) UUID
         */
        apr_uuid_get(&uuid);
        apr_uuid_format(session_file + offset, &uuid);


        /*
         * Test its uniqueness by trying to open the file in exclusive mode.
         * If the file already exists, the open will fail. Otherwise it will
         * succeed, and we have created the file to prevent any other threads
         * from using the same session id.
         */
        result = apr_file_open( &fd, session_file, open_flags, open_perms, r->pool );

    } while( result != APR_SUCCESS );

    apr_file_close(fd);

    return (session_file + offset);
}



/************************************
 * Static (internal) methods
 ************************************/

/**
 * Iterator method used to write a table key/value pair into a data packet.
 * @param vdata pointer to the data buffer
 * @param key the name of the session data key
 * @param value the session data value
 * @return 1 (as required)
 */
static int write_session_pair(void *vdata, const char* key, const char* value )
{
    session_packet* data = vdata;
    int lk = strlen(key);
    int lv = strlen(value);

    /* Check to see if we need to resize the buffer */

    if ((data->len +lk + lv + 2) > data->size ) {
        unsigned char* p = data->buffer;
        data->size += lk + lv + 2048;
        data->buffer = apr_pcalloc(data->pool, data->size);
        memcpy(data->buffer, p, data->len);
    }

    /* Copy the key and value into the buffer */

    strcpy((char*) data->buffer + data->len, key);
    data->len += lk + 1;

    strcpy((char*) data->buffer + data->len, value);
    data->len += lv + 1;

    return 1;
}
