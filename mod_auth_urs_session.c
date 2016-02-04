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

static int write_urs_session_pairs(void *fd, const char* key, const char* value );




/************************************
 * Exported (external) methods
 ************************************/


/**
 * Writes session data table to a session file.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param auth_cookie the cookie value. This is used to identify
 *          the session file.
 * @param session_data the current session data that should be stored.
 * @return APR_SUCCESS on success.
 */
apr_status_t write_urs_session(request_rec *r, const char* auth_cookie, apr_table_t* session_data )
{
    auth_urs_svr_config*    conf;
    char*               session_file;
    apr_file_t*         fd;
    apr_status_t        results;

    int                 open_flags = APR_READ | APR_WRITE | APR_CREATE;
    int                 open_perms = APR_FPROT_UREAD | APR_FPROT_UWRITE;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );

    /*
     * Build the session file name
     */
    session_file = apr_pstrcat(r->pool, conf->session_store_path, auth_cookie, NULL);


    /*
     * Open the session file for writing
     */
    results = apr_file_open( &fd, session_file, open_flags, open_perms, r->pool );
    if( results != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Unable to open session file for output: %s", session_file );

        return results;
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
     * Write the session file. All data is output
     * simply as name/value null terminated string pairs. This makes it
     * far easier to read it back in!
     */
    results = TRUE;
    if( session_data != NULL )
    {
        results = apr_table_do(write_urs_session_pairs, fd, session_data, NULL);
    }


    /*
     * Release the lock and close the file.
     */
    apr_file_unlock(fd);

    apr_file_close(fd);
    if( !results )
    {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
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
apr_status_t read_urs_session(request_rec *r, const char* auth_cookie, apr_table_t* session_data )
{
    auth_urs_svr_config*    conf;
    char*               session_file;
    char*               session_content;
    char*               key;
    char*               value;
    apr_file_t*         fd;
    apr_status_t        results;
    apr_finfo_t         finfo;
    apr_size_t          nbytes;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /*
     * Build the session file name
     */
    session_file = apr_pcalloc(r->pool, strlen(conf->session_store_path) + strlen(auth_cookie) + 2);
    strcpy(session_file, conf->session_store_path);
    strcat(session_file, auth_cookie);


    /*
     * Get the session file size so we can load it into a contiguous chunk
     * of memory. We place an upper limit on the size.
     */
    if( apr_stat(&finfo, session_file, APR_FINFO_SIZE, r->pool) != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Unable to test session file for input: %s", session_file );
        return APR_EGENERAL;
    }
    if( finfo.size > 1024 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Possible session file corruption: %s", session_file );
        return APR_EGENERAL;
    }


    /*
     * Open the session file
     */
    results = apr_file_open( &fd, session_file, APR_READ, APR_FPROT_UREAD, r->pool );
    if( results != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Unable to open session file for input: %s", session_file );

        return results;
    }


    /*
     * Allocate memory from the connection pool (it will persist
     * for the duration of the connection) and load the session
     * file.
     */
    session_content = apr_pcalloc(r->connection->pool, finfo.size );
    nbytes = finfo.size;

    if( apr_file_read(fd, session_content, &nbytes) != APR_SUCCESS
        || nbytes != finfo.size )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Failed to read session content: %s", session_file );

        apr_file_close(fd);
        return APR_EGENERAL;
    }
    apr_file_close(fd);


    /*
     * Process the data into key/value pairs and load into the session
     * table. For efficiency, we use the original memory used to load
     * the file.
     */
    nbytes = 0;
    while( nbytes < finfo.size )
    {
        key = session_content + nbytes;
        nbytes += strlen(key) + 1;
        value = session_content + nbytes;
        nbytes += strlen(value) + 1;

        apr_table_setn(session_data, key, value);
    }

    if( nbytes != finfo.size )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "Failed to load session data");

        return APR_EGENERAL;
    }


    return APR_SUCCESS;
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
apr_status_t destroy_urs_session(request_rec *r, const char* auth_cookie)
{
    auth_urs_svr_config*  conf;
    char*                 session_file;


    conf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /* Build the session file name */

    session_file = apr_pcalloc(r->pool, strlen(conf->session_store_path) + strlen(auth_cookie) + 2);
    strcpy(session_file, conf->session_store_path);
    strcat(session_file, auth_cookie);


    /* Delete session file */

    apr_file_remove(session_file, r->pool );

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
const char* create_urs_cookie_id(request_rec *r)
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


/**
 * Creates an encrypted session cookie
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param session_data a table with the session data that needs to be saved.
 * @return a pointer to the cookie value containing the encrypted and encoded
 *          session data.
 */
const char* create_urs_encrypted_cookie(request_rec *r, apr_table_t* session_data)
{
    char *content = "";
    const apr_array_header_t*   elements;


    /* Write the session data into a string */

    elements = apr_table_elts(session_data);
    if( elements->nelts > 0 )
    {
        const apr_array_header_t* elements;
        const apr_table_entry_t*  entry;
        int   i;

        elements = apr_table_elts(session_data);
        entry = (const apr_table_entry_t*) elements->elts;

        /*
         * Iterate through each key/value pair and add to the combined string.
         * Note that we url encode the values so we can use a separator
         * without worring about the separator value appearing in the data.
         * Note that this is an inefficient algorithm.
         */
        for( i = 0; i < elements->nelts; ++i )
        {
            content = apr_pstrcat(r->pool, content, "&",
                url_encode(
                    r->pool, entry[i].key), "|",
                    url_encode(r->pool, entry[i].val), NULL);
        }


        ++content; /* Discard the first '&' */

#ifdef USE_CRYPTO

        /* Encrypt the session data */

        if (1) {
            int rv;
            unsigned char* packet = NULL;
            apr_size_t len;

            /* Encrypt the data - this produces binary */

            rv = encrypt_block(content, strlen(content), &packet, &len, r);
            if (rv != APR_SUCCESS) return "";

            /* Now base64 encode it */

            content = apr_palloc(r->pool, apr_base64_encode_len(len) + 1);
            apr_base64_encode(content, (const char *) packet, len);
        }
#endif
    }

    return content;
}



/**
 * Reads an encrypted session cookie into a session data table.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param cookie the cookie value (the encrypted session data)
 * @param session_data a table into which all the session data
 *          will be placed.
 * @return APR_SUCCESS on success.
 */
apr_status_t read_urs_encrypted_cookie(request_rec *r, const char* cookie, apr_table_t* session_data )
{
    char *p;
    char *e, *s;

#ifdef USE_CRYPTO

    /* Decrypt the packet */

    if (1) {
        int rv;
        unsigned char *decrypted = NULL;
        unsigned char *packet = NULL;
        apr_size_t len, decryptedLen;

        /* Base64 decode the data first */

        packet = apr_palloc(r->pool, apr_base64_decode_len(cookie));
        len = apr_base64_decode(packet, cookie);

        /* Now decrypt it */

        rv = decrypt_block(packet, len, &decrypted, &decryptedLen, r);
        if (rv != APR_SUCCESS) return rv;
        cookie = decrypted;
    }
#endif

    p = apr_pstrdup(r->pool, cookie);

    do
    {
        e = strchr(p, '&');
        if (e) *e = '\0';

        s = strchr(p, '|');
        if (s == NULL) return APR_EGENERAL;
        *s = '\0';

        apr_table_set(session_data, url_decode(r->connection->pool, p), url_decode(r->connection->pool, s+1));
        p = e + 1;
    } while(e);

    return APR_SUCCESS;
}



/************************************
 * Static (internal) methods
 ************************************/


/**
* Support method used to iterate through a table and output
* key/value pairs.
* @param fd descriptor of file to write session data to
* @param key the name of the session data key
* @param value the session data value
* @return 1 (as required)
*/
static int write_urs_session_pairs(void *fd, const char* key, const char* value )
{
    apr_file_printf(fd, "%s%c%s%c", key, 0, value, 0);

    return 1;
}
