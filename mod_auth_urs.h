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
 * mod_auth_urs.h: URS OAuth2 Module
 *
 * Header declarations file for mod_auth_urs.
 *
 * Author: Peter Smith
 *
 *
 */

#include    "httpd.h"
#include    "http_core.h"
#include    "http_config.h"


extern module AP_MODULE_DECLARE_DATA auth_urs_module;



/****************************************
 * Server level declarations
 ***************************************/

/**
 * URS oauth2 module server level configuration structure.
 *
 */
typedef struct auth_urs_svr_config_t
{
    /**
     * The location of the directory in which to store session
     * data. All session data is stored here.
     */
    char*       session_store_path;

    /**
     * The address of the URS authentication server
     */
    apr_uri_t   urs_auth_server;

    /**
     * The path of the URS authentication request endpoint
     */
    char*       urs_auth_path;

    /**
     * The path of the URS token exchange endpoint
     */
    char*       urs_token_path;

    /**
     * A table of redirection URIs. The key is a host:path string (no port),
     * and the value is the authorization group. This is not configured
     * explicitly - it is built up from the directory level configuration.
     * The path is the simply the URL portion of the redirection url for
     * the given hostname. The authorization group is a simple name (also
     * used to name the session cookie) that represents a set of directories
     * that can all be accessed with the same login.
     */
    apr_table_t* redirection_map;

} auth_urs_svr_config;




/**
 * URS oauth2 module directory level configuration structure.
 *
 */
typedef struct auth_urs_dir_config_t
{

    /**
     * Used as the name of the session cookie. This is based upon
     * the per-directory 'UrsAuthGroup' configuration, and permits
     * authentication of groups of applications on a single
     * server.
     */
    char*       authorization_group;


    /**
     * The client ID assigned when the application was registered
     * for this particular location.
     */
    char*       client_id;

    /**
     * The authorization code to be passed to the server. This
     * code embeds the password, so whatever file it resides in
     * should be restricted.
     */
    char*       authorization_code;


    /**
     * Enables cookie based sessions.
     */
    int         use_cookie_sessions;


    /**
     * Enables cookie storage of original URLs
     */
    int         use_cookie_url;
    

    /**
     * The domain to be used for cookie configuration. This is generally only
     * useful for cookie based sessions to allow a single login across
     * multiple applications.
     */
    char*       cookie_domain;


    /**
     * The passphrase to be used for encrypted sessions.
     */
    char*       session_passphrase;


    /**
     * The name to user for anonymous access. If this is set,
     * anonymous access is enabled.
     */
    char*       anonymous_user;

    /**
     * The name to user for HEAD access. If this is set,
     * HEAD requests are enabled for protected files.
     */
    char*       head_user;

    /**
     * The application redirection URLs. These can be configured on a
     * per-hostname basis (for server aliases). The key is the server name,
     * and the value is the parsed redirct-url.
     */
    apr_table_t* redirect_urls;


    /**
     * The idle timeout on a session. If a session has not
     * been used for this amount of time, it will be destroyed,
     * (forcing re-authentication). Set to 0 to disable.
     */
    long        idle_timeout;


    /**
     * The timeout on an active session. Set to 0 to
     * disable. This destroys a session after the given
     * time (in seconds), regardless of whether the session
     * is in use. Generally, this should be set to something
     * like 12 hours (43200) or 24 hours (86400).
     */
    long        active_timeout;


    /**
     * The number of parts of the IP4 address octets to check
     * as part of session verification. 0 disables.
     */
    int         check_ip_octets;


    /**
     *  Disables the URS Oauth2 splash screen
     */
    int         splash_disable;


    /**
     *  Enables the 401 response from URS
     */
    int         auth401_enable;


    /**
     * A table of user profile parameters to save in the
     * sub-process environment.
     *
     */
    apr_table_t* user_profile_env;


    /**
     * The access error redirection URL
     */
    char*       access_error_url;


    /**
     * The access error resource parameter name
     */
    char*       access_error_parameter;

} auth_urs_dir_config;



/**
 * URS oauth2 module input filter context structure.
 * This structure is used to pass POST body information
 * through to the input filter.
 */
typedef struct auth_urs_post_input_filter_ctx_t
{
    /*
     * A pointer to the post body contents
     */
    char*  body;

    /*
     * The size of the post body
     */
    int  body_size;

} auth_urs_post_input_filter_ctx;


/**
 * Early request processing hook designed to capture the redirection
 * that comes back from the authentication server. It checks to
 * see if the request is for a configured redirection URL
 * (UrsRedirectUrl directive in the directory level configuration).
 * If so, it extracts the URS authentication code and the state
 * query parameters, and redirects the user back to the original
 * page the requested when authentication was invoked. The URL
 * of the orignal request is encoded using the state query parameter.
 *
 * @param r a pointer to the request_rec structure
 * @return DECLINED or HTTP status code
 */
int auth_urs_post_read_request_redirect(request_rec* r);



/**
 * Early request processing hook designed to provide a logout
 * capability. This is intended to be transparent to the
 * request processing, so this method always returns the
 * DECLINE status.
 *
 * @param r a pointer to the request_rec structure
 * @return DECLINED
 */
int auth_urs_post_read_request_logout(request_rec* r);



/**
 * Checks to see whether URS OAuth2 type authentication should
 * be performed on the request. This is a hook callback method
 * invoked by apache as part of the request processing, and
 * performs the intial redirection as well as token exchange.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @return DECLINED or HTTP status
 */
int auth_urs_check_user_id(request_rec* r);


/*
 * Declaration for the POST body input filter function.
 */
apr_status_t auth_urs_post_body_filter(
        ap_filter_t* f,
        apr_bucket_brigade* bb,
        ap_input_mode_t mode,
        apr_read_type_e block,
        apr_off_t readbytes );



/****************************************
 * JSON declarations
 ***************************************/


/**
 * JSON reference pointer used for handling json objects.
 */
typedef struct json json;


/**
 * JSON member type enumeration
 */
typedef enum
{
    json_string,
    json_number,
    json_object,
    json_array,
    json_boolean,
    json_null

} json_type;


/**
 * Parse a text string into a json object.
 * @param pool the pool to use for memory allocation
 * @param json_text the text to parse
 * @return a pointer to a json object, or NULL if the text
 *         could not be parsed.
 */
json* json_parse( apr_pool_t* pool, const char* json_text );


/**
 * Return whether or not the named json member exists.
 * @param json the json object to search
 * @param name the name of the member to test
 * @return true if the named member exists, false otherwise
 */
int json_has_member(json* json, const char* name );


/**
 * Return a named json member object.
 * @param json the json object to search
 * @param name the name of the member to be returned
 * @return a pointer to the json object, or NULL it the named
 *         member is not a json object.
 */
json* json_get_member_object(json* json, const char* name );


/**
 * Return the value of a named json member.
 * @param json the json object to search
 * @param name the name of the member whose value is to be returned
 * @return a pointer to the json member value, or NULL it the named
 *         member does not exist or is not a suitable type (e.g array)
 */
const char* json_get_member_string(json* json, const char* name );


/**
 * Return the type of a named json member.
 * @param json the json object to search
 * @param name the name of the member whose type is to be returned
 * @return the type of the named member, or json_null if it does
 *         not exists. Note that json_null is also a valid type.
 */
json_type json_get_member_type(json* json, const char* name );




/****************************************
 * Session declarations
 ***************************************/


/**
 * Constructs a data packet containing all the given session data.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param session pointer to the table containing the session data.
 * @param len used to return the size of the packet
 * @return a pointer to the packet (may contain embedded nulls)
 */
const unsigned char* session_pack(
        request_rec *r,
        apr_table_t* session,
        int* len);



/**
 * Reconstructs a session from a stored session packet.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param buffer the session packet buffer
 * @param len the lenght of the session packet
 * @param session pointer to the table into which the session data will be placed
 * @return APR_SUCCESS, or an error code
 */
apr_status_t session_unpack(
        request_rec *r,
        const unsigned char* buffer,
        int len,
        apr_table_t* session );


/**
 * Creates a unique cookie ID that can be used as a session
 * reference.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @return a pointer to the name of a new, unique, session ID.
 */
const char* session_create_id(request_rec *r);



/**
 * Writes session data to a session file. Note that the session data
 * must have been packed using the 'session_pack' method. It may also
 * be encrypted.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param session_id the session id (will be used as the filename).
 * @param data the current session data packet that should be stored.
 * @param len the length of the session data packet.
 * @return APR_SUCCESS on success.
 */
apr_status_t session_write_file(
        request_rec *r,
        const char* session_id,
        const unsigned char* data,
        int len );



/**
 * Reads session data from a session file.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param session_id the session id (will be used as the filename).
 * @param len returns the length of the session data packet.
 * @return a pointer to the session data file, or NULL if no session
 *          data file could be found.
 */
const unsigned char* session_read_file(
        request_rec *r,
        const char* session_id,
        int* len);


/**
 * Deletes a session file.
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param session_id the session id of the file to destroy
 *
 * @return APR_SUCCESS.
 */
apr_status_t session_destroy_file(request_rec *r, const char* session_id);


/****************************************
 * HTTP declarations
 ***************************************/

/**
 * Extracts the value of a query parameter from the client request.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param parameter the name of the query parameter to extract.
 * @return a pointer to the query parameter value, or NULL
 *         if it did not exist or was empty.
 */
char* http_get_query_param(
        request_rec* r,
        const char* parameter );


/**
 * Extracts the value of a named cookie.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param cookie_name the name of the cookie extract.
 * @return a pointer to the cookie value, or NULL
 *         if it did not exist or was empty.
 */
char* http_get_cookie(
        request_rec* r,
        const char* cookie_name );


/**
 * Deletes a named cookie.
 * This only deletes the cookie in the input headers, so a subsequent
 * handler will not find it.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @param cookie_name the name of the cookie extract.
 */
void http_delete_cookie(
        request_rec* r,
        const char* cookie_name );


/**
 * Encode a URL string.
 * This function maps reserved characters in a string to their % equivalent.
 *
 * @param pool the pool from which to allocate memory
 * @param uri the URI to encode.
 * @return a pointer to the encoded string. This can be the same
 *         string if no encoding is necessary.
 */
const char* http_url_encode(
        apr_pool_t *pool,
        const char* uri );


/**
 * Decode a URL string.
 * This function maps % encoded characters back to their string equivalent
 *
 * @param pool the pool from which to allocate memory
 * @param uri the URI to decode.
 * @return a pointer to the decoded string. This can be the same
 *         string if no decoding is necessary.
 */
const char* http_url_decode(
        apr_pool_t *pool,
        const char* uri );


/**
 * Performs an http post type request and reads the response.
 *
 * @param r the current request (used for configuration/memory pool allocations)
 * @param server URI containing the address of the server to send the request to
 * @param path the path to post
 * @param headers a table of headers to send. Also used to return response
 *        headers.
 * @param body the body of the request to send. Also used to return the
 *        response body.
 * @return the response status
 */
int http_post(
        request_rec *r,
        apr_uri_t* server,
        const char* path,
        apr_table_t* headers,
        char** body);


/**
 * Performs an http get type request and reads the response.
 *
 * @param r the current request (used for configuration/memory pool allocations)
 * @param server URI containing the address of the server to send the request to
 * @param path the path to post
 * @param headers a table of headers to send. Also used to return response
 *        headers.
 * @param body returns the response body
 * @return the response status
 */
int http_get(
        request_rec *r,
        apr_uri_t* server,
        const char* path,
        apr_table_t* headers,
        char** body);


/**
 * Reads the body of an HTTP request.
 *
 * @param r the current request (used for configuration/memory pool allocations)
 * @param buffer the buffer into which the data will be placed
 * @param size the size of the buffer. Used also to return the size of the data.
 * @return the response status
 *
 */
int http_get_request_body(
        request_rec* r,
        char* buffer,
        int* size );


/****************************************
 * SSL declarations
 ***************************************/

/**
 * External representation of a connection.
 */
typedef struct ssl_connection ssl_connection;


/**
 * Establishes an SSL connection to a remote server.
 * @param r a pointer to the apache request_rec structure.
 * @param host the name of the host to connect to
 * @param port the port number to connect to
 * return a pointer to an ssl_connection structure, or
 *        NULL on error
 */
ssl_connection *ssl_connect(request_rec* r, const char* host, int port );



/**
 * Close and tidy up an SSL connection.
 * @param r a pointer to the current request (not currently needed)
 * @param c a pointer to the ssl_connection structure to be cleaned
 */
void ssl_disconnect(request_rec* r, ssl_connection *c );


/**
 * Reads a chunk of data from the SSL connection.
 * @param r a pointer to the current request
 * @param c a pointer to the ssl_connection structure to be
 *          read from.
 * @param buffer the buffer into which the data is to be placed
 * @param bufsize the size of the buffer.
 * @return the number of bytes read, or negative error number
 */
int ssl_read(request_rec* r, ssl_connection *c, char* buffer, int bufsize);


/**
 * Writes a chunk of data to the SSL connection.
 * @param r a pointer to the current request
 * @param c a pointer to the ssl_connection structure to be
 *          read from.
 * @param buffer the data to be written
 * @param bufsize the size of the data in the buffer.
 * @return the number of bytes written, or negative error number
 */
int ssl_write(request_rec* r, ssl_connection *c, char* buffer, int bufsize );



/****************************************
 * Crypto declarations
 ***************************************/


/**
 * Encrypts a data packet.
 * @param r a pointer to the current request
 * @param p a pointer to the block of data to encrypt
 * @param len the length of the data block. Also returns the length of
 *          the encrypted block on return.
 * @param passphrase the passphrase to use to encrypt the data block.
 * @return a pointer to the encrypted data block.
 */
const unsigned char* crypto_encrypt_packet(
        request_rec *r,
        const unsigned char *p,
        int *len,
        const char* passphrase);



/**
 * Decrypts a data packet.
 * @param r a pointer to the current request
 * @param p a pointer to the block of data to decrypt
 * @param len the length of the data block. Also returns the length of
 *          the decrypted block on return.
 * @param passphrase the passphrase to use to decrypt the data block.
 * @return a pointer to the decrypted data block.
 */
const unsigned char* crypto_decrypt_packet(
        request_rec *r,
        const unsigned char *p,
        int *len,
        const char* passphrase);
