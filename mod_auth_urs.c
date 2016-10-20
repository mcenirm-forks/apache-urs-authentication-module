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
 * mod_auth_urs.c: URS OAuth2 Module
 *
 * This file contains the code that controls the overall flow
 * of the authentication process.
 *
 * This module uses cookies and session files to manage client
 * authentication state. Note that these are not generated until
 * after a successful token exchange (although it makes it a little
 * more complicated) in order to prevent a malicious client from
 * filling up our session directory by continuously pinging a
 * redirection point.
 *
 * Session files are managed by the module. Curently, an external cron
 * should be used to remove old session files at least once per-day.
 * The sesson files are located in the directory specified by
 * UrsSessionStorePath, and should exceed the age specified by
 * UrsIdleTimeout or UrsActiveTimeout before being cleaned up.
 *
 * Author: Peter Smith
 */

#include    "mod_auth_urs.h"


#include    "apr_base64.h"
#include    "apr_strings.h"
#include    "apr_uuid.h"
#define APR_WANT_STRFUNC           /* for strcasecmp */
#include    "apr_want.h"

#include    "httpd.h"
#include    "http_config.h"
#include    "http_core.h"
#include    "http_request.h"
#include    "http_log.h"
#include    "http_protocol.h"



/**
 * Internal method declarations.
 *
 */
static int validate_session(request_rec *r, const char* cookie, apr_table_t* session_data );
static int retrieve_user_profile(request_rec *r,auth_urs_dir_config* dconf, const char* access_token,const char* endpoint,json** profile );
static int token_exchange(request_rec *r, auth_urs_dir_config* dconf, const char** access_token, const char** endpoint);
int save_session(request_rec *r, auth_urs_dir_config *dconf, apr_table_t* session, const char* session_id);



/************************************
 * Exported (external) methods
 ************************************/

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
int auth_urs_post_read_request_redirect(request_rec *r)
{
    auth_urs_svr_config*    sconf = NULL;
    auth_urs_dir_config*    dconf = NULL;

    const char*     code = NULL;
    const char*     state = NULL;
    const char*     cookie_name = NULL;

    request_rec*    sub_req;
    const char*     access_token;
    const char*     endpoint;
    json*           user_profile;
    long            current_time;
    apr_table_t*    session;

    const apr_array_header_t* elements;

    char*           url_str;
    int             status;
    apr_uri_t       url;

    const char*     hostname = r->hostname ? r->hostname : r->server->server_hostname;
    const char*     p;

    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /*
     * Check to see if this request is a redirection URL. To determine this,
     * we check for an authorization group assigned to the host:path of the
     * request. If found, we must handle it, otherwise we decline and allow
     * someone else to do so.
     */
    p = strchr(hostname, ':');
    if( p != NULL ) hostname = apr_pstrndup(r->pool, hostname, p - hostname);
    p = apr_pstrcat(r->pool, hostname, ":", r->uri, NULL);


    /* The authorization group name is used as the cookie name */

    cookie_name = apr_table_get(sconf->redirection_map, p);
    if( cookie_name == NULL ) {
        /* This is not a redirection point */

        return DECLINED;
    }
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Authentication redirect for auth group %s: %s", cookie_name, r->uri );


    /*
     * URS is expected to return our 'state' query parameter, regardless
     * of whether the authentication was successful or not. We must url
     * decode this first.
     */
    state = http_get_query_param(r, "state");
    if( state == NULL ) {
        /* Assume a bad link or hack */

        return HTTP_FORBIDDEN;
    }
    
    
    /*
     * If we have a url cookie, extract it and use it if the state key matches. We also
    * expire the cookie.
     */
    url_str = http_get_cookie(r, apr_pstrcat(r->pool, cookie_name, "_url", NULL));
    if (url_str) {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r, "UrsAuth: Found cookie %s_url: %s", cookie_name, url_str );
        state = http_url_decode(r->pool, state);
        if (strstr(url_str, state) == url_str) {
            state = url_str + strlen(state) + 1;

            apr_table_addn(r->err_headers_out,
                "Set-Cookie",
                apr_pstrcat(r->pool,
                    cookie_name, "_url=; Expires=Sat, 01 Jan 2000 00:00:00 GMT; Path=/", NULL) );
        }
    }


    /*
     * Reconstruct the original URL from the state query parameter.
     * We are going to use this to generate a sub-request for the
     * purposes of extract the appropriate per-directory
     * configuration information we need for the token exchange.
     * Note that we do not explicitly call ap_destroy_sub_req for
     * the sub request - the main request does that when its pool
     * gets destroyed.
     */
    url_str = apr_palloc(r->pool, strlen(state) + 1);
    apr_base64_decode(url_str, state);
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r, "UrsAuth: Decoded URL is %s", url_str );

    if( apr_uri_parse(r->pool, url_str, &url) != APR_SUCCESS ) {
        return HTTP_BAD_REQUEST;
    }

    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Subrequest processing for %s", url_str );
    sub_req = ap_sub_req_lookup_uri(url.path, r, NULL);
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Subrequest returned %d", r->status );


    /*
     * We do not need to run the request - the above is sufficient to
     * do all the necessary setup to get the appropriate directory
     * configuration for the request.
     */
    dconf = ap_get_module_config(sub_req->per_dir_config, &auth_urs_module);
    if( dconf == NULL || dconf->client_id == NULL || dconf->authorization_code == NULL
        || dconf->authorization_group == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to retrieve directory configuration for %s", url_str );
        return HTTP_BAD_REQUEST;
    }
    if( strcmp(cookie_name, dconf->authorization_group) != 0 )
    {
        /* These should match all the time */

        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Misconfiguration for %s", url_str );
        return HTTP_BAD_REQUEST;
    }


    /*
     * We have now established that this request is for an application
     * redirect url. The user has hopefully been sent here as a result of
     * authenticating with URS.
     * Check the result of the user authentication. We expect to find
     * either a 'code' or a 'error' query parameter.
     */
    code = http_get_query_param(r, "code");
    if( code == NULL ) {
        /*
         * There was no code, so we expect an error. We handle
         * the 'access_denied' as a special case, redirecting (if configured)
         * to a special URL - this is the case when the user denies access
         * to the application (in the case of an interactive user-agent), or
         * has not already granted access (in the case of a script based
         * user-agent).
         */
        const char *error = http_get_query_param(r, "error");

        if( error != NULL && strcmp(error, "access_denied") == 0
                && dconf->access_error_url != NULL )
        {
            const char* error_url = dconf->access_error_url;

            if (*error_url == '/') {
                /* We use internal redirects on local URLs */

                ap_log_rerror( APLOG_MARK, APLOG_NOTICE, 0, r,
                    "UrsAuth: Access denied to user profile. Internal redirect to %s", error_url );
                r->status = 403;
                ap_internal_redirect(error_url, r);

                /*
                 * The fallthrough to the HTTP_MOVED_TEMPORARILY is ok, since
                 * the internal redirect has already returned the FORBIDDEN
                 * status back to the client.
                 */
            }
            else {
                /*
                 * Non-local error urls are handled with a redirect.
                 * If we have a UrsAccessErrorParmeter configured, add the
                 * original resource URL requested by the user to the
                 * error url. Note that if the URL already contains a
                 * query parameter, we must append it with '&' rather
                 * than '?'
                 */
                if( dconf->access_error_parameter != NULL ) {
                    const char* qp = "?";
                    if( strchr(dconf->access_error_url, '?') != NULL ){
                        qp = "&";
                    }

                    error_url = apr_pstrcat( r->pool, dconf->access_error_url,
                            qp, dconf->access_error_parameter, "=",
                            http_url_encode(r->pool, url_str), NULL );
                }

                ap_log_rerror( APLOG_MARK, APLOG_NOTICE, 0, r,
                    "UrsAuth: Access denied to user profile. Redirecting to %s", error_url );
                apr_table_setn(r->err_headers_out, "Location", error_url);
            }
            return HTTP_MOVED_TEMPORARILY;
        }


        /* Otherwise, just assume a bad link or hack */

        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Incomplete/malformed redirection request received for authorization group %s",
                dconf->authorization_group );

        return HTTP_FORBIDDEN;
    }


    /*
     * Now we need to initiate the token exchange with URS
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Initiating token exchange with code %s", code );

    status = token_exchange(r, dconf, &access_token, &endpoint);
    if( status != HTTP_OK ) return status;


    /*
     * Token is good. Now retrieve the user profile data.
     */
    status = retrieve_user_profile(r, dconf, access_token, endpoint, &user_profile);
    if( status != HTTP_OK ) return status;


    /*
     * Populate basic session data, including the IP address of the
     * remote host, and the current time. Note that in some cases
     * we use 'apr_table_set' so that the table will make its own
     * copy of the data using the pool that was used to originally
     * create the table (the connection pool). In other cases, we
     * use 'apr_table_setn' when we are using constants, or have to
     * allocate string data for other reasons.
     */
    current_time = apr_time_sec(apr_time_now());
    session = apr_table_make(r->connection->pool, 10);
#if AP_SERVER_MAJORVERSION_NUMBER > 2 || (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
    apr_table_set(session, "ip", r->useragent_ip);
#else
    apr_table_set(session, "ip", r->connection->remote_ip);
#endif
    apr_table_setn(session, "starttime", apr_ltoa(r->connection->pool, current_time));
    apr_table_setn(session, "lastupdatetime", apr_ltoa(r->connection->pool, current_time));
    apr_table_set(session, "uid", json_get_member_string(user_profile, "uid"));


    /*
     * Add the configured user profile information to the session data.
     * Anything configured to be part of the subprocess environment must be
     * added.
     */
    elements = apr_table_elts(dconf->user_profile_env);

    if( elements->nelts > 0 ) {
        int i;
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i ) {
            const char* name = entry[i].key;

            if( json_get_member_type(user_profile, name) == json_string ) {
                const char* value = json_get_member_string(user_profile, name);
                apr_table_set(session, name, value);
            }
        }
    }


    /*
     * Save the session, but also cache the session on the connection using the
     * auth group (cookie name) as the key. By caching it, we can speed up
     * persistent connections by avoiding the need to decrypt.
     */
    if (!save_session(r, dconf, session, NULL)) return HTTP_INTERNAL_SERVER_ERROR;

    apr_table_setn(r->connection->notes,
        apr_pstrdup(r->connection->pool, dconf->authorization_group),
        (char*) session);


    /*
     * Now redirect the user back to their original location.
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Authentication complete, redirecting to: %s", url_str );

    apr_table_setn(r->err_headers_out, "Location", url_str);

    return HTTP_MOVED_TEMPORARILY;
}



/**
 * Early request processing hook designed to provide a logout
 * capability. This is intended to be transparent to the
 * request processing, so this method always returns the
 * DECLINE status.
 *
 * @param r a pointer to the request_rec structure
 * @return DECLINED
 */
int auth_urs_post_read_request_logout(request_rec *r)
{
    char *cookie_name = NULL;
    char *cookie_value = NULL;


    /*
     * Check to see if the urs logout query parameter exists. If not,
     * no logout.
     */
    cookie_name = http_get_query_param(r, "urslogout");
    if( cookie_name == NULL ) return DECLINED;


    /*
     * This is a logout request. The value of the urslogout query
     * parameter is the application group (i.e. the cookie name).
     * We just go ahead and destroy the session.
     */
    apr_table_unset(r->connection->notes, cookie_name);

    cookie_value = http_get_cookie(r, cookie_name );
    if( cookie_value != NULL ) {
        /*
         * We really have no way of telling if this is a file or cookie based
         * session, so we just attempt to clear a session file and don't
         * worry about it if there isn't one.
         */
        session_destroy_file(r, cookie_value);
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Logout for session %s", cookie_name );
    }


    /*
     * Finally, delete the cookie so the auth handler does not see it. Note that
     * this does not tell the user-agent to destroy the cookie - we don't have
     * sufficient information about the cookie to do so (we have no way to
     * determine the correct domain, which must match for cookie deletion).
     * Thus, we have no easy way of expiring cookie based sessions unless we
     * wish to store the domain in the session data.
     */
    http_delete_cookie(r, cookie_name);


    /*
     * Pretend that we didn't do anything.
     */
    return DECLINED;
}




/**
 * Checks to see whether URS OAuth2 type authentication should
 * be performed on the request. This is a hook callback method
 * invoked by apache as part of the request processing, and
 * performs the intial redirection.
 *
 * @param r a pointer to the request structure for the
 *          currently active request.
 * @return DECLINED or HTTP status
 */
int auth_urs_check_user_id(request_rec *r)
{
    auth_urs_svr_config*        sconf = NULL;
    auth_urs_dir_config*        dconf = NULL;
    const char*                 auth_type = NULL;
    const char*                 cookie = NULL;
    apr_table_t*                session = NULL;
    int                         expire_cookie = 0;
    const apr_array_header_t*   elements;


    /*
     * Check the authentication type to see if we should handle
     * authentication for this request.
     */
    auth_type = ap_auth_type(r);
    if( auth_type == NULL || strcasecmp(auth_type, "UrsOAuth2") != 0 ) {
        return DECLINED;
    }


    /*
     * Get our configuration structures and verify that we have
     * been configured properly for this location.
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Required to authenticate access to %s", r->uri );

    dconf = ap_get_module_config(r->per_dir_config, &auth_urs_module );
    if( dconf->client_id == NULL
        || apr_table_elts(dconf->redirect_urls)->nelts == 0
        || dconf->authorization_group == NULL)
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Not configured correctly for location %s", r->uri );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );
    if( sconf == NULL
        || sconf->urs_auth_path == NULL || sconf->urs_token_path == NULL
        || sconf->urs_auth_server.is_initialized != 1 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Invalid server configuration for location %s", r->uri );

        return HTTP_INTERNAL_SERVER_ERROR;
    }



    /*
     * Everything looks set, and we need to check the authentication
     * state of this user. We do this by looking for our auth cookie.
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Checking for presence of session cookie '%s'",
        dconf->authorization_group);
    cookie = http_get_cookie(r, dconf->authorization_group);


    /*
     * If we have a cookie, we have authenticated this user. However,
     * we still have to check some verify the status.
     */
    if( cookie != NULL ) {

        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Cookie found - verifying" );

        /*
         * Check to see if we have saved the session in the
         * connection on a previous request (only works for persistent
         * connections, but can also be invoked on non-persistent
         * connections in the case of a sub-request).
         * Note that this is really a bit of a hack - 'notes'
         * is an apr_table_t, designed for strings. While our session
         * data are strings, the table we store it in is not. We store
         * our session table in the notes table by type casting. We can
         * only do this if we use 'apr_table_setn' (not 'apr_table_set').
         */
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Retrieving session for cookie (trying connection cache)" );

        session = (apr_table_t*) apr_table_get(r->connection->notes, dconf->authorization_group);

        if( session == NULL ) {
            const unsigned char* session_data;
            int len;

            /*
             * No session saved on connection, so retrieve it from the file
             * or cookie as appropriate.
             */
            session = apr_table_make(r->connection->pool, 10);

            if (dconf->use_cookie_sessions) {
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Session not found in connection cache - restoring from cookie" );

                /*
                 * Session data is stored in the cookie, so retrieve it and do
                 * the base64 decoding.
                 */
                session_data = apr_pcalloc(r->pool, strlen(cookie));
                len = apr_base64_decode_binary((unsigned char*) session_data, cookie);
            }
            else {
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Session not found in connection cache - restoring from file" );

                /*
                 * We don't have the session data cached, so load if
                 * back in from the session file. Note that all session
                 * data is allocated in the connection pool so we can
                 * persist it at the connection level.
                 */
                session_data = session_read_file(r, cookie, &len);
            }

            if (session_data) {
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Session packet length = %d", len );
            }

            /* If the session is encypted, descrypt it */

            if (session_data && dconf->session_passphrase != NULL) {
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Decrypting session data" );
                session_data = crypto_decrypt_packet(r, session_data, &len, dconf->session_passphrase);
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Decrypted session packet length = %d", len );
            }

            /* Unpack the session */

            if (session_data && session_unpack(r, session_data, len, session) == APR_SUCCESS ) {
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Loaded session data" );
            }
            else {
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Session data could not be restored." );
                session = NULL;
            }
        }
        else {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Session restored from connection." );
        }


        /*
         * If we loaded the session data, then validate it. If validation
         * fails, then flag the cookie for cleanup and make sure any session
         * stored on the connection is removed.
         */
        if( session == NULL || !validate_session(r, cookie, session) ) {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: No valid session found");

            apr_table_unset(r->connection->notes, dconf->authorization_group);
            if (dconf->session_passphrase == NULL) {
                session_destroy_file(r, cookie);
            }
            cookie = NULL;
            session = NULL;
            expire_cookie = 1;
        }
        else {
            /*
             * Make sure the session is cached on the connection. Note we
             * must use the connection pool to store the key, otherwise it could
             * go out of scope when the request terminates, leaving a potentially
             * corrupted connection 'notes' table.
             */
            apr_table_setn(r->connection->notes,
                apr_pstrdup(r->connection->pool, dconf->authorization_group),
                (char*) session);
        }
    }


    /*
     * We don't (or no longer) have a valid cookie. We cannot let this
     * request through, so we redirect or reject it, depending upon
     * the specifics of the request.
     */
    if( cookie == NULL ) {
        char*  url;
        char*  buffer;
        int    buflen;
        const char* host;

        apr_uri_t*  redirect_url;


        /*
         * This is a special case. If authenticate has been explicitly
         * disabled we exit with an OK status. However, none of the URS
         * environment will have been set up. This feature is provided
         * to allow applications sitting behind this module to have a
         * special resource - such as a home page - that can detect
         * whether or not a user is logged in.
         */
        if( dconf->anonymous_user != NULL ) {
            r->user = dconf->anonymous_user;
            ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
                "UrsAuth: Access granted to %s for anonymous user %s", r->uri, r->user);

            return OK;
        }

        if( r->header_only && dconf->head_user != NULL ) {
            r->user = dconf->head_user;
            ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
                "UrsAuth: Access granted to %s HEAD request", r->uri);

            return OK;
        }


        /*
         * If this is a subrequest, we cannot redirect the user to
         * authenticate, so at this point we simple return UNAUTHORIZED.
         * This means that a module such as autoindex may or may not
         * display the directory in a listing, depending upon the current
         * authentication state. Same goes for HEAD requests.
         * If a session was previously expired, we tell the browser to
         * also expire the cookie.
         */
        if( r->main != NULL || r->header_only) {
            /*
             * If we previously expired a session, tell the browser to
             * expire the cookie. This is not really neccessary, since
             * an old session cookie will be ignored, but in the case
             * of browsing a directory structure (via mod_autoindex),
             * this can create a lot of sub-requests, each of which
             * will require testing of the session cookie (a file op),
             * and performance is important.
             * For non sub/HEAD requests, this is not an issue, since
             * it will go on to establish a new session.
             */
            if( expire_cookie ) {
                const char* del_cookie = apr_pstrcat(r->pool,
                    dconf->authorization_group, "=; Path=/; Expires=Sat, 01 Jan 2000 00:00:00 GMT", NULL);
                    
                if (dconf->cookie_domain != NULL) 
                    del_cookie = apr_pstrcat(r->pool, del_cookie, "; Domain=", dconf->cookie_domain, NULL);

                r = r->main == NULL ? r : r->main;
                apr_table_addn(r->err_headers_out, "Set-Cookie", del_cookie);
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Expired cookie %s", dconf->authorization_group );
            }

            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Sub/HEAD request - not authorized" );

            return (HTTP_UNAUTHORIZED);
        }

        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: No cookie" );


        /*
         * Check the request type. We only support POST and GET requests,
         * and the POST requests require special handling to store the
         * request content in a client side cookie.
         */
        if( r->method_number == M_POST ) {
            /*
             * This is a POST request that requires special handling since it may
             * contain a body that needs to be preserved.
             */
            int status;
            int size = 2048;
            char* post_cookie;
            const char* header;
            int len;
            char* buffer;


            /*
             * Get the content type. We must store this in the POST cookie as well,
             * since we need to reconstruct it properly after authentication.
             */
            header = apr_table_get(r->headers_in, "Content-Type");
            if( header == NULL ) header = "application/x-www-form-urlencoded";
            len = strlen(header);


            /*
             * Get the request body. It will update 'size' to the amount
             * of data found in the body.
             */
            buffer = apr_palloc(r->pool, size + len + 2);
            strcpy(buffer, header);
            status = http_get_request_body(r, buffer + len + 1, &size);
            if( status != OK )
            {
                return status;
            }


            /*
             * Encode the content type and request body in base64. It is possible
             * that the body contains binary data, so we use base64 encoding so we
             * can store it in a cookie. We have to chop off any '=' padding, since
             * these are not permitted characters in a cookie.
             */
            post_cookie = apr_palloc(r->pool, ((size + len + 2) / 3) * 4 + 8);
            size = apr_base64_encode_binary(post_cookie, (unsigned char*) buffer, size + len + 1) - 1;
            if( size > 0 && post_cookie[size - 1] == '=' ) --size;
            if( size > 0 && post_cookie[size - 1] == '=' ) --size;
            post_cookie[size] = 0;


            /*
             * Construct the cookie. This not only stores the request content, but acts as a flag that
             * triggers the POST request reconstruction after authentication.
             * The cookie is linked(PatH) to the specific resource that the user requested. We also
             * place an age limit of 500 seconds (in most cases it should be no more than a few
             * seconds before the redirection completes and the resource is requested again). Note that we
             * use Max-Age which is not supported be IE8 or earlier. In this case, the cookie will only expire
             * when the browser restarts.
             */
            post_cookie = apr_pstrcat(r->pool, dconf->authorization_group, "_post=", post_cookie, "; Path=", r->uri, "; Max-Age=300", NULL);
            apr_table_addn(r->err_headers_out, "Set-Cookie",  post_cookie );
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Set post request cookie = %s", post_cookie );
        }
        else if( r->method_number != M_GET ) {
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Not a GET request - forbidden" );
            return HTTP_FORBIDDEN;
        }


        ap_log_rerror( APLOG_MARK, APLOG_NOTICE, 0, r,
            "UrsAuth: Redirecting to URS for authentication" );

        /*
         * We must record the original request URL so we can redirect the client
         * back there afterwards. This will be stored in the 'state' query parameter.
         * First reconstruct the original URL. It is actually not very easy to
         * reconstruct the original request in it's entirety!
         */
        host = r->hostname ? r->hostname : r->server->server_hostname;
        if( strchr(host, ':') != NULL ) {
            host = apr_pstrndup(r->pool, host, strchr(host, ':') - host);
        }

        if( ap_is_default_port(ap_get_server_port(r), r) ) {
            url = apr_psprintf(r->pool, "%s://%s%s",
                ap_http_scheme(r), host, r->unparsed_uri);
        }
        else {
            url = apr_psprintf(r->pool, "%s://%s:%d%s",
                ap_http_scheme(r), host, ap_get_server_port(r), r->unparsed_uri);
        }


        /*
         * Now base64 encode the URL. We do not do this for security,
         * just to obscure the fact that we have a URL embedded in a URL.
         */
        buffer = apr_palloc(r->pool, strlen(url) * 2);
        buflen = apr_base64_encode(buffer, url, strlen(url));
        --buflen; /* Return value includes null terminator in length */

        /* Chop off any trailing '=' which would cause problems when encoding */

        if( buffer[buflen - 1] == '=' ) --buflen;
        if( buffer[buflen - 1] == '=' ) --buflen;
        buffer[buflen] = '\0';


        /*
         * Construct the URL and query parameters for the authentication redirection URL.
         * We must url encode the query parameters (even the base64 encoded URL, which can
         * contain a '/').
         */

        /* First, look up the redirect URL for the request hostname */

        redirect_url = (apr_uri_t*) apr_table_get(dconf->redirect_urls, host);
        if( redirect_url == NULL ) {
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: No redirect URL configured for host %s and path %s",
                host, r->uri);
            return HTTP_BAD_REQUEST;
        }


        /*
         * If we are storing the original URL in a cookie, do that now. The state query 
         * parameter value is change to a randomly generated UID that is also stored 
         * in the cookie.
         */
        if (dconf->use_cookie_url) {
            /* Generate a uid. This will replace the original URL in the 'state' query parameter. */
           
            const char      suid[256];
            const char*     url_cookie;
            apr_uuid_t      uuid;

            apr_uuid_get(&uuid);
            apr_uuid_format(suid, &uuid);

            /* Create the cookie string. This is configured to be returned only for the redirect url path */
       
            url_cookie = apr_pstrcat(r->pool,
                    dconf->authorization_group, "_url=", suid, ":", buffer, "; Path=/; Max-Age=300", NULL);
            buffer = apr_pstrdup(r->pool, suid);

            /* Add the cookie. We use 'add' this time, just in case a 'post' cookie is being used */
       
            apr_table_addn(r->err_headers_out, "Set-Cookie",  url_cookie );
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Set url cookie = %s", url_cookie );
        }


        /* Now construct the redirect URL */

        buffer = apr_psprintf(r->pool,
            "%s://%s%s%s%s%sclient_id=%s&response_type=code&redirect_uri=%s%%3A%%2F%%2F%s%s&state=%s",
            sconf->urs_auth_server.scheme, sconf->urs_auth_server.hostinfo,
            sconf->urs_auth_path,
            strchr(sconf->urs_auth_path, '?') == NULL ? "?" : "&",
            dconf->splash_disable ? "splash=false&" : "",
            dconf->auth401_enable ? "app_type=401&" : "",
            http_url_encode(r->pool, dconf->client_id),
            redirect_url->scheme, http_url_encode(r->pool, redirect_url->hostinfo),
            http_url_encode(r->pool, redirect_url->path),
            http_url_encode(r->pool, buffer) );


        apr_table_setn(r->err_headers_out, "Location", buffer);

        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Redirection URL: %s", buffer );

        return HTTP_MOVED_TEMPORARILY;
    }


    /*
     * If we get here, the user has authenticated, so life is good. We now
     * need to check to see if the original request was a POST request (since
     * the redirects come back in as GETs). If so, we must modify the request
     * to make it look and feel like a POST request for the downstream handlers.
     */
    cookie = apr_pstrcat(r->pool, dconf->authorization_group, "_post", NULL);
    cookie = http_get_cookie(r, cookie);
    if( cookie != NULL && r->method_number == M_GET ) {
        auth_urs_post_input_filter_ctx* ctx;

        /*
         * We have a 'post' cookie for this URL, so the original request was
         * a POST request. We must convert this GET back into a POST (not an
         * easy task). First decode the cookie data - this is the orginal
         * POST request body and the content type, both of which must be
         * reconstructed in order for any downstream application to work.
         */
        int body_size = 0;
        char* body = "";
        char* type = "application/x-www-form-urlencoded";

        if( cookie[0] != '\0' ) {
            body_size = apr_base64_decode_len(cookie);
            body = apr_pcalloc(r->pool, body_size + 1);
            body_size = apr_base64_decode_binary((unsigned char*) body, cookie);
            type = body;
            body += strlen(type) + 1;
            body_size -= strlen(type) + 1;
        }
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Reconstructed POST content type = %s", type );
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Reconstructed POST body = %s", body );


        /*
         * Change the request back to a POST type. We must set the content type and length
         * headers.
         */
        r->method_number = M_POST;
        r->method = "POST";
        r->the_request = apr_pstrcat(r->pool, r->method, (r->the_request + 3), NULL);
        apr_table_setn(r->headers_in,
            "Content-Type", type);
        apr_table_setn(r->headers_in,
            "Content-Length", apr_psprintf(r->pool, "%d", body_size));


        /*
         * Add an input filter to the request. This will regenerate the request body when the downstream
         * handler reads the input stream.
         */
        ctx = (auth_urs_post_input_filter_ctx*) apr_pcalloc(r->pool, sizeof(auth_urs_post_input_filter_ctx));
        ctx->body = body;
        ctx->body_size = body_size;
        ap_add_input_filter( "UrsPostReconstruct", ctx, r, r->connection);


        /*
         * Make sure the POST cookie is expired so it cannot influence a
         * GET request to the same URL at a later point.
         */
        apr_table_addn(r->err_headers_out,
            "Set-Cookie",
            apr_pstrcat(r->pool,
                dconf->authorization_group,
                "_post=; Expires=Sat, 01 Jan 2000 00:00:00 GMT; Path=", r->uri, NULL) );
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Expired post cookie %s_post", dconf->authorization_group );
    }



    /*
     * All we have to do now is set up some basic environment information
     * about the user so that it can be picked up by downstream modules,
     * or even cgi scripts.
     */
    r->user = apr_pstrdup(r->pool, apr_table_get(session, "uid"));

    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
        "UrsAuth: Access granted to %s for user %s", r->uri, r->user);


    elements = apr_table_elts(dconf->user_profile_env);

    if( elements->nelts > 0 ) {
        int i;
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i ) {
            const char* value;
            const char* s_name =  entry[i].key;
            const char* e_name = entry[i].val;

            value = apr_table_get(session, s_name);

            if( value != NULL ) {
                apr_table_set(r->subprocess_env, e_name, value);
            }
        }
    }

    return OK;
}



/************************************
 * Static (internal) methods
 ************************************/

/**
 * Performs a token exchange with the URS endpoint.
 *
 * @param r a pointer to the request_rec structure
 * @param dconf a pointer to the per-directory configuration for
 *        the URL originally accessed.
 * @param access_token used to return the retrieved access token
 * @param endpoint used to return the user profile endpoint
 * @return HTTP_OK on success, error code otherwise
 */
static int token_exchange(request_rec *r, auth_urs_dir_config* dconf, const char** access_token, const char** endpoint)
{
    auth_urs_svr_config*    sconf = NULL;

    const char*             host;
    apr_uri_t*              redirect_url;

    apr_table_t*            headers;
    char*                   body;
    int                     status;
    json*                   json;

    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );

    /* Get the redirect URL for the request hostname */
    host = r->hostname ? r->hostname : r->server->server_hostname;
    if( strchr(host, ':') != NULL )
    {
        host = apr_pstrndup(r->pool, host, strchr(host, ':') -host);
    }

    redirect_url = (apr_uri_t*) apr_table_get(dconf->redirect_urls, host);
    if( redirect_url == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: No redirect URL configured for host %s and path %s",
            host, r->uri);
        return HTTP_BAD_REQUEST;
    }


    /*
     * Perform the token exchange. The only custom header we need is the
     * authorization code. The body contains the rest of the information.
     * For the redirect-url, we just build it up from the request (since this
     * was a request to the redirect URL)
     */
    headers = apr_table_make(r->pool, 10);
    apr_table_setn(headers, "Authorization",
        apr_psprintf(r->pool, "BASIC %s", dconf->authorization_code) );

    body = apr_psprintf(r->pool,
        "grant_type=authorization_code&code=%s&redirect_uri=%s%%3A%%2F%%2F%s%s",
        http_url_encode(r->pool, http_get_query_param(r, "code")),
        redirect_url->scheme,
        http_url_encode(r->pool, redirect_url->hostinfo),
        http_url_encode(r->pool, redirect_url->path) );

    status = http_post(r, &sconf->urs_auth_server, sconf->urs_token_path, headers, &body);
    if( status != HTTP_OK )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Token exchange failed with status %d", status );
        return status;
    }


    /*
     * The data we need is returned as a json document in the body of the response.
     * Verify that all the necessary components are there.
     */
    json = json_parse( r->pool, body );
    if( json == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed parsing json: %s", body );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if( !json_has_member(json, "access_token" ) )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: No access token returned from URS" );
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if( !json_has_member(json, "endpoint" ) )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: No endpoint returned from URS" );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    *access_token = json_get_member_string(json, "access_token" );
    *endpoint = json_get_member_string(json, "endpoint" );

    return HTTP_OK;
}


/**
 * Retrieve a user's profile information from the URS.
 *
 * @param r a pointer to the request_rec structure
 * @param dconf a pointer to the per-directory configuration for
 *        the URL originally accessed.
 * @param access_token the URS access token
 * @param endpoint the URS user profile endpoint
 * @param profile used to return the user profile
 * @return HTTP_OK on success, error code otherwise
 */
static int retrieve_user_profile(
    request_rec *r,
    auth_urs_dir_config* dconf,
    const char* access_token,
    const char* endpoint,
    json** profile )
{
    auth_urs_svr_config*    sconf = NULL;

    apr_table_t*            headers;
    char*                   body;
    int                     status;


    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );

    /*
     * Submit the request to the server to retrieve the user profile.
     */
    headers = apr_table_make(r->pool, 10);
    apr_table_setn(headers, "Authorization",
        apr_psprintf(r->pool, "Bearer %s", access_token) );

    status = http_get(r, &sconf->urs_auth_server, endpoint, headers, &body);
    if( status != HTTP_OK )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Retrieve profile failed with status %d", status );
        return status;
    }


    /*
     * Parse the resulting json
     */
    *profile = json_parse( r->pool, body );
    if( *profile == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed parsing json: %s", body );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return status;
}



/**
 * Validates session data for completeness, expiration, and security.
 *
 * @param r a pointer to the current request
 * @param cookie the name of the session file
 * @param session_data the table containing the session data
 * @return true (1) if session is good, false (0) otherwise
 */
static int validate_session(request_rec *r, const char* cookie, apr_table_t* session )
{
    auth_urs_dir_config*    dconf;

    long    current_time;



    /*
     * We have a valid session. Check the data to make sure the
     * basic info is there.
     */
    if( apr_table_get(session, "ip") == NULL ||
        apr_table_get(session, "uid") == NULL ||
        apr_table_get(session, "starttime") == NULL ||
        apr_table_get(session, "lastupdatetime") == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r, "Invalid session");
        return 0;
    }


    /*
     * Verify the IP address parts if configured
     */
    dconf = ap_get_module_config(r->per_dir_config, &auth_urs_module );
    if( dconf->check_ip_octets > 0 )
    {
        const char* real_ip = apr_table_get(session, "ip");
#if AP_SERVER_MAJORVERSION_NUMBER > 2 || (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
        const char* fake_ip = r->useragent_ip;
#else
        const char* fake_ip = r->connection->remote_ip;
#endif
        int i;

        for( i = 0; i < dconf->check_ip_octets; ++i )
        {

            if( strtol(real_ip, (char**) &real_ip, 0) != strtol(fake_ip, (char**) &fake_ip, 0) )
            {
                /*
                 * If an IP octet doesn't match, fail the session
                 * validation.
                 */
                ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                    "Possible session hijack for %s", cookie );
                return 0;
            }
            ++real_ip;
            ++fake_ip;
        }
    }



    /*
     * Check that the session has not exceeded the configured
     * time limits on total duration, or inactivity.
     */
    current_time = apr_time_sec(apr_time_now());

    if( dconf->active_timeout > 0 )
    {
        long time_value = apr_atoi64(apr_table_get(session, "starttime"));
        if( (current_time - time_value) > dconf->active_timeout )
        {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "Session active time exceeded for %s", cookie );
            return 0;
        }
    }

    if( dconf->idle_timeout > 0 )
    {
        long time_value = apr_atoi64(apr_table_get(session, "lastupdatetime"));
        if( (current_time - time_value) > dconf->idle_timeout)
        {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "Session idle time exceeded for %s", cookie );
            return 0;
        }

        /*
        * A this point, everything looks ok. However, we need to update the
        * lastupdatetime to make sure it doesn't expire, yes we don't want
        * to do this every time, otherwise we could overload the file system.
        * Thus we do it at most once per minute.
        */
        if( (current_time - time_value) > 60 )
        {
            apr_table_set(session, "lastupdatetime",
                apr_psprintf(r->pool, "%ld", current_time) );

            if (!save_session(r, dconf, session, cookie))
                return HTTP_INTERNAL_SERVER_ERROR;

            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "Session lastupdatetime updated");
        }
    }


    return 1;
}



/**
 * General function to save session data. This handles encryption and saving
 * the session to the appropriate store (file/cookie), based on the configuration.
 * @param r the current request
 * @param dconf the directory level configuration for this request
 * @param session the session to save
 * @param session_id the session ID (only used for file base sessions).
 * @return 1 if the session was saved, 0 otherwise.
 */
int save_session(request_rec *r, auth_urs_dir_config *dconf, apr_table_t* session, const char* session_id)
{
    const unsigned char *p;
    const char          *cookie;
    int                 len;


    /*
     * Save the session. Depending upon configuration, there are two ways
     * in which we can do this. The first is to use a local session store -
     * save the session data in a file in a local directory. The filename
     * is identified using a unique ID that is saved in a cookie.
     * The second is to save the session data in the cookie directly.
     */

    /* The first step is to pack the session data into a buffer */

    p = session_pack(r, session, &len);


    /*
     * Check to see if session encryption has been configured. If so,
     * we must encrypt the data.
     */
    if (dconf->session_passphrase != NULL) {
        p = crypto_encrypt_packet(r, p, &len, dconf->session_passphrase);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Session data has been encrypted");
    }


    /*
     * Save the session. By default, this will be saved in a temporary
     * file system, but it can also be configured to use a cookie.
     */
    if (dconf->use_cookie_sessions) {
        char *buffer;

        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Using cookie sessions");

        /*
         * We have been configured to save session data directly in the cookie.
         * We base64 enode the data to handle encrypted session data (cookie
         * sessions *should* be encrpyted, but we do not enforce it).
         */
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Encoding session data");

        buffer = apr_palloc(r->pool, len * 2);
        len = apr_base64_encode_binary(buffer, p, len);
        p = (unsigned char*) buffer;
        --len; /* Return value includes null terminator in length */
    }
    else
    {
        /* We are using session files */

        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Using file sessions");

        /*
         * Generate a unique cookie ID. This will be used as the session
         * filename.
         */
        if (session_id == NULL) session_id = session_create_id(r);
        if (session_id == NULL) {
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to create new cookie" );
            return 0;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Using session ID '%s'", session_id );

        /* Write the session file */

        if (session_write_file(r, session_id, p, len) != APR_SUCCESS) {
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to create new session");
            return 0;
        }
        p = (const unsigned char*) session_id;
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Wrote %d bytes to session file", len);
    }


    /*
     * Set the cookie that we use to track the session for this user. We
     * put it in err_headers_out so it is sure to be sent back to the
     * user, even on an internal redirect. Not that one of the primary
     * reasons for storing session data in the cookie is to make cross-
     * application authentication easier (for systems that do not or cannot
     * shared a local directory for session storage). In this case, we
     * should provide a configurable cookie domain. If one is not provided,
     * then only different applications within a single domain will be
     * supported.
     */
    cookie = apr_pstrcat(r->pool, dconf->authorization_group, "=", p, "; Path=/", NULL);
    if (dconf->cookie_domain) {
        cookie = apr_pstrcat(r->pool, cookie, "; Domain=", dconf->cookie_domain, NULL);
    }
    apr_table_addn(r->err_headers_out, "Set-Cookie", cookie);

    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Saved session: %s", cookie);

    return 1;
}




/************************************
 * Filter methods
 ************************************/
/**
 * Request input filter used to re-insert the previously saved body of a POST request. This filter
 * is attached to the input filter chain for a request that was original submitted as a POST request,
 * but then got converted to a GET request as a result of the authentication redirections.
 */
apr_status_t auth_urs_post_body_filter( ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes )
{
    auth_urs_post_input_filter_ctx* ctx = (auth_urs_post_input_filter_ctx*) f->ctx;

    if( mode != AP_MODE_READBYTES )
    {
        /*
         * This is a quirk needed to trigger an output pipeline flush in http_request.c
         * (part of the core system) that prevents a short delay in sending the response
         */
        return APR_EOF;
    }


    if(ctx == NULL || ctx->body == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, f->r,
            "UrsAuth: Missing context information in post body input filter" );

        return APR_EGENERAL;
    }


    /*
     * If we have some data left to provide, then do so
     */
    if( readbytes > ctx->body_size )
    {
        readbytes = ctx->body_size;
    }

    if( readbytes > 0 )
    {
        /*
         * We simply want to create a bucket and put in the appropriate amount of data.
         */
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_transient_create( ctx->body, readbytes, f->c->bucket_alloc));
        ctx->body += readbytes;
        ctx->body_size -= readbytes;
    }


    /*
     * If we have reached the end of the data, then add an end-of-stream marker
     */
    if( ctx->body_size == 0 )
    {
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));
    }

    return APR_SUCCESS;
}
