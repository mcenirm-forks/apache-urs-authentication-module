/*
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
static char* replace_cookie(request_rec* r, const char* cookies, const char* cookie_name, const char* cookie_value );
static int validate_session(request_rec *r, const char* cookie, apr_table_t* session_data );
static int retrieve_user_profile(request_rec *r,auth_urs_dir_config* dconf, const char* access_token,const char* endpoint,json** profile );
static int token_exchange(request_rec *r, auth_urs_dir_config* dconf, const char** access_token, const char** endpoint);



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
    const char*     cookie_value = NULL;
    
    request_rec*    sub_req;
    const char*     access_token;
    const char*     endpoint;
    json*           user_profile;
    long            current_time;
    apr_table_t*    session_data;
    
    const apr_array_header_t* elements;

    char*           url_str;
    int             status;
    apr_uri_t       url;


    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /*
     * Check to see if this request is a redirection URL.
     * If so, we must handle it, otherwise we decline and allow
     * someone else to do so.
     */
    cookie_name = apr_table_get(sconf->redirection_map, r->uri);
    if( cookie_name == NULL )
    {
        /* This is not a redirection point */
        
        return DECLINED;
    }
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Authentication redirect for auth group %s: %s", cookie_name, r->uri );
    
    
    /*
     * We expect this request to provide both the URS code and
     * return our state. If either of these are missing, we
     * consider the request malformed.
     */    
    code = get_query_param(r, "code");
    state = get_query_param(r, "state");
    if( code == NULL || state == NULL )
    {
        return HTTP_FORBIDDEN;
    }


    /*
     * Reconstruct the original URL from the state query parameter.
     * We are going to use this to generate a sub request for the
     * purposes of extract the appropriate per-directory
     * configuration information we need for the token exchange.
     * Note that we do not explicitly call ap_destroy_sub_req for 
     * the sub request - the main request does that when its pool
     * gets destroyed.
     */
    url_str = apr_palloc(r->pool, strlen(state) + 1);
    apr_base64_decode(url_str, state);
    
    if( apr_uri_parse(r->pool, url_str, &url) != APR_SUCCESS )
    {
        return HTTP_BAD_REQUEST;
    }
    
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Subrequest processing for %s", url_str );
    sub_req = ap_sub_req_lookup_uri(url.path, r, NULL);
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Subrequest returned %d", r->status );


    /*
     * We do not need to run the request - the above is sufficent to
     * do all the necessary setup to get the directory configuration.
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
    session_data = apr_table_make(r->connection->pool, 10);
    
    apr_table_set(session_data, "ip", r->connection->remote_ip);
    apr_table_setn(session_data, "starttime", apr_ltoa(r->connection->pool, current_time));
    apr_table_setn(session_data, "lastupdatetime", apr_ltoa(r->connection->pool, current_time));
    apr_table_set(session_data, "uid", json_get_member_string(user_profile, "uid"));


    /*
     * Add user profile information to the session data. Anything configured
     * to be part of the subprocess environment must be added.
     */
    elements = apr_table_elts(dconf->user_profile_env);
    if( elements->nelts > 0 )
    {
        int i;
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            const char* name = entry[i].key;
            if( json_get_member_type(user_profile, name) == json_string )
            {
                apr_table_set(session_data, name, json_get_member_string(user_profile, name));
            }
        }
    }
    
     
    /*
     * Generate a unique cookie ID.
     */
    cookie_value = create_urs_cookie_id(r);
    if( cookie_value == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to create new cookie" );
        return HTTP_INTERNAL_SERVER_ERROR;
    }



    /*
     * Set the cookie that we use to track the session for this user. We
     * put it in err_headers_out so it is sure to be sent back to the
     * user, even on an internal redirect.
     * We set the path to '/', so it will be returned for all accesses to 
     * this server. This is not ideal, but without additional
     * configuration, we have no way of knowing exactly what paths it
     * should be valid for - for example, the first request for a protected
     * resource could be some way inside the lowest level directory that
     * is to be protected.
     */
    apr_table_set(r->err_headers_out,
        "Set-Cookie",
        apr_pstrcat(r->pool, cookie_name, "=", cookie_value, "; Path=/", NULL) );


    /*
     * Write the session file and cache it on the connection in case
     * of sub-requests or persistent connections.
     */
    if( write_urs_session(r, cookie_value, session_data) != APR_SUCCESS )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to create new session for %s", cookie_value );
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_table_setn(r->connection->notes,
        apr_pstrdup(r->connection->pool, cookie_value), (char*) session_data);



    /*
     * Now redirect the user back to their original location.
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Redirecting to: %s", url_str );
    
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
    int len;
    auth_urs_svr_config*    sconf = NULL;

    char*                   cookie_name = NULL;
    char*                   cookie_value = NULL;

    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /*
     * Check to see if the urs logout query parameter exists. If not,
     * no logout.
     */
    cookie_name = get_query_param(r, "urslogout");
    if( cookie_name == NULL ) return DECLINED;
    
    
    /*
     * This is a logout request. The value of the urslogout query 
     * parameter is the application group (i.e. the cookie name).
     * We just go ahead and destroy the session.
     */
    cookie_value = get_cookie(r, cookie_name );
    if( cookie_value != NULL )
    {
        apr_table_unset(r->connection->notes, cookie_value);
        destroy_urs_session(r, cookie_value);
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Logout for session %s", cookie_value );
    }


    /*
     * Pretend that we didn't do anything.
     */
    return DECLINED;
}




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
int auth_urs_check_user_id(request_rec *r)
{
    auth_urs_svr_config*        sconf = NULL;
    auth_urs_dir_config*        dconf = NULL;
    const char*                 auth_type = NULL;
    const char*                 cookie = NULL;
    apr_table_t*                session_data;
    int                         expire_cookie = 0;
    const apr_array_header_t*   elements;


    /*
     * Check the authentication type to see if we should handle
     * authentication for this request.
     */
    auth_type = ap_auth_type(r);
    if( auth_type == NULL || strcasecmp(auth_type, "UrsOAuth2") != 0 )
    {
        return DECLINED;
    }
    
    
    /*
     * Get our configuration structures and verify that we have
     * been configured properly for this location.
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Required to authenticate access to %s", r->uri );

    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );
    dconf = ap_get_module_config(r->per_dir_config, &auth_urs_module );

    if( dconf->client_id == NULL || dconf->redirect_url.hostname == NULL
        || dconf->authorization_group == NULL)
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Not configured correctly for location %s", r->uri );
    
        return HTTP_INTERNAL_SERVER_ERROR;
    }



    /*
     * Everything looks set, and we need to check the authentication
     * state of this user. Look for our auth cookie. 
     */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Checking for cookie/session" );
    cookie = get_cookie(r, dconf->authorization_group);


    /*
     * If we have a cookie, we have authenticated this user. However,
     * we still have to check some stuff before we let them access
     * the resource.
     */
    if( cookie != NULL )
    {
        /*
         * Check to see if we have saved the session data in the
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
             "UrsAuth: Retrieving session (trying connection cache)" );

         session_data = (apr_table_t*) apr_table_get(r->connection->notes, cookie);
         if( session_data == NULL )
         {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Session not found in connection cache. Loading from file" );

            /*
             * We don't have the session data cached, so load if
             * back in from the session file. Note that all session
             * data is allocated in the connection pool so we can
             * persist it at the connection level.
             */
            session_data = apr_table_make(r->connection->pool, 10);

            if( read_urs_session(r, cookie, session_data) != APR_SUCCESS )
            {
                session_data = NULL;
            }
        }

        
        /*
         * If we loaded the session data, then verify it. If verification
         * fails, or we failed to load the session at all, then
         * clean  up. 
         */
        if( session_data == NULL || !validate_session(r, cookie, session_data) )
        {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Expiring session %s", cookie );

            apr_table_unset(r->connection->notes, cookie);
            destroy_urs_session(r, cookie);
            cookie = NULL;
            session_data = NULL;
            expire_cookie = 1;
        }
        else
        {
            /*
             * Make sure the session data is cached on the connection. Note we
             * must use the connection pool to store the key, otherwise it would
             * go out of scope when the request terminates, leaving a potentially
             * corrupted connection 'notes' table.
             */
            apr_table_setn(r->connection->notes,
                apr_pstrdup(r->connection->pool, cookie), (char*) session_data);
        }
    }


    /*
     * We don't (or no longer) have a valid cookie. We cannot let this
     * request through, so we redirect or reject it, depending upon
     * the specifics of the request.
     */    
    if( cookie == NULL )
    {
        char*  url;
        char*  buffer;
        int    buflen;


        /*
         * If this is a subrequest, we cannot redirect the user to
         * authenticate, so at this point we simple return UNAUTHORIZED.
         * This means that a module such as autoindex may or may not 
         * display the directory in a listing, depending upon the current
         * authentication state. Same goes for HEAD requests.
         * If a session was previously expired, we tell the browser to
         * also expire the cookie.
         */
        if( r->main != NULL || r->header_only)
        {
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
            if( expire_cookie )
            {
                r = r->main == NULL ? r : r->main;
                apr_table_set(r->err_headers_out,
                    "Set-Cookie",
                    apr_pstrcat(r->pool,
                        dconf->authorization_group,
                        "=; Expires=Sat, 01 Jan 2000 00:00:00 GMT; Path=/", NULL) );
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
         * Currently, we can only handle GET requests at 
         * initial authentication (otherwise we would potentially have
         * to record too much information).
         */
        if( r->method_number != M_GET )
        {
            ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
                "UrsAuth: Not a GET request - forbidden" );
            return HTTP_FORBIDDEN;
        }
        
 
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Redirecting to URS for authentication" );

        /*
         * No code, so this is an initial contact and we must redirect
         * the user to URS for authentication. We must record the original
         * request so we can redirect the client back there afterwards.
         * First reconstruct the original URL.
         */
        if( ap_is_default_port(ap_get_server_port(r), r) )
        {
            url = apr_psprintf(r->pool, "%s://%s%s",
                ap_get_server_protocol(r->server), ap_get_server_name(r), 
                r->unparsed_uri);
        }
        else
        {
            url = apr_psprintf(r->pool, "%s://%s:%d%s",
                ap_get_server_protocol(r->server), ap_get_server_name(r), 
                ap_get_server_port(r), r->unparsed_uri);
        }
            
            
        /*
         * Now encode the base64 encode the URL
         */
        buffer = apr_palloc(r->pool, strlen(url) * 2);
        buflen = apr_base64_encode(buffer, url, strlen(url));
        --buflen; /* Return value includes null terminator in length */

        /* Chop off any trailing '=' which would cause problems when encoding */
        
        if( buffer[buflen - 1] == '=' ) --buflen;
        if( buffer[buflen - 1] == '=' ) --buflen;
        buffer[buflen] = '\0';


        /*
         * Now construct the authentication redirection URL, including all
         * our OAuth2 paramaters, plus the clients ultimate URL base 64 encoded
         * into the 'state' query parameter.
         */
        buffer = apr_psprintf(r->pool,
            "%s://%s%s?client_id=%s&response_type=code&redirect_uri=%s://%s%s&state=%s",
            sconf->urs_auth_server.scheme, sconf->urs_auth_server.hostinfo,
            sconf->urs_auth_path, dconf->client_id,
            dconf->redirect_url.scheme, dconf->redirect_url.hostinfo,  dconf->redirect_url.path,
            buffer );
            
        apr_table_setn(r->err_headers_out, "Location", buffer);

        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Redirection URL: %s", buffer );

        return HTTP_MOVED_TEMPORARILY;
    }


    /*
     * If we get here, the user has authenticated, so life is good.
     * All we have to do now is set up some basic environment information
     * about the user so that it can be picked up by downstream modules,
     * or even cgi scripts.
     */
    r->user = apr_pstrdup(r->pool, apr_table_get(session_data, "uid"));

    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r, 
        "UrsAuth: Access granted to %s for user %s", r->uri, r->user);

    
    elements = apr_table_elts(dconf->user_profile_env);
    if( elements->nelts > 0 )
    {
        int i;
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            const char* value;
            const char* s_name =  entry[i].key;
            const char* e_name = entry[i].val;
            
            value = apr_table_get(session_data, s_name);
            if( value != NULL )
            {
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

    apr_table_t*            headers;
    char*                   body;
    int                     status;

    json*                   json;

    sconf = ap_get_module_config(r->server->module_config, &auth_urs_module );


    /*
     * Perform the token exchange. The only custom header we need is the
     * authorization code. The body contains the rest of the information.
     */
    headers = apr_table_make(r->pool, 10);
    apr_table_setn(headers, "Authorization",
        apr_psprintf(r->pool, "BASIC %s", dconf->authorization_code) );

    body = apr_psprintf(r->pool,
        "grant_type=authorization_code&code=%s&redirect_uri=%s://%s%s",
        get_query_param(r, "code"),
        dconf->redirect_url.scheme,
        dconf->redirect_url.hostinfo,
        dconf->redirect_url.path );

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

    /*!!! Potential security problem */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Received json: %s", body );
    
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

    /*!!! Potential security problem - this is for testing only */
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: User profile: %s", body );

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
static int validate_session(request_rec *r, const char* cookie, apr_table_t* session_data )
{
    auth_urs_dir_config*    dconf;
    
    long    current_time;
    
    
    
    /*
     * We have a valid session. Check the data to make sure the
     * basic info is there.
     */
    if( apr_table_get(session_data, "ip") == NULL ||
        apr_table_get(session_data, "uid") == NULL ||
        apr_table_get(session_data, "starttime") == NULL ||
        apr_table_get(session_data, "lastupdatetime") == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "Session incomplete for %s", cookie );
        return 0;
    }
    
    
    /*
     * Verify the IP address parts if configured
     */
    dconf = ap_get_module_config(r->per_dir_config, &auth_urs_module );
    if( dconf->check_ip_octets > 0 )
    {
        const char* real_ip = apr_table_get(session_data, "ip");
        const char* fake_ip = r->connection->remote_ip;
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
        long time_value = apr_atoi64(apr_table_get(session_data, "starttime"));
        if( (current_time - time_value) > dconf->active_timeout )
        {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "Session active time exceeded for %s", cookie );
            return 0;
        }
    }
    
    if( dconf->idle_timeout > 0 )
    {
        long time_value = apr_atoi64(apr_table_get(session_data, "lastupdatetime"));
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
            apr_table_set(session_data, "lastupdatetime",
                apr_psprintf(r->pool, "%ld", current_time) );
                
            write_urs_session(r, cookie, session_data);
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "Session lastupdatetime touched for %s", cookie );
        }
    }
    
    
    return 1;
}



/**
 * Replaces a cookie if it exists, adds it if it does not.
 *
 *
 * @param r a pointer to the request structure for the 
 *          currently active request.
 * @param cookies the cookie string (my contain 0 or more cookies)
 * @param cookie_name the name of the cookie to update
 * @param cookie_value the new value for the cookie
 * @return a new string containing the replaced cookie
 */
static char* replace_cookie( request_rec* r, const char* cookies, const char* cookie_name, const char* cookie_value )
{
    char* start;
    char* end;

    /*
     * Special case of no existing cookies
     */
    if( cookies == NULL || cookies[0] == '\0' )
    {
        start = apr_psprintf(r->pool, "%s=%s", cookie_name, cookie_value);
        return start;
    }
    
    
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Replacing %s=%s in %s", cookie_name, cookie_value, cookies );

    /*
     * Find the start and end of the named cookie (if it does indeed exist
     */
    start = strstr(cookies, cookie_name);
    if( start == NULL ||
        (start > cookies && start[-1] != ' ') ||
        (start[strlen(cookie_name)] != '=') )
    {
        /*
         * The named cookie does not exist, so just append it.
         */
        start = apr_psprintf(r->pool, "%s; %s=%s", cookies, cookie_name, cookie_value);
        return start;
    }


    /*
     * We have a cookie that needs to be replaced. Find the
     * end of it so we can chop it out. These algorithms are
     * not particularly efficient.
     */
    end = strchr(start, ';');
    start = apr_pstrndup(r->pool, cookies, (start - cookies));
    if( end == NULL )
    {
        start = apr_psprintf(r->pool, "%s%s=%s", start, cookie_name, cookie_value);
    }
    else
    {
        start = apr_psprintf(r->pool, "%s%s=%s%s", start, cookie_name, cookie_value, end);
    }
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: New cookie string: %s", start );

    
    return start;
}

