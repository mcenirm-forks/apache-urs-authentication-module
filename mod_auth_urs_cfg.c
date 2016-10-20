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
 * Author: Peter Smith
 */

#include    "mod_auth_urs.h"


#include    "apr_base64.h"
#include    "apr_lib.h"
#include    "apr_strings.h"
#include    "apr_uuid.h"

#include    "httpd.h"
#include    "http_config.h"
#include    "http_core.h"
#include    "http_log.h"
#include    "http_protocol.h"



/**
 * Method used to create the module server configuration.
 *
 * @param p the pool from which to allocate permanent storage
 * @param s a pointer to the server_rec structure
 * @returna void pointer to the configuration structure
 */
static void *create_auth_urs_svr_config(apr_pool_t *p, server_rec *s)
{
    auth_urs_svr_config* conf = apr_pcalloc( p, sizeof(*conf) );

    ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s,
        "UrsAuth: Initializing server module configuration" );

    /*
     * Initialize the redirection url map. We use this to track
     * valid application redirection URLs.
     */
    conf->redirection_map = apr_table_make(p, 10);

    /* Set up default values for URS */

/*
    conf->urs_auth_path = "/oauth/authorize/";
    conf->urs_token_path = "/oauth/token";
*/
    return conf;
}


/**
 * Method used to merge two module server configurations.
 *
 * @param p the pool from which to allocate storage
 * @path path unused
 * @return void pointer to the configuration structure
 */
static void *merge_auth_urs_srv_config(apr_pool_t *p, void* b, void* a)
{
    auth_urs_svr_config* base = b;
    auth_urs_svr_config* add  = a;
    auth_urs_svr_config* conf = apr_pcalloc(p, sizeof(*conf));
    conf->redirection_map = apr_table_make(p, 10);

    char*   s;
    const apr_array_header_t* elements;

    /*
     * Copy the string configuration values
     */
    s = (add->session_store_path != NULL) ? add->session_store_path : base->session_store_path;
    if( s != NULL ) conf->session_store_path = apr_pstrdup(p, s);

    s = (add->urs_auth_path != NULL) ? add->urs_auth_path : base->urs_auth_path;
    if( s != NULL ) conf->urs_auth_path = apr_pstrdup(p, s);

    s = (add->urs_token_path != NULL) ? add->urs_token_path : base->urs_token_path;
    if( s != NULL ) conf->urs_token_path = apr_pstrdup(p, s);


    /*
     * Copy the auth server uri
     */
    if( add->urs_auth_server.is_initialized )
    {
        apr_uri_parse(p, apr_uri_unparse(p, &add->urs_auth_server, 0), &conf->urs_auth_server);
    }
    else if( base->urs_auth_server.is_initialized )
    {
        apr_uri_parse(p, apr_uri_unparse(p, &base->urs_auth_server, 0), &conf->urs_auth_server);
    }


    /*
     * And finally copy the redirection mappings
     */
    elements = apr_table_elts(add->redirection_map);
    if( elements->nelts == 0 )
    {
        elements = apr_table_elts(base->redirection_map);
    }

    if( elements->nelts > 0 )
    {
        int i;
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            const char* key = entry[i].key;
            const char* value = entry[i].val;

            apr_table_set(conf->redirection_map, key, value);
        }
    }


    return conf;
}


/**
 * Callback used by apache to set the session store directory path
 * when it encounters our UrsSessionStorePath configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config unused
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_session_store_path(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_svr_config* conf = (auth_urs_svr_config*) ap_get_module_config(
        cmd->server->module_config, &auth_urs_module );

    char* test_file;
    apr_file_t* fd;
    apr_finfo_t finfo;


    /*
     * Check that the session store path actually exists and is a directory
     */
    if( apr_stat(&finfo, arg, APR_FINFO_TYPE, cmd->pool) != APR_SUCCESS
        || finfo.filetype != APR_DIR )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsSessionStorePath %s - unable to verify access to configured directory",
            arg);
    }


    /*
     * Check that we can create a file there.
     */
    test_file = apr_pstrcat(cmd->pool, arg, "/.session_test", NULL );

    fd = NULL;
    if( apr_file_open( &fd, test_file,
        APR_READ | APR_WRITE | APR_CREATE | APR_TRUNCATE,
        APR_FPROT_UREAD | APR_FPROT_UWRITE,
        cmd->pool ) != APR_SUCCESS )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsSessionStorePath %s - unable to write to configured directory",
            arg);
    }
    apr_file_close(fd);
    apr_file_remove(test_file, cmd->pool);


    /*
     * Looks like everything is ok. Chop off the test file name and save the
     * new session store path.
     */
    test_file[strlen(arg) + 1] = '\0';
    conf->session_store_path = test_file;

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Session store set to %s", test_file );

    return NULL;
}


/**
 * Callback used by apache to set the URS server when it
 * encounters our UrsAuthServer configuration directive
 *
 * @param cmd pointer to the the command/directive structure
 * @para config unused
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_auth_server(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_svr_config* conf;

    conf = (auth_urs_svr_config*) ap_get_module_config(
        cmd->server->module_config, &auth_urs_module );

    /*
     * Verify the format of the url.
     */
    if( apr_uri_parse(cmd->pool, arg, &conf->urs_auth_server) != APR_SUCCESS )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsAuthServer %s - cannot parse URL",
            arg);
    }
    if( conf->urs_auth_server.path != NULL && conf->urs_auth_server.path[0] != '/' )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsAuthServer %s - path not permitted",
            arg);
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: URS authentication server configured as %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the authentication endpoint path
 * when it encounters our UrsAuthPath configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config unused
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_auth_path(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_svr_config* conf;


    conf = (auth_urs_svr_config*) ap_get_module_config(
        cmd->server->module_config, &auth_urs_module );

    /*
     * Simple check on the path
     */
    if( arg[0] != '/' )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsAuthPath %s - must begin with '/'",
            arg);
    }

    conf->urs_auth_path = apr_pstrdup(cmd->pool, arg);
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: URS authentication path set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the token exchange endpoint path when
 * it encounters our UrsTokenPath configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config unused
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_token_path(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_svr_config* conf;


    conf = (auth_urs_svr_config*) ap_get_module_config(
        cmd->server->module_config, &auth_urs_module );

    /*
     * Simple check on the path
     */
    if( arg[0] != '/' )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsTokenPath %s - must begin with '/'",
            arg);
    }

    conf->urs_token_path = apr_pstrdup(cmd->pool, arg);
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: URS token path set to %s", arg );

    return NULL;
}




/**
 * Method used to create the module directory configuration.
 *
 * @param p the pool from which to allocate storage
 * @path path unused
 * @return void pointer to the configuration structure
 */
static void *create_auth_urs_dir_config(apr_pool_t *p, char* path)
{
    auth_urs_dir_config* conf = apr_pcalloc( p, sizeof(*conf) );

    /*
     * Initialize the user profile sub-process environment
     * map and the redirection url/host map. Everything else is nulled
     * out by virtue of using calloc.
     */
    conf->user_profile_env = apr_table_make(p, 10);
    conf->redirect_urls = apr_table_make(p, 10);

    /* Set up HEAD access by default */

    conf->head_user = "anonymous";

    return conf;
}




/**
 * Method used to merge two module directory configurations.
 *
 * @param p the pool from which to allocate storage
 * @path path unused
 * @return void pointer to the configuration structure
 */
static void *merge_auth_urs_dir_config(apr_pool_t *p, void* b, void* a)
{
    auth_urs_dir_config* base = b;
    auth_urs_dir_config* add  = a;
    auth_urs_dir_config* conf = create_auth_urs_dir_config( p, "merge" );

    char*   s;
    long    l;
    int     i;

    const apr_array_header_t* elements;

    /*
     * Copy the string configuration values
     */
    s = (add->authorization_group != NULL) ? add->authorization_group : base->authorization_group;
    if( s != NULL ) conf->authorization_group = apr_pstrdup(p, s);

    s = (add->cookie_domain != NULL) ? add->cookie_domain : base->cookie_domain;
    if( s != NULL ) conf->cookie_domain = apr_pstrdup(p, s);

    s = (add->session_passphrase != NULL) ? add->session_passphrase : base->session_passphrase;
    if( s != NULL ) conf->session_passphrase = apr_pstrdup(p, s);

    s = (add->client_id != NULL) ? add->client_id : base->client_id;
    if( s != NULL ) conf->client_id = apr_pstrdup(p, s);

    s = (add->authorization_code != NULL) ? add->authorization_code : base->authorization_code;
    if( s != NULL ) conf->authorization_code = apr_pstrdup(p, s);

    s = (add->access_error_url != NULL) ? add->access_error_url : base->access_error_url;
    if( s != NULL ) conf->access_error_url = apr_pstrdup(p, s);

    s = (add->access_error_parameter != NULL) ? add->access_error_parameter : base->access_error_parameter;
    if( s != NULL ) conf->access_error_parameter = apr_pstrdup(p, s);

    s = (add->anonymous_user != NULL) ? add->anonymous_user : base->anonymous_user;
    if( s != NULL ) conf->anonymous_user = apr_pstrdup(p, s);

    s = (add->head_user != NULL) ? add->head_user : base->head_user;
    if( s != NULL ) conf->head_user = apr_pstrdup(p, s);


    /*
     * Copy the numeric configuration values
     */
    l = (add->idle_timeout != 0) ? add->idle_timeout : base->idle_timeout;
    conf->idle_timeout = l;

    l = (add->active_timeout != 0) ? add->active_timeout : base->active_timeout;
    conf->active_timeout = l;

    i = (add->check_ip_octets != 0) ? add->check_ip_octets : base->check_ip_octets;
    conf->check_ip_octets = i;

    i = (add->splash_disable != 0) ? add->splash_disable : base->splash_disable;
    conf->splash_disable = i;

    i = (add->auth401_enable != 0) ? add->auth401_enable : base->auth401_enable;
    conf->auth401_enable = i;

    i = (add->use_cookie_sessions != 0) ? add->use_cookie_sessions : base->use_cookie_sessions;
    conf->use_cookie_sessions = i;

    i = (add->use_cookie_url != 0) ? add->use_cookie_url : base->use_cookie_url;
    conf->use_cookie_url = i;

    /*
     * Copy the redirection uri map
     */
    elements = apr_table_elts(add->redirect_urls);
    if( elements->nelts == 0 )
    {
        elements = apr_table_elts(base->redirect_urls);
    }

    if( elements->nelts > 0 )
    {
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            const char* key = entry[i].key;
            apr_uri_t*  value = (apr_uri_t*) entry[i].val;

            apr_uri_t* url = apr_pcalloc(p, sizeof(apr_uri_t));
            apr_uri_parse(p, apr_uri_unparse(p, value, 0), url);

            apr_table_setn(
                conf->redirect_urls,
                apr_pstrdup(p, key),
                (char*) url);
        }
    }


    /*
     * And finally copy any user profile mappings
     */
    elements = apr_table_elts(add->user_profile_env);
    if( elements->nelts == 0 )
    {
        elements = apr_table_elts(base->user_profile_env);
    }

    if( elements->nelts > 0 )
    {
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            const char* key = entry[i].key;
            const char* value = entry[i].val;

            apr_table_set(conf->user_profile_env, key, value);
        }
    }


    return conf;
}


/**
 * Callback used by apache to set the application client_id when it
 * encounters our UrsClientId configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_client_id(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->client_id = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Authentication client Id set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the cookie domain when it
 * encounters our UrsCookieDomain configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_cookie_domain(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->cookie_domain = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Cookie domain set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the session passphrase when it
 * encounters our UrsSessionPassphrase configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_session_passphrase(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->session_passphrase = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Session passphrase configured - encrypted cookie sessions enabled.");

    return NULL;
}


/**
 * Callback used by apache to enable or disable the cookie session flag.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_cookie_sessions(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    /*
    * Convert to a number and verify.
    */
    if( strcasecmp(arg, "true") == 0 || strcasecmp(arg, "yes") == 0 )
    {
        conf->use_cookie_sessions = 1;
    }
    else if( strcasecmp(arg, "false") == 0 || strcasecmp(arg, "no") == 0 )
    {
        conf->use_cookie_sessions = 0;
    }
    else
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsEnableCookieSessions %s",
            arg);
    }

    if (conf->use_cookie_sessions)
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
            "UrsAuth: Cookie sessions enabled" );
    else
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
            "UrsAuth: Cookie sessions disabled" );

    return NULL;
}


/**
 * Callback used by apache to enable or disable the cookie url flag.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_cookie_url(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    /*
    * Convert to a number and verify.
    */
    if( strcasecmp(arg, "true") == 0 || strcasecmp(arg, "yes") == 0 )
    {
        conf->use_cookie_url = 1;
    }
    else if( strcasecmp(arg, "false") == 0 || strcasecmp(arg, "no") == 0 )
    {
        conf->use_cookie_url = 0;
    }
    else
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsEnableCookieURL %s",
            arg);
    }

    if (conf->use_cookie_url)
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
            "UrsAuth: Cookie URL enabled" );
    else
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
            "UrsAuth: Cookie URL disabled" );

    return NULL;
}


/**
 * Callback used by apache to set the authorization code when it
 * encounters our UrsAuthCode configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_authorization_code(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->authorization_code = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Authentication code set" );

    return NULL;
}


/**
 * Callback used by apache to set the anonymous user when it
 * encounters our UrsAllowAnonymous configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_anonymous_user(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->anonymous_user = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Anonymous user = %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the authorization group when
 * it encounters our UrsAuthGroup configuration driective.
 * This value is used as the cookie name, and is therefore
 * restricted in what characters it may contain (e.g. no spaces).
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_authorization_group(cmd_parms *cmd, void *config, const char *arg)
{
    int i = 0;
    auth_urs_svr_config* sconf;
    auth_urs_dir_config* conf = config;

    const apr_array_header_t* elements;


    conf->authorization_group = apr_pstrdup(cmd->pool, arg);

    while( arg[i] != '\0' )
    {
        if( !apr_isalnum(arg[i]) && arg[i] != '_' )
        {
            return apr_psprintf(cmd->pool,
                "Invalid configuration for UrsAuthGroup %s - '%c' not permitted",
                arg, arg[i]);
        }
        ++i;
    }


    /*
     * Check to see if we there are any entries in the redirect-url map. If so,
     * we must copy them all into the global authorization group/redirect-url
     * map.
     */
    sconf = (auth_urs_svr_config*) ap_get_module_config(
            cmd->server->module_config, &auth_urs_module );

    elements = apr_table_elts(conf->redirect_urls);
    if( elements->nelts > 0 )
    {
        const apr_table_entry_t*  entry;

        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            const char* host = entry[i].key;
            apr_uri_t*  url = (apr_uri_t*) entry[i].val;

            const char* key = apr_pstrcat(cmd->temp_pool, host, ":", url->path, NULL);
            const char* p = apr_table_get(sconf->redirection_map, key);

            if( p == NULL )
            {
                apr_table_set(sconf->redirection_map, key, conf->authorization_group);
            }
            else if( strcasecmp(p, conf->authorization_group) != 0 )
            {
                /* A redirection point associated with more than one group */

                return apr_psprintf(cmd->pool,
                    "Invalid configuration for UrsRedirectUrl %s and UrsAuthGroup %s"
                    " - redirection url already assigned to group %s",
                    key, conf->authorization_group, p);
            }

        }
    }



    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Authorization group set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to enable or disable HEAD request access
 * to protected files. This is invoked by the UrsAllowHead configuration
 * directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param flag boolean value to enable/disable
 * @param name name of user when enabled
 * @return NULL on success, an error essage otherwise
 */
static const char *set_head_user(cmd_parms *cmd, void *config, const char *flag, const char* name)
{
    auth_urs_dir_config* conf = config;

    /* Check to see if HEAD access is enabled or disabled */

    if( strcasecmp(flag, "false") == 0 || strcasecmp(flag, "no") == 0
        || strcasecmp(flag, "0") == 0 )
    {
        conf->head_user = NULL;
        return NULL;
    }


    /* HEAD access is enabled */

    if (name == NULL) {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsAllowHead - enabled, but no user name given");
    }


    conf->head_user = apr_pstrdup(cmd->pool, name);
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: HEAD user = %s", name );

    return NULL;
}


/**
 * Callback used by apache to set the redirection URL when it
 * encounters our UrsRedirectUrl configuration directive.
 * Since this module intercepts a call to this url, it does not
 * actually need to be a real resource.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_redirect_url(cmd_parms *cmd, void *config, const char *host, const char* redirect)
{
    auth_urs_svr_config*    sconf;
    auth_urs_dir_config*    conf = config;

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: set_redirect_url %s | %s | %s | %d",
        host, redirect, cmd->server->server_hostname, cmd->server->port);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: REDIRECT %s   %s",
        host, redirect );
    if( redirect == NULL )
    {
        redirect = host;
        host = cmd->server->server_hostname;
        if( strchr(host, ':') != NULL )
        {
            host = apr_pstrndup(cmd->pool, host, strchr(host, ':') - host);
        }
    }
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: REDIRECT %s   %s",
        host, redirect );


    /*
     * Verify the format of the url.
     */
    apr_uri_t* redirect_url = apr_pcalloc(cmd->pool, sizeof(apr_uri_t));
    if( apr_uri_parse(cmd->pool, redirect, redirect_url) != APR_SUCCESS )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsRedirectUrl %s - cannot parse URL",
            redirect);
    }


    /*
     * Add the redirection url and hostname to the map.
     */
    apr_table_setn(conf->redirect_urls, apr_pstrdup(cmd->pool, host), (const char*) redirect_url);


    /*
     * Check to see if we can add this redirection URL to the server level
     * redirection/authorization group map. This is a mapping from the
     * redirect URL to the authorization group (which determines a specific
     * set of client id/username/password values).
     * We can only set this if the authorization group has already been set
     * for this directory, but have no control over the order in which the
     * configuration is set (and no post-config processing). Thus we have
     * similar code in the authorization group configuration setter.
     */
    sconf = (auth_urs_svr_config*) ap_get_module_config(
            cmd->server->module_config, &auth_urs_module );

    if( conf->authorization_group != NULL )
    {
        const char* key = apr_pstrcat(cmd->temp_pool, host, ":", redirect_url->path, NULL);
        const char* p = apr_table_get(sconf->redirection_map, key);

        if( p == NULL )
        {
            apr_table_set(sconf->redirection_map, key, conf->authorization_group);
        }
        else if( strcasecmp(p, conf->authorization_group) != 0 )
        {
            /* A redirection point associated with more than one group */

            return apr_psprintf(cmd->pool,
                "Invalid configuration for UrsRedirectUrl %s and UrsAuthGroup %s"
                " - redirection url already assigned to group %s",
                key, conf->authorization_group, p);
        }
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Application redirection URL for %s set to %s://%s%s",
        host, redirect_url->scheme, redirect_url->hostinfo, redirect_url->path );

    return NULL;
}


/**
 * Callback used by apache to set the session idle timeout.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_idle_timeout(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    char* p;

    /*
    * Convert to a number and verify.
    */
    conf->idle_timeout = apr_strtoi64(arg, &p, 0);
    if( *p != '\0' )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsIdleTimeout %s",
            arg);
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Idle timeout set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the session active timeout.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_active_timeout(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    char* p;

    /*
    * Convert to a number and verify.
    */
    conf->active_timeout = apr_strtoi64(arg, &p, 0);
    if( *p != '\0' )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsActiveTimeout %s",
            arg);
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Active timeout set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the splash screen disable state.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_splash_disable(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    /*
    * Convert to a number and verify.
    */
    if( strcasecmp(arg, "true") == 0 || strcasecmp(arg, "yes") == 0 )
    {
        conf->splash_disable = 1;
    }
    else if( strcasecmp(arg, "false") == 0 || strcasecmp(arg, "no") == 0 )
    {
        conf->splash_disable = 0;
    }
    else
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsSplashDisable %s",
            arg);
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Splash screen disable set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the 401 URS response.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_auth401_enable(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    /*
    * Convert to a number and verify.
    */
    if( strcasecmp(arg, "true") == 0 || strcasecmp(arg, "yes") == 0 )
    {
        conf->auth401_enable = 1;
    }
    else if( strcasecmp(arg, "false") == 0 || strcasecmp(arg, "no") == 0 )
    {
        conf->auth401_enable = 0;
    }
    else
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for Urs401Enable %s",
            arg);
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: 401 authorization enable set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the session ip octet check count.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_ip_check_octets(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;

    char* p;

    /*
    * Convert to a number and verify.
    */
    conf->check_ip_octets = apr_strtoi64(arg, &p, 0);
    if( *p != '\0' )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsIPCheckOctets %s",
            arg);
    }
    if( conf->check_ip_octets > 4 || conf->check_ip_octets < 0 )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsIPCheckOctets %s - out of range (0-4 inclusive)",
            arg);
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Active timeout set to %s", arg );

    return NULL;
}


/**
 * Callback used by apache to set the sub-process user profile
 * environment.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_user_profile_env(cmd_parms *cmd, void *config, const char *arg1, const char *arg2)
{
    auth_urs_dir_config* conf = config;

    if( arg1 == NULL || arg2 == NULL )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsUserProfileEnv - null value");
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Setting user profile env %s = %s", arg1, arg2 );


    apr_table_set(conf->user_profile_env, arg1, arg2);

    return NULL;
}


/**
 * Callback used by apache to set the access error URL when it
 * encounters our UrsAccessErrorUrl configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_access_error_url(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->access_error_url = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Access error URL set to %s",
        conf->access_error_url );

    return NULL;
}


/**
 * Callback used by apache to set the access error parameter name when it
 * encounters our UrsAccessErrorParameter configuration directive.
 *
 * @param cmd pointer to the the command/directive structure
 * @para config our directory level configuration structure
 * @param arg our directive parameters
 * @return NULL on success, an error essage otherwise
 */
static const char *set_access_error_parameter(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_dir_config* conf = config;
    conf->access_error_parameter = apr_pstrdup(cmd->pool, arg);

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Access error parameter set to %s",
        conf->access_error_parameter );

    return NULL;
}



/**
 * Initialization function for the URS module.
 * Currently nothing to do.
 */
static int urs_module_init(apr_pool_t* p, apr_pool_t* p2, apr_pool_t* p3, server_rec* s)
{
    int rv = APR_SUCCESS;

    return rv;
}


/**
 * Module configuration records.
 */
static const command_rec auth_urs_cmds[] =
{
    /**
     * Session store path is set once, in httpd.conf, not in a directory or
     * location context.
     */
    AP_INIT_TAKE1( "UrsSessionStorePath",
                    set_session_store_path,
                    NULL,
                    RSRC_CONF,
                    "Set the session store path" ),

    AP_INIT_TAKE1( "UrsAuthServer",
                    set_auth_server,
                    NULL,
                    RSRC_CONF,
                    "Set the URS authentication server address" ),

    AP_INIT_TAKE1( "UrsAuthPath",
                    set_auth_path,
                    NULL,
                    RSRC_CONF,
                    "Set the URS authentication endpoint" ),

    AP_INIT_TAKE1( "UrsTokenPath",
                    set_token_path,
                    NULL,
                    RSRC_CONF,
                    "Set the URS token exchange endpoint" ),



    AP_INIT_TAKE1( "UrsAuthGroup",
                    set_authorization_group,
                    NULL,
                    OR_AUTHCFG,
                    "Set the authorization group name" ),

    AP_INIT_TAKE1( "UrsCookieDomain",
                    set_cookie_domain,
                    NULL,
                    OR_AUTHCFG,
                    "Set the cookie domain value" ),

    AP_INIT_TAKE1( "UrsSessionPassphrase",
                    set_session_passphrase,
                    NULL,
                    OR_AUTHCFG,
                    "Set the session encryption passphrase" ),

    AP_INIT_TAKE1( "UrsEnableCookieSessions",
                    set_cookie_sessions,
                    NULL,
                    OR_AUTHCFG,
                    "Enable cookie based sessions" ),

    AP_INIT_TAKE1( "UrsEnableCookieURL",
                    set_cookie_url,
                    NULL,
                    OR_AUTHCFG,
                    "Enable cookie storage of URLs" ),

    AP_INIT_TAKE1( "UrsClientId",
                    set_client_id,
                    NULL,
                    OR_AUTHCFG,
                    "Set the client identifier" ),

    AP_INIT_TAKE1( "UrsAuthCode",
                    set_authorization_code,
                    NULL,
                    OR_AUTHCFG,
                    "Set the authorization code for token exchange" ),

    AP_INIT_TAKE1( "UrsAllowAnonymous",
                    set_anonymous_user,
                    NULL,
                    OR_AUTHCFG,
                    "Set the user for unauthenticated access" ),

    AP_INIT_TAKE12( "UrsAllowHead",
                    set_head_user,
                    NULL,
                    OR_AUTHCFG,
                    "Enable/disable head access to protected files" ),

    AP_INIT_TAKE12( "UrsRedirectUrl",
                    set_redirect_url,
                    NULL,
                    OR_AUTHCFG,
                    "Set the application redirection URL" ),

    AP_INIT_TAKE1( "UrsIdleTimeout",
                    set_idle_timeout,
                    NULL,
                    OR_AUTHCFG,
                    "Set the application idle timeout" ),

    AP_INIT_TAKE1( "UrsActiveTimeout",
                    set_active_timeout,
                    NULL,
                    OR_AUTHCFG,
                    "Set the application active timeout" ),

    AP_INIT_TAKE1( "UrsDisableSplash",
                    set_splash_disable,
                    NULL,
                    OR_AUTHCFG,
                    "Disable URS OAuth2 splash screen" ),

    AP_INIT_TAKE1( "Urs401Enable",
                    set_auth401_enable,
                    NULL,
                    OR_AUTHCFG,
                    "Enable URS 401 response" ),

    AP_INIT_TAKE1( "UrsIPCheckOctets",
                    set_ip_check_octets,
                    NULL,
                    OR_AUTHCFG,
                    "Set the number of IP4 octets to check" ),

    AP_INIT_TAKE2( "UrsUserProfileEnv",
                    set_user_profile_env,
                    NULL,
                    OR_AUTHCFG,
                    "Set the sub-process environment from the user profile" ),

    AP_INIT_TAKE1( "UrsAccessErrorUrl",
                    set_access_error_url,
                    NULL,
                    OR_AUTHCFG,
                    "Set the access error redirection URL" ),

    AP_INIT_TAKE1( "UrsAccessErrorParameter",
                    set_access_error_parameter,
                    NULL,
                    OR_AUTHCFG,
                    "Set the access error URL parameter name" ),

    { NULL }
};

/*
 * Hook function used to register our module.
 * @param p a pool from which memory can be allocated.
 */
static void register_hooks(apr_pool_t *p)
{
    /*
     * Register the primary entry point for our module. This performs
     * the authentication check and redirection.
     */
    ap_hook_check_user_id(auth_urs_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);


    /*
     * Hook used to capture and redirect the URS auth redirection
     */
    ap_hook_post_read_request(auth_urs_post_read_request_redirect, NULL, NULL, APR_HOOK_MIDDLE);


    /*
     * Hook used to capture logout requests
     */
    ap_hook_post_read_request(auth_urs_post_read_request_logout, NULL, NULL, APR_HOOK_MIDDLE);


    /*
     * Filter used to reconstruct the body of a POST request
     */
    ap_register_input_filter( "UrsPostReconstruct", auth_urs_post_body_filter, NULL, AP_FTYPE_CONTENT_SET);


    /*
     * Hook used to perform any post-startup initialization.
     */
    ap_hook_post_config(urs_module_init, NULL, NULL, APR_HOOK_MIDDLE);
}



/**
* The module initialization data.
*/
module AP_MODULE_DECLARE_DATA auth_urs_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_urs_dir_config,
    merge_auth_urs_dir_config,
    create_auth_urs_svr_config,
    merge_auth_urs_srv_config,
    auth_urs_cmds,
    register_hooks
};
