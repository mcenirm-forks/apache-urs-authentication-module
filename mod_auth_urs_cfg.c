/*
 * mod_auth_urs.c: URS OAuth2 Module
 *
 * Author: Peter Smith
 */

#include    "mod_auth_urs.h"


#include    "apr_base64.h"
#include    "apr_lib.h"
#include    "apr_strings.h"

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

    return conf;
}



/**
 * Post configuration callback that we use to verify that our
 * basic module configuration is sound.
 *
 * @param p a pool to use for permanant allocations.
 * @param p2 another pool for temporary allocations?
 * @param p3 yet another pool because 2 is never enough.
 * @param s a pointer to the server record structure.
 * return OK if configuration is value, HTTP_INTERNAL_SERVER_ERROR
 *        otherwise.
 */
static int auth_urs_post_config(apr_pool_t* p, apr_pool_t* p2, apr_pool_t* p3, server_rec* s )
{
    auth_urs_svr_config* conf;
    
    
    conf = ap_get_module_config(s->module_config, &auth_urs_module );
    ap_log_perror( APLOG_MARK, APLOG_NOTICE, 0, p,
        "UrsAuth: Post Config check" );    
        
    if( conf->session_store_path == NULL )
    {
        ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p,
            "UrsAuth: Missing configuration UrsSessionStorePath" );    
        return HTTP_INTERNAL_SERVER_ERROR;
    }
         
    if( conf->urs_auth_server.hostname == NULL  )
    {
        ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p,
            "UrsAuth: Missing configuration UrsAuthServer" );    
        return HTTP_INTERNAL_SERVER_ERROR;
    }
         
    if( conf->urs_auth_path == NULL  )
    {
        ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p,
            "UrsAuth: Missing configuration UrsAuthPath" );    
        return HTTP_INTERNAL_SERVER_ERROR;
    }
          
    if( conf->urs_token_path == NULL  )
    {
        ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p,
            "UrsAuth: Missing configuration UrsTokenPath" );    
        return HTTP_INTERNAL_SERVER_ERROR;
    }
  
    return OK;
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

    ap_log_perror( APLOG_MARK, APLOG_DEBUG, 0, p,
        "UrsAuth: Initializing module directory configuration");

    /*
     * Initialize the user profile sub-process environment
     * map. 
     */
    conf->user_profile_env = apr_table_make(p, 10);

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
     * Check to see if we can add this redirection URL to the server level
     * redirection map. This is a mapping from the URL to the auth group,
     * and must be unique across all configurations. 
     * We can only set this when both the group AND the URL have been set,
     * but have no control over the order (and no post-config processing).
     * Thus we must check in each setter method to see if the other one is
     * set, and if so, update the map. Hence this code is duplicated in 
     * the other setter function (as is this comment!).
     */
    sconf = (auth_urs_svr_config*) ap_get_module_config(
            cmd->server->module_config, &auth_urs_module );

    if( conf->redirect_url.path != NULL )
    {
        const char* p = apr_table_get(sconf->redirection_map, conf->redirect_url.path);
        
        if( p == NULL )
        {
            apr_table_setn(sconf->redirection_map,
                conf->redirect_url.path, conf->authorization_group);
        }
        else if( strcasecmp(p, conf->authorization_group) != 0 )
        {
            /* A redirection point associated with more than one group */
            
            return apr_psprintf(cmd->pool,
                "Invalid configuration for UrsRedirectUrl %s and UrsAuthGroup %s"
                " - redirection url already assigned to group %s",
                conf->redirect_url.path, conf->authorization_group, p);
        }
    }
    
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Authorization group set to %s", arg );
           
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
static const char *set_redirect_url(cmd_parms *cmd, void *config, const char *arg)
{
    auth_urs_svr_config*    sconf;
    auth_urs_dir_config*    conf = config;


    /*
     * Verify the format of the url.
     */
    if( apr_uri_parse(cmd->temp_pool, arg, &conf->redirect_url) != APR_SUCCESS )
    {
        return apr_psprintf(cmd->pool,
            "Invalid configuration for UrsRedirectUrl %s - cannot parse URL",
            arg);
    }


    /*
     * Check to see if we can add this redirection URL to the server level
     * redirection map. This is a mapping from the URL to the auth group,
     * and must be unique across all configurations. 
     * We can only set this when both the group AND the URL have been set,
     * but have no control over the order (and no post-config processing).
     * Thus we must check in each setter method to see if the other one is
     * set, and if so, update the map. Hence this code is duplicated in 
     * the other setter function (as is this comment!).
     */
    sconf = (auth_urs_svr_config*) ap_get_module_config(
            cmd->server->module_config, &auth_urs_module );

    if( conf->authorization_group != NULL )
    {
        const char* p = apr_table_get(sconf->redirection_map, conf->redirect_url.path);
        
        if( p == NULL )
        {
            apr_table_setn(sconf->redirection_map,
                conf->redirect_url.path, conf->authorization_group);
        }
        else if( strcasecmp(p, conf->authorization_group) != 0 )
        {
            /* A redirection point associated with more than one group */
            
            return apr_psprintf(cmd->pool,
                "Invalid configuration for UrsRedirectUrl %s and UrsAuthGroup %s"
                " - redirection url already assigned to group %s",
                conf->redirect_url.path, conf->authorization_group, p);
        }
    }

    ap_log_error( APLOG_MARK, APLOG_INFO, 0, cmd->server,
        "UrsAuth: Application redirection URL set to %s://%s%s", 
        conf->redirect_url.scheme, conf->redirect_url.hostinfo, conf->redirect_url.path );
    
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

    AP_INIT_TAKE1( "UrsRedirectUrl",
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

    { NULL }
};



/*
 * Hook function used to register our module.
 * @param p a pool from which memory can be allocated.
 */
static void register_hooks(apr_pool_t *p)
{
    /**
    * Register the primary entry point for our module. This performs
    * the authentication check and redirection.
    */
    ap_hook_check_user_id(auth_urs_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
    
    
    /**
    * Hook used to verify that the necessary configuration has been set.
    */
    ap_hook_post_config(auth_urs_post_config, NULL, NULL, APR_HOOK_MIDDLE);


    /**
    * Hook used to capture and redirect the URS auth redirection
    */
    ap_hook_post_read_request(auth_urs_post_read_request_redirect, NULL, NULL, APR_HOOK_MIDDLE);


    /**
    * Hook used to capture logout requests
    */
    ap_hook_post_read_request(auth_urs_post_read_request_logout, NULL, NULL, APR_HOOK_MIDDLE);
}



/**
* The module initialization data.
*/
module AP_MODULE_DECLARE_DATA auth_urs_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_urs_dir_config,
    NULL, /* directory configuration cannot be inherited */
    create_auth_urs_svr_config,
    NULL, /* server configuration cannot be inherited */
    auth_urs_cmds,
    register_hooks
};

