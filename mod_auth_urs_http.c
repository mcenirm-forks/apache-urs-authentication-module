/*
 * mod_auth_urs_http.c: URS OAuth2 Module
 *
 * This module contains functions for sending and receiving
 * HTTP requests over a secure socket.
 * 
 * Author: Peter Smith
 */

#include    "mod_auth_urs.h"

#include    "http_log.h"

#include    "apr_lib.h"
#include    "apr_strings.h"



/**
 * Internal method declarations.
 *
 */

static int http_post_request(request_rec *r, ssl_connection *c, apr_uri_t* server, const char* path, const apr_table_t* headers, const char* body);
static int http_get_request(request_rec *r, ssl_connection *c, apr_uri_t* server, const char* path, const apr_table_t* headers, const char* body);
static int http_read_response(request_rec *r, ssl_connection *c, apr_table_t* headers, char** body);





/************************************
 * External methods
 ************************************/

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
int http_post(request_rec *r, apr_uri_t* server, const char* path, apr_table_t* headers, char** body)
{
    ssl_connection*         connection;
    int                     status;


    /*
     * Establish a connection to the URS endpoint, and post the packet.
     */
    connection = ssl_connect(r, server->hostname, server->port );
    if( connection == NULL ) return HTTP_SERVICE_UNAVAILABLE;



    /*
     * Post the request to the server.
     */
    status = http_post_request(r, connection, server, path, headers, *body);
    if( status == HTTP_OK )
    {
        /*
        * Clear the header table (we will use it to receive the response headers)
        * and read the response.
        */
        apr_table_clear(headers);
        status = http_read_response(r, connection, headers, body );
    }
        
    ssl_disconnect(r, connection);

    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
        "UrsAuth: Request submission status = %d", status );

    if( status == HTTP_OK )
    {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Body: %s", *body );
    }
    
    return status;
}




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
int http_get(request_rec *r, apr_uri_t* server, const char* path, apr_table_t* headers, char** body)
{
    ssl_connection*         connection;
    int                     status;


    /*
     * Establish a connection to the URS endpoint, and post the packet.
     */
    connection = ssl_connect(r, server->hostname, server->port );
    if( connection == NULL ) return HTTP_SERVICE_UNAVAILABLE;



    /*
     * Post the request to the server.
     */
    status = http_get_request(r, connection, server, path, headers, *body);
    if( status == HTTP_OK )
    {
        /*
         * Clear the header table (we will use it to receive the response headers)
         * and read the response.
         */
        apr_table_clear(headers);
        status = http_read_response(r, connection, headers, body );
    }
        
    ssl_disconnect(r, connection);

    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
        "UrsAuth: Request submission status = %d", status );

    if( status == HTTP_OK )
    {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: Body: %s", *body );
    }
    
    return status;
}


/**
 * Extracts the value of a query parameter from the client request.
 * 
 * @param r a pointer to the request structure for the 
 *          currently active request.
 * @param parameter the name of the query parameter to extract.
 * @return a pointer to the query parameter value, or NULL
 *         if it did not exist or was empty.
 */
char* get_query_param( request_rec* r, const char* parameter )
{
    const char* start;
    const char* end;

    if( r->args == NULL ) return NULL;
    
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Searching for [%s] in [%s]", parameter, r->args );

    start = strstr(r->args, parameter);
    if( start == NULL ) return NULL;

    start += strlen(parameter);
    if( start[0] != '=' ) return NULL;

    ++start;
    end = strchr(start, '&');
    if( end == NULL )
    {
        end = start + strlen(start);
    }
    if( start == end ) return NULL;
    
    return apr_pstrndup(r->pool, start, (end - start));
}



/**
 * Extracts the value of a named cookie.
 *
 *
 * @param r a pointer to the request structure for the 
 *          currently active request.
 * @param cookie_name the name of the cookie extract.
 * @return a pointer to the cookie value, or NULL
 *         if it did not exist or was empty.
 */
char* get_cookie( request_rec* r, const char* cookie_name )
{
    const char* all_cookies = apr_table_get(r->headers_in, "Cookie");
    const char* start;
    const char* end;

    /* If there are no cookies, abort */
        
    if( all_cookies == NULL ) return NULL;
    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Cookie string: %s", all_cookies );
    
    /*
     * We have some cookies. Look to see if we can find
     * the right one. Note that we must avoid situations where
     * a cookie name is part of another cookie name, so we must
     * explicitly check the cookie name boundaries.
     */
    start = strstr(all_cookies, cookie_name);
    if( start == NULL ) return NULL;
    if( start > all_cookies && start[-1] != ' ') return NULL;


    start += strlen(cookie_name);
    if( start[0] != '=' ) return NULL;

    ++start;
    end = strchr(start, ';');
    if( end == NULL )
    {
        end = start + strlen(start);
    }
    if( start == end ) return NULL;
    
    return apr_pstrndup(r->pool, start, (end - start));
}




/**
 * Performs an http post type request and reads the response.
 *
 * @param r the current request (used for configuration/memory pool allocations)
 * @param c the secure socket connection to used for sending the request
 * @param server URI containing the address of the server to send the request to
 * @param path the path to post
 * @param headers a table of headers to send. Also used to return response
 *        headers.
 * @param body the body of the request to send. Also used to return the
 *        response body.
 * @return the response status
 */
static int http_post_request(request_rec *r, ssl_connection *c, apr_uri_t* server, const char* path, const apr_table_t* headers, const char* body)
{
    char* request;


    /*
     * Create the initial post header block. Note that we use
     * HTTP/1.0 here, instead of HTTP/1.1. This is to prevent
     * the server from returning use chunked data, which is
     * VERY much harder to read and parse robustly.
     */    
    request = apr_psprintf(r->pool,
        "POST %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n",
        path,  server->hostname, (int) strlen(body));
    
    /*
     * Append any additional headers.
     */
    if( headers != NULL && !apr_is_empty_table(headers) )
    {
        const apr_array_header_t* elements;
        const apr_table_entry_t*  entry;
        int   i;
        
        elements = apr_table_elts(headers);
        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            request = apr_psprintf(r->pool, "%s%s: %s\r\n", request, entry[i].key, entry[i].val );
        }
    }
    
    /*
     * Finalize the request.
     */
    request = apr_psprintf(r->pool, "%s\r\n%s", request, body );

    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
        "UrsAuth: Sending request: %s", request );
        
    if( ssl_write(r, c, request, strlen(request)) <= 0 )
    {
        return HTTP_SERVICE_UNAVAILABLE;
    }
   
    return HTTP_OK;
}


/**
 * Performs an http get type request and reads the response.
 *
 * @param r the current request (used for configuration/memory pool allocations)
 * @param c the secure socket connection to used for sending the request
 * @param server URI containing the address of the server to send the request to
 * @param path the path to post
 * @param headers a table of headers to send. Also used to return response
 *        headers.
 * @param body returns the body of the response
 * @return the response status
 */
static int http_get_request(request_rec *r, ssl_connection *c, apr_uri_t* server, const char* path, const apr_table_t* headers, const char* body)
{
    char* request;


    /*
     * Create the initial request header block.This is to prevent
     * the server from returning use chunked data, which is
     * VERY much harder to read and parse robustly.
     */    
    request = apr_psprintf(r->pool,
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n",
        path,  server->hostname);

    /*
     * Append any additional headers.
     */
    if( headers != NULL && !apr_is_empty_table(headers) )
    {
        const apr_array_header_t* elements;
        const apr_table_entry_t*  entry;
        int   i;
        
        elements = apr_table_elts(headers);
        entry = (const apr_table_entry_t*) elements->elts;

        for( i = 0; i < elements->nelts; ++i )
        {
            request = apr_psprintf(r->pool, "%s%s: %s\r\n", request, entry[i].key, entry[i].val );
        }
    }
    
    /*
     * Finalize the request.
     */
    request = apr_psprintf(r->pool, "%s\r\n", request );

    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r,
        "UrsAuth: Sending request: %s", request );
        
    if( ssl_write(r, c, request, strlen(request)) <= 0 )
    {
        return HTTP_SERVICE_UNAVAILABLE;
    }
   
    return HTTP_OK;
}


/**
 * Reads an HTTP response from a connection.
 *
 * Given we are writing a module for an HTTP server, I would expect there
 * to be some pre-built function for this sort of processing - just can't
 * find anything suitable.
 *
 * @param r the current request (used for configuration/memory pool allocations)
 * @param c the secure socket connection to used for the request/response
 * @param headers used to return the response headers
 * @param body used to return the body of the response
 * @return the response status
*
 */
static int http_read_response(request_rec *r, ssl_connection *c, apr_table_t* headers, char** body)
{
    char*   buffer;
    char*   start;
    char*   end;
    char*   line;
    
    const char* p;

    int     header_done = 0;
    int     body_done = 0;
    
    int     content_length = 0;
    int     status = HTTP_INTERNAL_SERVER_ERROR;


    /*
     * Allocate a buffer to store the response in. We are assuming
     * a limited size response here. Any overflow results in an
     * internal server error.
     */
    buffer = apr_pcalloc(r->pool, 16536);
    start = buffer;
    end = buffer;
    line = buffer;

    
    /*
     * Start a loop read/process loop or the headers. This is complicated
     * by the fact that the server may not send all the data as a 
     * single packet, yet we do not wish to end up with a blocking
     * read.
     */
    while( !header_done )
    {
        /* If we have no more data left, read some more */
        
        if( start == end )
        {
            int freespace;
            int bytes_read;
            
            freespace = 16535 - (end - buffer);
            if( freespace == 0 ) return HTTP_INTERNAL_SERVER_ERROR;
            
            bytes_read = ssl_read(r, c, end, freespace);
            if( bytes_read <= 0 ) return HTTP_INTERNAL_SERVER_ERROR;
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Read packet. size = %d", bytes_read );
            
            end += bytes_read;
            *end = '\0';
        }


        /* Continue parsing the header data */

        while( start < end && !header_done )
        {
            if( *start == '\r' && start[1] == '\n' )
            {
                /*
                 * This is an end of header line, so null terminate
                 * it (we return pointers into the read buffer for the
                 * various header strings).
                 */
                
                *start = 0;
             
                ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                    "UrsAuth: Header: [%s]", line );
                    
                if( start == line )
                {
                    /* This is a blank line, and signifies the end of the header */
                    
                    header_done = 1;
                }
                else if( strncmp(line, "HTTP/1", 6) == 0 )
                {
                    /*
                     * This is the status line, so extract the status.
                     */
                    
                    char* p = line + 9;
                    if( !apr_isdigit(*p) ) return HTTP_INTERNAL_SERVER_ERROR;
                    status = atoi(p);
                }
                else
                {
                    /*
                     * This is a regular header line and must be parsed into
                     * a key (the header name) and its value.
                     */
                    char* key = line;
                    char* value;
                    
                    while( *key == ' ') ++key;
                    
                    value = key;
                    while( *value != ':' )
                    {
                        if( *value == '\0' ) return HTTP_INTERNAL_SERVER_ERROR;
                        ++value;
                    }
                    *value = '\0';
                    ++value;
                    while( *value == ' ') ++value;

                    apr_table_setn(headers, key, value);
                }
                
                ++start;
                line = start + 1;
            }
            ++start;
        }
    }


    /*
     * We carry on to ready the body only in the case of a 200 status,
     * or the caller wishes to read the body, as indicated by a non-null
     * location to store the body pointer.
     */
    
    if( status != HTTP_OK || body == NULL ) return status;

    
    /* 
     * Now we must read the body. If we have a content length, we can use this to
     * determine exactly how much to read. Otherwise,we have to read until the
     * connection closes and the read returns 0 (unless it is 'chunked', but we
     * do not currently support that).
     * 
     * At this point, 'start' should point to the first character of the response
     * body, and 'end' to the last character read (these may be equal).
     */
    p = apr_table_get(headers, "Content-Length");
    if( p != NULL ) content_length = atoi(p);
    
    if( content_length == 0 )
    {
        /* No content length, look for transfer encoding */
        
        p = apr_table_get(headers, "Transfer-Encoding");
        if( p != NULL && strncasecmp(p, "chunked", 7) == 0 )
        {
            /* The server is chunking - currently not supported */

            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Server response is chunked - not supported!" );

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    
    while( !body_done )
    {
        int bytes_read = end - start;
        
        if( content_length == 0 || bytes_read < content_length )
        {
            int freespace;
            
            freespace = 16535 - (end - buffer);
            if( freespace == 0 ) return HTTP_INTERNAL_SERVER_ERROR;
            
            bytes_read = ssl_read(r, c, end, freespace);
            if( bytes_read == 0 && content_length == 0 )
            {
                /*
                 * This is the 'no content length header' case. We set the flag
                 * to indicate the we have done reading the body, and set the
                 * content length header ourself.
                 */
            
                body_done = 1;
                apr_table_setn(headers,
                    "Content-length", apr_psprintf(r->pool, "%d", bytes_read));
            }
            else if( bytes_read < 0 )
            {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
                "UrsAuth: Read packet. size = %d", bytes_read );

            end += bytes_read;
            *end = '\0';
        }
        else if( bytes_read == content_length )
        {
            body_done = 1;
        }
    }

    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Read body: %s", start );
    *body = start;

    return status;
}






