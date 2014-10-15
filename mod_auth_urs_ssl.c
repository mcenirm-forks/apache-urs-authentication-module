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
 * mod_auth_urs_ssl.c: URS OAuth2 Module
 *
 * SSL connection handling methods.
 *
 * Author: Peter Smith
 */

#include    "mod_auth_urs.h"

#include    "http_log.h"

#include    <openssl/ssl.h>

#include    <sys/socket.h>
#include    <netinet/in.h>
#include    <netdb.h>
#include    <unistd.h>


/**
 * Internal structure used to record details of an SSL connection.
 */
struct ssl_connection
{
    int      socket;
    SSL*     ssl_handle;
    SSL_CTX* ssl_context;

};



/**
 * Establishes an SSL connection to a remote server.
 * @param r a pointer to the apache request_rec structure.
 * @param host the name of the host to connect to
 * @param port the port number to connect to
 * return a pointer to an ssl_connection structure, or
 *        NULL on error
 */
ssl_connection *ssl_connect(request_rec *r, const char* host, int port )
{
    int     handle;
    struct hostent *hostent;
    struct sockaddr_in server;
    ssl_connection* c;


    if( port == 0 ) port = DEFAULT_HTTPS_PORT;

    ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
        "UrsAuth: Creating secure connection to %s on port %d", host, port );

    /*
     * Allocate a connection structure and create a socket
     * connected to the approriate host
     */
    hostent = gethostbyname(host);
    handle = socket(AF_INET, SOCK_STREAM, 0);
    if( handle == -1 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Unable to create a socket - possible descriptor exhaustion?" );

        return NULL;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr = *((struct in_addr *) hostent->h_addr);
    bzero(&(server.sin_zero), 8);

    if( connect(handle,(struct sockaddr *) &server, sizeof(struct sockaddr)) == -1 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to connect to %s on port %d", host, port );

        return NULL;
    }

    c = apr_pcalloc(r->pool, sizeof(ssl_connection));
    c->socket = handle;


    /*
     Initialize the SSL library (shold not be necessary if
     mod_ssl is enabled).

     Register the error strings for libcrypto & libssl

       SSL_load_error_strings();

     Register the available ciphers and digests

       SSL_library_init();
    */


    /*
     * Allocate context saying we are a client, and using SSL 2 or 3
     */
    c->ssl_context = SSL_CTX_new(SSLv23_client_method());

    if( c->ssl_context == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to create context for SSL" );
        ssl_disconnect(r, c);

        return NULL;
    }

    /* Create an SSL struct for the connection */

    c->ssl_handle = SSL_new(c->ssl_context);
    if( c->ssl_handle == NULL )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to create handle for SSL" );
        ssl_disconnect(r, c);

        return NULL;
    }


    /* Connect the SSL struct to our connection */

    if( !SSL_set_fd(c->ssl_handle, c->socket) )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to set handle for SSL" );
        ssl_disconnect(r, c);

        return NULL;
    }

    /* Initiate SSL handshake */

    if( SSL_connect(c->ssl_handle) != 1 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
            "UrsAuth: Failed to establish SSL session" );
        ssl_disconnect(r, c);

        return NULL;
    }

    return c;
}



/**
 * Close and tidy up an SSL connection.
 * @param r a pointer to the current request (not currently needed)
 * @param c a pointer to the ssl_connection structure to be cleaned
 */
void ssl_disconnect( request_rec *r, ssl_connection *c )
{
    if( c->socket ) close(c->socket);

    if( c->ssl_handle ) SSL_shutdown(c->ssl_handle);
    if( c->ssl_handle ) SSL_free(c->ssl_handle);
    if( c->ssl_context ) SSL_CTX_free(c->ssl_context);
}




/**
 * Reads a chunk of data from the SSL connection.
 * @param r a pointer to the current request
 * @param c a pointer to the ssl_connection structure to be
 *          read from.
 * @param buffer the buffer into which the data is to be placed
 * @param bufsize the size of the buffer.
 * @return the number of bytes read, or negative error number
 */
int ssl_read(request_rec *r, ssl_connection *c, char *buffer, int bufsize)
{
    int received = SSL_read(c->ssl_handle, buffer, bufsize);
    if( received < 0 )
    {
        ap_log_rerror( APLOG_MARK, APLOG_DEBUG, 0, r,
            "UrsAuth: SSL read failed - returned exit code %d", received );
    }

    return received;
}




/**
 * Writes a chunk of data to the SSL connection.
 * @param r a pointer to the current request
 * @param c a pointer to the ssl_connection structure to be
 *          read from.
 * @param buffer the data to be written
 * @param bufsize the size of the data in the buffer.
 * @return the number of bytes written, or negative error number
 */
int ssl_write(request_rec *r, ssl_connection *c, char *buffer, int bufsize )
{
    int sent= 0;

    if( bufsize > 0 )
    {
        sent = SSL_write(c->ssl_handle, buffer, bufsize);
        if( sent <= 0 )
        {
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: SSL write failed - returned exit code %d", sent );
        }
    }

    return sent;
}

