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

#ifdef USE_CRYPTO
#include    "apr_crypto.h"

#include    "httpd.h"
#include    "http_config.h"
#include    "http_core.h"
#include    "http_log.h"
#include    "http_protocol.h"


//const char* passphrase = "This should be a reasonable large, and ideally quite random string to act as a passphrase";



/**
 * Encrpytion function.
 */
 apr_status_t encrypt_block(
        const unsigned char* message, apr_size_t len,
        const char* passphrase,
        unsigned char** out, apr_size_t* outlen,
        request_rec* r )
{
    int rv = APR_SUCCESS;

    apr_crypto_t *context = NULL;
    apr_crypto_key_t *key = NULL;
    apr_size_t ivSize = 0;
    apr_uuid_t salt;

    apr_crypto_block_t *block = NULL;
    const unsigned char *iv = NULL;
    apr_size_t blockSize = 0;

    unsigned char *encrypt = NULL;
    apr_size_t encryptlen, tlen;


    /* Get the encryption context */

    rv = apr_pool_userdata_get((void*) &context, URS_CRYPTO_KEY, r->server->process->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Unable to retrieve encryption context");
        return rv;
    }
    ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r, "UrsAuth: Have context");
    if (context == NULL) ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, r, "UrsAuth: Context is null");

    /* Generate a salt value. This gets embedded in the packet */

    apr_uuid_get(&salt);

    /* Generate a key from the passphrase and salt value */

    rv = apr_crypto_passphrase(&key, &ivSize, passphrase,
        strlen(passphrase),
        (unsigned char *) (&salt), sizeof(apr_uuid_t),
        APR_KEY_AES_256 , APR_MODE_CBC, 1, 4096, context, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Failed generating encryption key");
        return rv;
    }
/*
    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "Key created. ivSize = %d", ivSize);
*/

    /* Initialize the encryption block */

    rv = apr_crypto_block_encrypt_init(&block, &iv, key, &blockSize, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Failed to initialize encrpytion block");
        return rv;
    }
/*
    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "Block created");
*/

    /* Encrypt the data */

    rv = apr_crypto_block_encrypt(
            &encrypt, &encryptlen, message, len, block);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Message encryption failed");
        return rv;
    }
/*
    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "Message encrypted");
*/

    rv = apr_crypto_block_encrypt_finish(encrypt + encryptlen, &tlen, block);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Message encryption failed to finish");
        return rv;
    }
    encryptlen += tlen;
/*
    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "Message encrypted. Length = %d", encryptlen);
*/
    /*
     * Generate the complete encrypted packet. This includes the salt,
     * the initialization vector, and the encrypted data.
     */
    *outlen = ivSize + encryptlen + sizeof(apr_uuid_t);
    *out = apr_palloc(r->pool, ivSize + encryptlen + sizeof(apr_uuid_t));
    memcpy(*out, &salt, sizeof(apr_uuid_t));
    memcpy(*out + sizeof(apr_uuid_t), iv, ivSize);
    memcpy(*out + sizeof(apr_uuid_t) + ivSize, encrypt, encryptlen);
/*
    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "Packet complete. Length = %d", *outlen);
*/
    return rv;
}




/**
 * Encrpytion function.
 */
 apr_status_t decrypt_block(
        const unsigned char* in, apr_size_t inlen,
        const char* passphrase,
        unsigned char** out, apr_size_t* outlen,
        request_rec* r )
{
    int rv = APR_SUCCESS;

    apr_crypto_t *context = NULL;
    apr_crypto_key_t *key = NULL;
    apr_size_t ivSize = 0;

    apr_crypto_block_t *block = NULL;
    apr_size_t blockSize = 0;

    unsigned char *decrypted = NULL;
    apr_size_t decryptedlen, tlen;


    /* Get the encryption context */

    rv = apr_pool_userdata_get((void*) &context, URS_CRYPTO_KEY, r->server->process->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Unable to retrieve encryption context");
        return rv;
    }


    /* Generate the decryption key from the passphrase */

    rv = apr_crypto_passphrase(&key, &ivSize, passphrase,
            strlen(passphrase),
            in, sizeof(apr_uuid_t),
            APR_KEY_AES_256, APR_MODE_CBC, 1, 4096, context, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
            "UrsAuth: Failed generating decryption key");
        return rv;
    }
/*
    ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "Key created. ivSize = %d", ivSize);
*/

    /* Skip the salt value */

    in += sizeof(apr_uuid_t);
    inlen -= sizeof(apr_uuid_t);

    /* Initialize the decryption block */

    rv = apr_crypto_block_decrypt_init(
            &block, &blockSize, in, key, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                "UrsAuth: Failed to initialize decrpytion block");
        return rv;
    }


    /* Skip the initializatio vector */

    in += ivSize;
    inlen -= ivSize;

    /* Now decrypt the message */

    rv = apr_crypto_block_decrypt(
            &decrypted, &decryptedlen, in, inlen, block);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                "UrsAuth: Packet decryption failed");
        return rv;
    }

    rv = apr_crypto_block_decrypt_finish(decrypted + decryptedlen, &tlen, block);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                "UrsAuth: Packet decryption failed to complete");
        return rv;
    }
    decryptedlen += tlen;
    decrypted[decryptedlen] = 0;

/*
    ap_log_rerror( APLOG_MARK, APLOG_INFO, 0, r, "UrsAuth: Decrypted packet: %s", decrypted);
*/
    *out = decrypted;
    *outlen = decryptedlen;

    return rv;
}




#endif



