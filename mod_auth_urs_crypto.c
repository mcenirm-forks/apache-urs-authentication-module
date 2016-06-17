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


#include    "apr_uuid.h"

#include    "http_log.h"

#include    <openssl/evp.h>


static const char* urs_cipher_name = "aes-256-cbc";
static const char* urs_digest_name = "sha1";


static const char* urs_init_key = "urs_init_key";


/**
 * Encryption function.
 *
 * This method is used to encrypt a data chunk using the given passphrase.
 */
const unsigned char* crypto_encrypt_packet(request_rec *r, const unsigned char *p, int *len, const char* passphrase)
{
    EVP_CIPHER_CTX      *ctx;
    const EVP_CIPHER    *cipher = NULL;
    const EVP_MD        *digest = NULL;
    unsigned char       key[EVP_MAX_KEY_LENGTH];
    unsigned char       iv[EVP_MAX_IV_LENGTH];
    apr_uuid_t          salt;
    unsigned char       *ciphertext;
    int                 cipherlen;
    void                *init;


    /* One time initialization */

    apr_pool_userdata_get(&init, urs_init_key, r->server->process->pool);
    if(init != NULL) {
        OpenSSL_add_all_algorithms();
    }
    else {
        apr_pool_userdata_set((const void *)1, urs_init_key,
            apr_pool_cleanup_null, r->server->process->pool);
    }


    /* Get the named cipher */

    cipher = EVP_get_cipherbyname(urs_cipher_name);
    if (!cipher) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Unsupported cypher name '%s'", urs_cipher_name);
        return 0;
    }


    /* Get the named digest */

    digest = EVP_get_digestbyname(urs_digest_name);
    if (!digest) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Unsupported digest name '%s'", urs_digest_name);
        return 0;
    }

    /* Generate a salt value. This gets embedded in the packet */

    apr_uuid_get(&salt);


    /* Generate the key and IV */

    if (!EVP_BytesToKey(cipher, digest, (const unsigned char*) &salt,
        (unsigned char *) passphrase, strlen(passphrase), 1, key, iv))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to generate cipher key with cipher '%s' and digest '%s'",
                urs_cipher_name, urs_digest_name);
        return 0;
    }


    /*
     * Now we have everything we need to encrypt a packet, so generate the
     * cipher context.
     */

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to create cipher context");
        return 0;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to initialize cipher context");
        return 0;
    }

    /*
     * Note that AES encryption does not expand the data, although
     * there may be padding bytes. We use a brute force approach
     * to make sure the ciphertext buffer is large enough. Note that the
     * buffer also contains the salt.
     */
    ciphertext = apr_pcalloc(r->pool, *len < 256 ? 1024 : *len * 4);
    memcpy(ciphertext, &salt, sizeof(apr_uuid_t));

    if (!EVP_EncryptUpdate(ctx, ciphertext + sizeof(apr_uuid_t), &cipherlen, p, *len)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to encrypt packet");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    cipherlen += sizeof(apr_uuid_t);


    if (!EVP_EncryptFinal_ex(ctx, ciphertext + cipherlen, len)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to finalize packet encryption");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* All done - clean up and return */

    EVP_CIPHER_CTX_free(ctx);

    *len += cipherlen;

    return ciphertext;
}



/**
 * Decryption function.
 *
 * This method is used to decrypt a data chunk previously encrypted using the
 * given passphrase.
 */
const unsigned char* crypto_decrypt_packet(request_rec *r, const unsigned char *p, int *len, const char* passphrase)
{
    EVP_CIPHER_CTX      *ctx;
    const EVP_CIPHER    *cipher = NULL;
    const EVP_MD        *digest = NULL;
    unsigned char       key[EVP_MAX_KEY_LENGTH];
    unsigned char       iv[EVP_MAX_IV_LENGTH];
    unsigned char       *plaintext;
    int                 plainlen;
    void                *init;


    /* Simple check to prevent basic problems with corrupted packets */

    if (*len <= 16) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Cannot decrypt packet - invalid length");
        return 0;
    }


    /* One time initialization */

    apr_pool_userdata_get(&init, urs_init_key, r->server->process->pool);
    if(init != NULL) {
        OpenSSL_add_all_algorithms();
    }
    else {
        apr_pool_userdata_set((const void *)1, urs_init_key,
            apr_pool_cleanup_null, r->server->process->pool);
    }


    /* Get the named cipher */

    cipher = EVP_get_cipherbyname(urs_cipher_name);
    if (!cipher) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Unsupported cypher name '%s'", urs_cipher_name);
        return 0;
    }


    /* Get the named digest */

    digest = EVP_get_digestbyname(urs_digest_name);
    if (!digest) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Unsupported digest name '%s'", urs_digest_name);
        return 0;
    }


    /*
     * Generate the key and IV. Note that the salt comes from the start of
     * the ciphertext (input).
     */
    if (!EVP_BytesToKey(cipher, digest, p,
        (unsigned char *) passphrase, strlen(passphrase), 1, key, iv))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to generate cipher key with cipher '%s' and digest '%s'",
                urs_cipher_name, urs_digest_name);
        return 0;
    }
    p += sizeof(apr_uuid_t);
    *len -= sizeof(apr_uuid_t);


    /*
     * Now we have everything we need to decrypt a packet, so generate the
     * cipher context.
     */

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to create cipher context");
        return 0;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to initialize cipher context");
        return 0;
    }

    /*
     * Note that AES decryption does not expand the data, so we can allocate
     * an output buffer size the same as the input (the input also has a salt
     * value padding it out).
     */
    plaintext = apr_pcalloc(r->pool, *len);

    if (!EVP_DecryptUpdate(ctx, plaintext, &plainlen, p, *len)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to decrypt packet");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + plainlen, len)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "UrsAuth: Failed to finalize packet decryption");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* All done - clean up and return */

    EVP_CIPHER_CTX_free(ctx);

    *len += plainlen;

    return plaintext;
}
