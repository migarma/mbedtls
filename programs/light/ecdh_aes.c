/*
 *  Example ECDHE with Curve25519 program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#include "mbedtls/ecdh.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_CIPHER_C) && defined(MBEDTLS_MD_C) && \
 defined(MBEDTLS_FS_IO)
#include "mbedtls/cipher.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if !defined(MBEDTLS_ECDH_C) || !defined(MBEDTLS_ECDH_LEGACY_CONTEXT) || \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or MBEDTLS_ECDH_LEGACY_CONTEXT and/or "
                    "MBEDTLS_ECP_DP_CURVE25519_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

#define USAGE   \
    "\n  ecdh_aes <input string buffer>\n" \
    "\n  example: ecdh_aes 'text to encrypt'\n" \
    "\n"

#define PUBLIC_KEY_LEN 32

typedef struct node
{
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_md_context_t md_ctx;

    char name[32];
    char cipher_type[32];
    char md_type[32];
} node_t;

int node_init(node_t *node, const char* name)
{
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;

    mbedtls_ecdh_init(&node->ecdh_ctx);
    mbedtls_ctr_drbg_init(&node->ctr_drbg);
    mbedtls_cipher_init(&node->cipher_ctx);
    mbedtls_md_init(&node->md_ctx);
    strncpy(node->name, name, 32);
    strncpy(node->cipher_type, "AES-256-CBC", 32);
    strncpy(node->md_type, "SHA512", 32);

    mbedtls_entropy_init( &node->entropy );

    if ((mbedtls_ctr_drbg_seed(&node->ctr_drbg, mbedtls_entropy_func, &node->entropy,
                               (const unsigned char *) node->name,
                               strlen(name) ) ) != 0 )
    {
        mbedtls_printf("failed! mbedtls_ctr_drbg_seed\n");
        goto error;
    }

    if (mbedtls_ecp_group_load( &node->ecdh_ctx.grp, MBEDTLS_ECP_DP_CURVE25519 ) != 0 )
    {
        mbedtls_printf("failed! mbedtls_ecp_group_load\n");
        goto error;
    }

    if (mbedtls_ecdh_gen_public(&node->ecdh_ctx.grp, &node->ecdh_ctx.d, &node->ecdh_ctx.Q,
                                mbedtls_ctr_drbg_random, &node->ctr_drbg ) != 0 )
    {
        mbedtls_printf("failed! mbedtls_ecdh_gen_public\n");
        goto error;
    }

    cipher_info = mbedtls_cipher_info_from_string(node->cipher_type);
    if( cipher_info == NULL )
    {
        mbedtls_printf("Cipher '%s' not found\n", node->cipher_type);
        goto error;
    }

    if(mbedtls_cipher_setup(&node->cipher_ctx, cipher_info) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_setup failed\n" );
        goto error;
    }

    md_info = mbedtls_md_info_from_string(node->md_type);
    if(md_info == NULL)
    {
        mbedtls_printf("Message Digest '%s' not found\n", node->md_type);
        goto error;
    }

    if( mbedtls_md_setup(&node->md_ctx, md_info, 1) != 0 )
    {
        mbedtls_printf("mbedtls_md_setup failed\n");
        goto error;
    }
    return 0;

error:
    mbedtls_cipher_free(&node->cipher_ctx);
    mbedtls_md_free(&node->md_ctx);
    mbedtls_ecdh_free(&node->ecdh_ctx );
    mbedtls_ctr_drbg_free(&node->ctr_drbg);
    mbedtls_entropy_free(&node->entropy);
    return -1;
}

int node_write_public_key(const node_t* node, unsigned char* buffer, size_t bufflen)
{
    if (mbedtls_mpi_write_binary(&node->ecdh_ctx.Q.X, buffer, bufflen) != 0)
    {
        mbedtls_printf("failed! mbedtls_mpi_write_binary\n");
        return -1;
    }

    return 0;
}

int node_compute_shared_key(node_t* node, const unsigned char* public_key, size_t public_key_len)
{
    if (mbedtls_mpi_lset(&node->ecdh_ctx.Qp.Z, 1 ) != 0)
    {
        mbedtls_printf( "failed! mbedtls_mpi_lset\n");
        return -1;
    }

    if(mbedtls_mpi_read_binary( &node->ecdh_ctx.Qp.X, public_key, public_key_len) != 0)
    {
        mbedtls_printf( "failed! mbedtls_mpi_read_binary\n");
        return -1;
    }

    if(mbedtls_ecdh_compute_shared(&node->ecdh_ctx.grp, &node->ecdh_ctx.z,
                                   &node->ecdh_ctx.Qp, &node->ecdh_ctx.d,
                                   mbedtls_ctr_drbg_random, &node->ctr_drbg) != 0)
    {
        mbedtls_printf( "failed! mbedtls_ecdh_compute_shared\n");
        return -1;
    }

    return 0;
}

const mbedtls_mpi* node_shared_key(const node_t* node)
{
    return &node->ecdh_ctx.z;
}

int node_shared_key_string(const node_t* node, char *string)
{
    size_t outputlen = 0;
    if (mbedtls_mpi_write_string(node_shared_key(node),
                                 16, string, 128, &outputlen))
    {
        mbedtls_printf("failed! mbedtls_mpi_write_string");
        return -1;
    }

    return 0;
}

int node_shared_key_buffer(const node_t* node, unsigned char *buff, size_t len)
{
    if (mbedtls_mpi_write_binary(node_shared_key(node),
                                 buff, len))
    {
        mbedtls_printf("failed! mbedtls_mpi_write_binary");
        return -1;
    }

    return 0;
}

size_t node_shared_key_len(const node_t* node)
{
    return mbedtls_mpi_size(node_shared_key(node));
}

int node_gen_IV(node_t* node, unsigned char* IV, size_t len)
{
    unsigned char buffer[1024];
    unsigned char digest[MBEDTLS_MD_MAX_SIZE];

    if (mbedtls_ctr_drbg_random(&node->ctr_drbg, buffer, sizeof(buffer)))
    {
        mbedtls_printf("failed! mbedtls_ctr_drbg_random\n");
        return -1;
    }

    mbedtls_md_starts(&node->md_ctx);
    mbedtls_md_update(&node->md_ctx, buffer, 8);
    mbedtls_md_finish(&node->md_ctx, digest);
    memcpy(IV, digest, len);

    return 0;
}

int node_encrypt(node_t* node,
                 const unsigned char* inbuff, size_t ilen,
                 unsigned char* outbuff, size_t* olen)
{
    int i;
    int ret = -1;
    uint32_t count = 0;
    uint32_t offset;
    size_t blocklen;
    size_t encrypted_buff_len;
    unsigned char IV[16];
    unsigned char digest[MBEDTLS_MD_MAX_SIZE] = {0};
    unsigned char key[512] = {0};
    unsigned char encrypted_buff[1024];
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;

    node_gen_IV(node, IV, sizeof(IV));

    memcpy(outbuff + count, IV, sizeof(IV));
    count += sizeof(IV);

    memcpy(digest, IV, sizeof(IV));

    node_shared_key_buffer(node, key, node_shared_key_len(node));
    for (i = 0; i < 8192; i++)
    {
        mbedtls_md_starts(&node->md_ctx );
        mbedtls_md_update(&node->md_ctx, digest, 32);
        mbedtls_md_update(&node->md_ctx, key, node_shared_key_len(node));
        mbedtls_md_finish(&node->md_ctx, digest);
    }

    cipher_info = mbedtls_cipher_info_from_string(node->cipher_type);
    if (mbedtls_cipher_setkey(&node->cipher_ctx, digest, cipher_info->key_bitlen,
                       MBEDTLS_ENCRYPT ) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_setkey() returned error\n");
        goto exit;
    }

    if (mbedtls_cipher_set_iv(&node->cipher_ctx, IV, 16 ) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_set_iv() returned error\n");
        goto exit;
    }

    if (mbedtls_cipher_reset(&node->cipher_ctx) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_reset() returned error\n");
        goto exit;
    }

    mbedtls_md_hmac_starts(&node->md_ctx, digest, 32);

    for( offset = 0; offset < ilen; offset += mbedtls_cipher_get_block_size(&node->cipher_ctx))
    {
        blocklen = (ilen - offset > mbedtls_cipher_get_block_size( &node->cipher_ctx ) ) ?
            mbedtls_cipher_get_block_size( &node->cipher_ctx ) : ( ilen - offset );

        if (mbedtls_cipher_update(&node->cipher_ctx,
                                  inbuff + offset, blocklen,
                                  encrypted_buff, &encrypted_buff_len ) != 0 )
        {
            mbedtls_printf("mbedtls_cipher_update() returned error\n");
            goto exit;
        }

        mbedtls_md_hmac_update(&node->md_ctx, encrypted_buff, encrypted_buff_len);

        memcpy(outbuff + count, encrypted_buff, encrypted_buff_len);
        count += encrypted_buff_len;
    }

    if (mbedtls_cipher_finish(&node->cipher_ctx, encrypted_buff, &encrypted_buff_len) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_finish() returned error\n" );
        goto exit;
    }

    mbedtls_md_hmac_update(&node->md_ctx, encrypted_buff, encrypted_buff_len);

    memcpy(outbuff + count, encrypted_buff, encrypted_buff_len);
    count += encrypted_buff_len;

    mbedtls_md_hmac_finish(&node->md_ctx, digest);

    md_info = mbedtls_md_info_from_string(node->md_type);
    memcpy(outbuff + count, digest, mbedtls_md_get_size(md_info));
    count += mbedtls_md_get_size(md_info);
    *olen = count;

    ret = 0;

exit:
    mbedtls_platform_zeroize(IV, sizeof(IV));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(digest, sizeof(digest));
    return ret;
}

int node_decrypt(node_t* node,
                 const unsigned char* inbuff, size_t ilen,
                 unsigned char* outbuff, size_t* olen)
{
    int i;
    int ret = -1;
    uint32_t count = 0;
    uint32_t offset;
    size_t blocklen;
    size_t decrypted_buff_len;
    size_t datalen;
    const unsigned char *buffer;
    unsigned char IV[16];
    unsigned char digest[MBEDTLS_MD_MAX_SIZE] = {0};
    unsigned char key[512];
    unsigned char decrypted_buff[1024];
    unsigned char diff;
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;

    memcpy(IV, inbuff, sizeof(IV));

    memcpy(digest, IV, sizeof(IV));

    node_shared_key_buffer(node, key, node_shared_key_len(node));
    for (i = 0; i < 8192; i++)
    {
        mbedtls_md_starts(&node->md_ctx);
        mbedtls_md_update(&node->md_ctx, digest, 32);
        mbedtls_md_update(&node->md_ctx, key, node_shared_key_len(node));
        mbedtls_md_finish(&node->md_ctx, digest);
    }

    cipher_info = mbedtls_cipher_info_from_string(node->cipher_type);
    if (mbedtls_cipher_setkey(&node->cipher_ctx, digest, cipher_info->key_bitlen,
                       MBEDTLS_DECRYPT ) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_setkey() returned error\n");
        goto exit;
    }

    if(mbedtls_cipher_set_iv(&node->cipher_ctx, IV, 16) != 0)
    {
        mbedtls_printf("mbedtls_cipher_set_iv() returned error\n" );
        goto exit;
    }

    if(mbedtls_cipher_reset(&node->cipher_ctx) != 0)
    {
        mbedtls_fprintf( stderr, "mbedtls_cipher_reset() returned error\n" );
        goto exit;
    }

    mbedtls_md_hmac_starts(&node->md_ctx, digest, 32);

    md_info = mbedtls_md_info_from_string(node->md_type);
    datalen = ilen - sizeof(IV) - mbedtls_md_get_size(md_info);

    for( offset = 0; offset < datalen; offset += mbedtls_cipher_get_block_size(&node->cipher_ctx))
    {
        blocklen = (datalen - offset > mbedtls_cipher_get_block_size( &node->cipher_ctx ) ) ?
            mbedtls_cipher_get_block_size( &node->cipher_ctx ) : (datalen - offset);

        buffer = inbuff + sizeof(IV) + offset;

        mbedtls_md_hmac_update(&node->md_ctx, buffer, blocklen);
        if (mbedtls_cipher_update(&node->cipher_ctx,
                                  buffer, blocklen,
                                  decrypted_buff, &decrypted_buff_len ) != 0 )
        {
            mbedtls_printf("mbedtls_cipher_update() returned error\n");
            goto exit;
        }

        memcpy(outbuff + count, decrypted_buff, decrypted_buff_len);
        count += decrypted_buff_len;
    }

    if (mbedtls_cipher_finish(&node->cipher_ctx, decrypted_buff, &decrypted_buff_len) != 0 )
    {
        mbedtls_printf("mbedtls_cipher_finish() returned error\n" );
        goto exit;
    }

    memcpy(outbuff + count, decrypted_buff, decrypted_buff_len);
    count += decrypted_buff_len;

    mbedtls_md_hmac_finish(&node->md_ctx, digest);

    buffer =  inbuff + ilen - mbedtls_md_get_size(md_info);

    /* Use constant-time buffer comparison */
    diff = 0;
    for( i = 0; i < mbedtls_md_get_size( md_info ); i++ )
        diff |= digest[i] ^ buffer[i];

    if( diff != 0 )
    {
        mbedtls_printf("HMAC check failed: wrong key, "
                       "or file corrupted.\n" );
        goto exit;
    }

    ret = 0;
    *olen = count;

exit:
    mbedtls_platform_zeroize(IV, sizeof(IV));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(digest, sizeof(digest));
    return ret;
}

void node_free(node_t* node)
{
    mbedtls_cipher_free(&node->cipher_ctx);
    mbedtls_md_free(&node->md_ctx);
    mbedtls_ecdh_free(&node->ecdh_ctx );
    mbedtls_ctr_drbg_free(&node->ctr_drbg);
    mbedtls_entropy_free(&node->entropy);
}

int main( int argc, char *argv[] )
{
    int exit_code = MBEDTLS_EXIT_FAILURE;
    node_t server;
    node_t client;
    unsigned char cli_to_srv[512], srv_to_cli[512];
    size_t outlen_server;
    size_t outlen_client;
    char server_shared_key[512];
    char client_shared_key[512];
    unsigned char *text_to_encrypt;
    uint32_t i;

    if( argc != 2)
    {
        mbedtls_printf(USAGE);
        return exit_code;
    }

    text_to_encrypt = (unsigned char*) argv[1];

    if (node_init(&server, "server-node"))
    {
        mbedtls_printf("failed! server node_init\n");
        goto exit1;
    }

    if (node_init(&client, "client-node"))
    {
        mbedtls_printf("failed! client node_init\n");
        goto exit2;
    }

    if (node_write_public_key(&server, srv_to_cli, PUBLIC_KEY_LEN))
    {
        mbedtls_printf("failed! server node_write_public_key\n");
        goto exit;
    }

    if (node_write_public_key(&client, cli_to_srv, PUBLIC_KEY_LEN))
    {
        mbedtls_printf("failed! client node_write_public_key\n");
        goto exit;
    }

    if (node_compute_shared_key(&server, cli_to_srv, PUBLIC_KEY_LEN))
    {
        mbedtls_printf("failed! server node_compute_shared_key\n");
        goto exit;
    }

    if (node_compute_shared_key(&client, srv_to_cli, PUBLIC_KEY_LEN))
    {
        mbedtls_printf("failed! client node_compute_shared_key\n");
        goto exit;
    }

    /*
     * Verification: are the computed secrets equal?
     */
    node_shared_key_string(&server, server_shared_key);
    node_shared_key_string(&client, client_shared_key);
    mbedtls_printf( "Server shared key: 0x%s\n", server_shared_key);
    mbedtls_printf( "Client shared key: 0x%s\n", client_shared_key);

    mbedtls_printf( "  . Checking if both computed secrets are equal..." );

    if(mbedtls_mpi_cmp_mpi(node_shared_key(&server),
                           node_shared_key(&client)) != 0)
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared\n");
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Encript the input
    mbedtls_printf( "  . Encrypting %s...", text_to_encrypt);
    if (node_encrypt(&server,
                     text_to_encrypt, strlen((char*)text_to_encrypt),
                     srv_to_cli, &outlen_server))
    {
        mbedtls_printf( " failed\n  ! server node_encript\n");
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    fflush(stdout);

    mbedtls_printf( "  . Decrypting ");
    for (i = 0; i < outlen_server; i++)
    {
        mbedtls_printf("%02X", srv_to_cli[i]);
    }
    mbedtls_printf( "...");

    if (node_decrypt(&client,
                     srv_to_cli, outlen_server,
                     cli_to_srv, &outlen_client))
    {
        mbedtls_printf( " failed! server node_encript\n");
        goto exit;
    }

    mbedtls_printf( " ok\n    Received: ");

    for (i = 0; i < outlen_client; i++)
    {
        mbedtls_printf("%c", cli_to_srv[i]);
    }

    mbedtls_printf("\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    node_free(&client);
exit2:
    node_free(&server);
exit1:
#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( exit_code );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
