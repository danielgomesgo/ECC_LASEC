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
#else
#include <mbedtls/stdio.h>
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_ECDH_C) || \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or "
                    "MBEDTLS_ECP_DP_CURVE25519_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha1.h"
#include "time.h"

#define SERVER_PORT "5000"
#define PLAINTEXT "==Hello there!=="

int main( void )
{
	int i = 0;
	

    int ret;
    mbedtls_net_context listen_fd, client_fd;

    mbedtls_ecdh_context ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_aes_context aes;

    unsigned char cli_to_srv[32], srv_to_cli[32];
    const char pers[] = "ecdh";
    unsigned char mensagem[64] = "Texto para envio";
    unsigned char mensagem2[64] = "";
    unsigned char mensagem3[64] = "";

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_aes_init( &aes );
    mbedtls_aes_free( &aes );
    /*
     * Initialize random number generation
     */ 

    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               sizeof pers ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Server: initialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up server context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_srv.grp, MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q,
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

     ret = mbedtls_mpi_write_binary( &ctx_srv.Q.X, srv_to_cli, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Wait for a client to connect
     */

    mbedtls_printf( "\n  . Waiting for a remote connection" );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

 
    /*
     * Server: read peer's key and generate shared secret
     */

    mbedtls_printf( "  . Server reading client key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_srv.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_net_recv( &client_fd, cli_to_srv, sizeof(cli_to_srv) ) ) != sizeof(cli_to_srv) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_recv returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.X, cli_to_srv, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared( &ctx_srv.grp, &ctx_srv.z,
                                       &ctx_srv.Qp, &ctx_srv.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

     
     /*
     * Server: send public key
     */

    mbedtls_printf( "  . Server sending public key and computing secret..." );
    fflush( stdout );

     if( ( ret = mbedtls_net_send( &client_fd, srv_to_cli, sizeof(srv_to_cli) ) ) != sizeof(srv_to_cli) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_send returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );


    mbedtls_printf("  . s: %d \n  . n: %lu \n  . *p: %lu%lu \n\n", ctx_srv.z.s, ctx_srv.z.n, *ctx_srv.z.p, *(ctx_srv.z.p+sizeof(uint64_t)));

    /*
    mbedtls_printf("%lu \n\n", *ctx_srv.z.p);
    */
    unsigned char chave[21];
	sprintf(chave, "%lu", *ctx_srv.z.p);
    mbedtls_printf("%s\n\n", chave);   
	

	/*
    Iniciando Criptografia
    */
	mbedtls_aes_setkey_enc( &aes, chave, 128);

	mbedtls_printf("  . Mensagem: %s\n", mensagem);
	ret = mbedtls_aes_crypt_ecb( &aes, MBEDTLS_AES_ENCRYPT, mensagem, mensagem2);
	mbedtls_printf("  . Resultado: %d \n\n", ret);
	mbedtls_printf("  . Mensagem cifrada: %s  \n\n\n", mensagem2);

	mbedtls_printf("  . Enviando mensagem cifrada\n");
	
	mbedtls_net_send(&client_fd, mensagem2, sizeof(mensagem2));

	mbedtls_aes_setkey_dec( &aes, chave, 128);
		

    //ret = mbedtls_aes_crypt_ecb( &aes, MBEDTLS_AES_DECRYPT, mensagem2, mensagem3);
    //mbedtls_printf("  . Resultado: %d \n\n", ret);
    //mbedtls_printf("  . Mensagem decifrada: %s  \n", mensagem3);
     
exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecdh_free( &ctx_srv );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret != 0 );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
