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
#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/platform.h"
#else
#include <stdio.h>
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

#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/entropy.h"
#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/ctr_drbg.h"
#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/ecdh.h"
#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/net_sockets.h"
#include "/home/daniel/LASEC/2017-1/mbedtls-2.4.2/include/mbedtls/sha1.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT "11999"

int main( void )
{
    int ret;
    mbedtls_ecdh_context ctx_cli;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_net_context server_fd;
    // mbedtls_aes_context aes;
    unsigned char cli_to_srv[32], srv_to_cli[32];
    const char pers[] = "ecdh";
   
    mbedtls_net_init( &server_fd );
    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ctr_drbg_init( &ctr_drbg );

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
     * Initiate the connection
     */
    mbedtls_printf( "\n  . Connecting to tcp/%s/%s", SERVER_NAME,
                                             SERVER_PORT );
    fflush( stdout );

    if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );


    /*
     * Client: Generate public key
     */

    mbedtls_printf( " ok\n" );
    mbedtls_printf( "  . Setting up client context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_cli.grp, MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );
    mbedtls_printf( "  . Client generating public key..." );
    fflush( stdout );

    ret = mbedtls_ecdh_gen_public( &ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q,
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_cli.Q.X, cli_to_srv, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

      /*
     * Client: Send public key to server
     */
    mbedtls_printf( "  . Client sending public key to server..." );
    fflush( stdout );

     if( ( ret = mbedtls_net_send( &server_fd, cli_to_srv, sizeof(cli_to_srv) ) ) != sizeof(cli_to_srv) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_send returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

     /*
     * Client: read server's key and generate shared secret
     */

    mbedtls_printf( "  . Client reading server key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_cli.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_net_recv( &server_fd, srv_to_cli, sizeof(srv_to_cli) ) ) != sizeof(srv_to_cli) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_recv returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.X, srv_to_cli, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared( &ctx_cli.grp, &ctx_cli.z,
                                       &ctx_cli.Qp, &ctx_cli.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

   /*
    * Start encryption
    */


exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecdh_free( &ctx_cli );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret != 0 );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
