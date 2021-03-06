/*
 *  Diffie-Hellman-Merkle key exchange (server side)
 *
 *  Copyright (C) 2006-2011, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/pk.h"
#include "polarssl/rsa.h"
#include "polarssl/sha256.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <stdio.h>
#include <string.h>

#include <sgx.h>

#define SERVER_PORT 11298
#define PLAINTEXT "==Hello there!=="

int main( void )
{
    FILE *f;

    int ret;
    size_t n, buflen, manifestlen;
    int listen_fd = -1;
    int client_fd = -1;

    unsigned char buf[2048];
    unsigned char hash[32];
    unsigned char buf2[2];
    unsigned char manifest[2048];
    const char *pers = "dh_server";
    report_t r;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    rsa_context rsa_server, rsa_quoting;
    dhm_context dhm;
    aes_context aes;
    pk_context pk;
    pk_init(&pk);
    dhm_init( &dhm );
    aes_init( &aes );

    memset(hash, 0, 64);
    /*
     * 1. Setup the RNG
     */
    printf( "\n  . Seeding the random number generator" );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    /*
     * 2a. Read the server private RSA key
     */
    printf( "\n  . Reading private key from bootstrap/test-priv.pem" );
    fflush( stdout );



    if( ( ret = pk_parse_keyfile(&pk, "bootstrap/test-priv.pem", NULL) ) != 0 )
    {
        printf( " failed\n  ! Could not parse key in bootstrap/test-priv.pem\n\n");
        goto exit;
    }
    rsa_copy(&rsa_server, pk_rsa(pk));
    rsa_set_padding( &rsa_server, RSA_PKCS_V15, POLARSSL_MD_SHA256 );
    pk_free(&pk);

    /*
     * 2b. Get the DHM modulus and generator
     */
    printf( "\n  . Reading DH parameters from bootstrap/dh_prime.txt" );
    fflush( stdout );

    if( ( f = fopen( "bootstrap/dh_prime.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open bootstrap/dh_prime.txt !\n\n" );
        goto exit;
    }

    if( mpi_read_file( &dhm.P, 16, f ) != 0 ||
        mpi_read_file( &dhm.G, 16, f ) != 0 )
    {
        printf( " failed\n  ! Invalid DH parameter file\n\n" );
        goto exit;
    }

    fclose( f );

    /*
     * 3. Wait for a client to connect
     */
    printf( "\n  . Waiting for a remote connection" );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, NULL, SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 4. Setup the DH parameters (P,G,Ys)
     */
    printf( "\n  . Computing the server's DH parameters" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = dhm_make_params( &dhm, (int) mpi_size( &dhm.P ), buf, &n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! dhm_make_params returned %d\n\n", ret );
        goto exit;
    }
    memcpy(manifest, buf, n); // stash away our info to use in hashing what we get back

    /*
     * 5. Sign the parameters and send them
     */
    printf( "\n  . Hashing and signing the server's %d byte DH parameters", (int)n );
    fflush( stdout );

    sha256( buf, n, hash, 0 );

    buf[n    ] = (unsigned char)( rsa_server.len >> 8 );
    buf[n + 1] = (unsigned char)( rsa_server.len      );

    if( ( ret = rsa_pkcs1_sign( &rsa_server, NULL, NULL, RSA_PRIVATE, POLARSSL_MD_SHA256,
                                0, hash, buf + n + 2 ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_sign returned %d\n\n", ret );
        goto exit;
    }

    buflen = n + 2 + rsa_server.len;
    buf2[0] = (unsigned char)( buflen >> 8 );
    buf2[1] = (unsigned char)( buflen      );

    if( ( ret = net_send( &client_fd, buf2, 2 ) ) != 2 ||
        ( ret = net_send( &client_fd, buf, buflen ) ) != (int) buflen )
    {
        printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 6. Get the client's public value: Yc = G ^ Xc mod P
     */
    printf( "\n  . Receiving the client's public value" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );
    if( ( ret = net_recv( &client_fd, buf, dhm.len ) ) != (int) dhm.len )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = dhm_read_public( &dhm, buf, dhm.len ) ) != 0 )
    {
        printf( " failed\n  ! dhm_read_public returned %d\n\n", ret );
        goto exit;
    }

    memcpy(manifest + n, buf, dhm.len); // Complete constructing the manifest
    manifestlen = n + dhm.len;

    printf( "\n  . Receiving the client's enclave report" );
    if( ( ret = net_recv( &client_fd, (unsigned char *)&r, sizeof(report_t) ) ) != (int) sizeof(report_t) )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    printf( "\n  . Computing the manifest hash and comparing with hash in report");
    memset(hash, 0, 64);
    sha256(manifest, manifestlen, hash, 0);
    
    ret = memcmp(hash, r.reportData, 64);
    if (ret) {
        printf( " failed\n  ! manifest hash and report hash did not match\n\n");
        goto exit;
    }

    printf( "\n  . Receiving the quoting enclave signature of the report" );
    if( ( ret = net_recv( &client_fd, buf2, 2 ) ) != 2 )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    buflen = (buf2[0] << 8) + buf2[1];
    if( ( ret = net_recv( &client_fd, buf, buflen ) ) != buflen )
    {
        printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    printf( "\n  . Checking that the report is signed with the quoting key" );
    if( ( ret = pk_parse_public_keyfile(&pk, "bootstrap/quoting-pub.pem") ) != 0 )
    {
        printf( " failed\n  ! Could not parse key in bootstrap/quoting-pub.pem\n\n");
        goto exit;
    }
    rsa_copy(&rsa_quoting, pk_rsa(pk));
    rsa_set_padding( &rsa_quoting, RSA_PKCS_V15, POLARSSL_MD_SHA256 );
    pk_free(&pk);

    if (rsa_quoting.len != buflen) {
        printf( " failed\n  ! Received signature length (%lu) did not match RSA key length (%lu).\n", buflen, rsa_quoting.len);
	ret = -1;
	goto exit;
    }

    sha256((unsigned char *)&r, 384, hash, 0);

    ret = rsa_pkcs1_verify( &rsa_quoting, NULL, NULL, RSA_PUBLIC, 
			    POLARSSL_MD_SHA256, 0, hash, buf);
    if (ret)
    {
        printf( " failed\n  ! rsa_pkcs1_verify returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 7. Derive the shared secret: K = Ys ^ Xc mod P
     */
    printf( "\n  . Shared secret: " );
    fflush( stdout );

    if( ( ret = dhm_calc_secret( &dhm, buf, &n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    for( n = 0; n < 16; n++ )
        printf( "%02x", buf[n] );

    /*
     * 8. Setup the AES-256 encryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys
     * and MACs.
     */
    printf( "...\n  . Encrypting and sending the ciphertext" );
    fflush( stdout );

    aes_setkey_enc( &aes, buf, 256 );
    memcpy( buf, PLAINTEXT, 16 );
    aes_crypt_ecb( &aes, AES_ENCRYPT, buf, buf );

    if( ( ret = net_send( &client_fd, buf, 16 ) ) != 16 )
    {
        printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    printf( "\n\n" );

exit:

    if( client_fd != -1 )
        net_close( client_fd );

    aes_free( &aes );
    rsa_free( &rsa_server );
    rsa_free( &rsa_quoting );
    dhm_free( &dhm );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    return( ret );
}
