/*
 * implements dhm exchange with server, based on sample by mbedTLS
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/pk.h"
#include "polarssl/rsa.h"
#include "polarssl/sha256.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

int kvstore_dhm(int server_fd, aes_context * aes, unsigned char * enckey,
        int keylen_bits)
{
    int ret, filesize;
    size_t n, buflen, dhmlen, totallen;

    unsigned char *p, *end;
    unsigned char buf[2048];
    unsigned char hash[32];
    unsigned char dummy[1];
    unsigned char *fptr, *fptr_rsa;
    const char *pers = "dh_client";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    rsa_context rsa;
    dhm_context dhm;
    pk_context pk;
    FILE * f;

    dhm_init( &dhm );

    // setting up the RNG
    printf("\n . Seeding the RNG");
    fflush(stdout);

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                    (const unsigned char *) pers,
                    strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n ! ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    // read server public key
    printf( "\n . Reading server public key" );
    fflush( stdout );

    pk_init(&pk);
    if( (ret = pk_parse_public_keyfile(&pk, "keys/server_pub.pem")) != 0) {
        printf(" failed\n ! could not parse public key (%d).\n", ret);
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA256 );
    rsa_copy(&rsa, pk_rsa(pk));

    // receiving the server parameters
    printf( "\n . Receiving the server's DH parameters" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, 2 ) ) != 2 )
    {
        printf( " failed\n ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    n = buflen = ( buf[0] << 8 ) | buf[1];
    if( buflen < 1 || buflen > sizeof( buf ) ) {
        printf( " failed\n ! Got an invalid buffer length (%zu)\n\n", n );
        goto exit;
    }
    dhmlen = buflen - rsa.len - 2;

    if( ( ret = net_send( &server_fd, dummy, 1) != 1 ) ) {
        printf( " failed \n ! Could not send confirmation to server\n\n" );
        goto exit;
    }

    // get the DHM parameters
    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, n ) ) != (int) n ) {
        printf( " failed\n ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    p = buf, end = buf + buflen;

    if( ( ret = dhm_read_params( &dhm, &p, p + dhmlen) ) != 0 ) {
        printf( " failed\n ! dhm_read_params returned %d\n\n", ret );
        goto exit;
    }

    if( dhm.len < 64 || dhm.len > 512 ) {
        ret = 1;
        printf( " failed\n ! Invalid DHM modulus size\n\n" );
        goto exit;
    }


    // check rsa signature matches
    printf( "\n . Verifying the server's RSA signature" );
    fflush( stdout );

    p += 2;

    if( ( n = (size_t) ( end - p ) ) != rsa.len ) {
        ret = 1;
        printf( " failed\n ! Invalid RSA signature size\n\n" );
        goto exit;
    }

    sha256( buf, (int)( p - 2 - buf ), hash, 0 );

    if( ( ret = rsa_pkcs1_verify( &rsa, NULL, NULL, RSA_PUBLIC,
                    POLARSSL_MD_SHA256, 0, hash, p ) ) != 0 ) {
        printf( " failed\n ! rsa_pkcs1_verify returned %d\n\n", ret );
        goto exit;
    }


    // send public values
    printf( "\n . Sending own public value to server" );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_make_public( &dhm, (int) dhm.len, buf, n,
                    ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
        printf( " failed\n ! dhm_make_public returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = net_send( &server_fd, buf, n ) ) != (int) n ) {
        printf( " failed\n ! net_send returned %d\n\n", ret );
        goto exit;
    }


    // derive shared secret
    printf( "\n . Shared secret: " );
    fflush( stdout );

    if( ( ret = dhm_calc_secret( &dhm, buf, &n,
                    ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n ! dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    memcpy(enckey, buf, keylen_bits);


    // sending the public key value
    printf("\n . Signing the public key");
    fflush(stdout);
    f = fopen("keys/public_key.pem", "r");
    if (f == NULL) {
        printf(" failed\n ! private key file not found\n\n");
        ret = 1;
        goto exit;
    }

    fptr = buf + 4;

    filesize = fread(fptr, sizeof(char), 2048, f);
    if (filesize == 0) {
        printf(" failed\n ! file could not be read\n\n");
        ret = 1;
        goto exit;
    }

    fptr_rsa = fptr + filesize;

    // perform the hash
    sha256(fptr, filesize, hash, 0);

    // read out private key
    pk_init(&pk);
    if ( (ret = pk_parse_keyfile(&pk, "keys/private_key.pem", NULL)) != 0) {
        printf(" failed\n ! could not parse private key (%d).\n", ret);
        goto exit;
    }
    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA256 );
    rsa_copy(&rsa, pk_rsa(pk));

    if ( (ret = rsa_pkcs1_sign(&rsa, NULL, NULL, RSA_PRIVATE,
                    POLARSSL_MD_SHA256, 0, hash, fptr_rsa) ) != 0) {
        printf(" failed\n ! rsa_pkcs1_sign (%d)\n", ret);
        goto exit;
    }

    /*
     * our public string has this format
     * pubkey_size (2) | pubkey (n) | sign_size (2) | signature (k)
     */
    totallen = filesize + 2 + rsa.len;
    buf[0] = (unsigned char)(totallen >> 8);
    buf[1] = (unsigned char)(totallen);
    buf[2] = (unsigned char)(rsa.len >> 8);
    buf[3] = (unsigned char)(rsa.len);

    /* TODO maybe encrypt the signature */

    printf("\n . Sending our public key and signature");
    fflush(stdout);
    if ( ( ret = net_send( &server_fd, buf, 2 ) ) != 2 ) {
        printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    if ( ( ret = net_recv( &server_fd, dummy, 1) != 1 ) ) {
        printf( " failed \n ! Could not get confirmation from server\n\n" );
        goto exit;
    }

    // send the remaining data
    if ( ( ret = net_send( &server_fd, buf+2, totallen) ) != totallen ) {
        printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    // read response from server
    if ( ( ret = net_recv( &server_fd, dummy, 1) != 1 ) ) {
        printf( " failed \n ! Could not get answer from server\n\n" );
        goto exit;
    }

    if (dummy[0] == 0) {
        printf("\n ! Server rejected our public key");
        ret = 1;
    }

    printf("\n * Successfully logged in :) ");

exit:
    fflush(stdout);
    rsa_free( &rsa );
    dhm_free( &dhm );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    return ret;
}

