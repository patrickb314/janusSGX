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

#define MAX_PUBKEY_FILESIZE 512

int
kvstore_dhm(int server_fd,
            aes_context * aes,
            char * client_name,
            unsigned char * enckey,
            int keylen_bits)
{
    int ret;
    size_t n, buflen, dhmlen, totallen, namelen;

    unsigned char *p, *end, *buf1;
    unsigned char buf[2048], secret[2048];
    unsigned char hash[32];
    unsigned char dummy[1];
    unsigned char *fptr, *fptr_rsa;
    char privatekey[50];
    const char *pers = "dh_client";

    sprintf(privatekey, "keys/%s_priv.txt", client_name);

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    rsa_context rsa;
    dhm_context dhm;
    pk_context pk;

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
    if( (ret = pk_parse_public_keyfile(&pk, "keys/enclave_pub.txt")) != 0) {
        printf(" failed\n ! could not parse enclave public key (%d).\n", ret);
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
        ret = 1;
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
        ret = 1;
        goto exit;
    }

    // get the DHM parameters
    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, n ) ) != (int) n ) {
        printf( " failed\n ! net_recv returned %d\n\n", ret );
        ret = 1;
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

    buf1 = buf + 4;
    /* setting the client's hash and rsa sizes */
    n = dhm.len;
    if( ( ret = dhm_make_public( &dhm, (int) dhm.len, buf1, n,
                    ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
        printf( " failed\n ! dhm_make_public returned %d\n\n", ret );
        goto exit;
    }

    // derive shared secret
    printf( "\n . Shared secret: " );
    fflush( stdout );

    if( ( ret = dhm_calc_secret( &dhm, secret, &n,
                    ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n ! dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    memcpy(enckey, secret, keylen_bits);

    // send public values
    printf( "\n . Sending own public value to server" );
    fflush( stdout );

    /* final buffer is of the format */
    /*     total_len    | len(sign) | (dhm) | hash | sign
     *      2 bytes     |  2 bytes  |       |  4
     */

    // sending the public key value
    printf("\n . Signing the message");
    fflush(stdout);
    fptr = buf1 + n;

    namelen = strlen(client_name);

    // perform the hash
    strncpy((char *)fptr, client_name, namelen);

    // add the hash of the public key to buf
    // move over by 32 bytes
    fptr_rsa = fptr + namelen;
    fptr_rsa[0] = '\0';
    fptr_rsa++;

    // + 1 to include the \0 terminator
    sha256(buf1, n + namelen + 1, hash, 0);

    // read out private key
    pk_init(&pk);
    if ( (ret = pk_parse_keyfile(&pk, privatekey, NULL)) != 0) {
        printf(" failed\n ! could not parse private key (%s, %d).\n", privatekey, ret);
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
     * pubkey_size (2) | pubkey (n) | name + 1 | signature (k)
     */
    totallen = 2 + n + namelen + 1 + rsa.len;
    buf[0] = (unsigned char)(totallen >> 8);
    buf[1] = (unsigned char)(totallen);
    buf[2] = (unsigned char)(rsa.len >> 8);
    buf[3] = (unsigned char)(rsa.len);

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

    // TODO this must contain session ID from server (0 means rejected)
    if ( ( ret = net_recv( &server_fd, dummy, 1) != 1 ) ) {
        printf( " failed \n ! Could not get answer from server\n\n" );
        goto exit;
    }

    if (dummy[0] == 0) {
        printf("\n ! Server rejected our public key");
        ret = 1;
    }

    printf("\n + Successfully logged in :) ");

exit:
    fflush(stdout);
    rsa_free( &rsa );
    dhm_free( &dhm );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    return ret;
}

