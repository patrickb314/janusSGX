/**
 * This file is used to generated signed version of client's public keys.
 * to emulate "adding a user" to DynAC
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "polarssl/pk.h"
#include "polarssl/sha256.h"
#include "polarssl/rsa.h"

#define MAX_PUBKEY_SIZE 512

int main(int argc, char **argv)
{
    int ret = 1;
    int filesize;
    char inputfile[50], outputfile[50];
    unsigned char pubkey[MAX_PUBKEY_SIZE], hash[32],\
        buf[POLARSSL_MPI_MAX_SIZE]={0};
    pk_context pk;
    rsa_context rsa;
    FILE *f;

    pk_init(&pk);
    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA256 );

    snprintf(inputfile, 50, "keys/%s_pub.txt", argv[1]);
    snprintf(outputfile, 50, "keys/%s_pub.sig.txt", argv[1]);

    printf("\n . Reading private key");
    if ( (ret = pk_parse_keyfile(&pk, "keys/dynac_priv.txt", NULL)) != 0) {
        printf(" FAILED\n ! pk_parse_private_keyfile (%d, keys/dynac_priv.txt)",
                ret);
        goto exit;
    }
    rsa_copy(&rsa, pk_rsa(pk));
    pk_free(&pk);

    printf("\n . Computing hash of the public key");
    f = fopen(inputfile, "r");
    if (f == NULL) {
        ret = 1;
        printf(" FAILED\n ! File not found (%s)", inputfile);
        goto exit;
    }

    filesize = fread(pubkey, sizeof(char), MAX_PUBKEY_SIZE, f);
    if (filesize == 0) {
        printf(" failed\n ! file could not be read\n\n");
        ret = 1;
        goto exit;
    }

    memset(hash, 0, sizeof(hash));
    sha256(pubkey, filesize, hash, 0);
    fclose(f);

    printf("\n . Performing and writing signature to file");

    if( ( ret = rsa_pkcs1_sign( &rsa, NULL, NULL,
                    RSA_PRIVATE, POLARSSL_MD_SHA256,
                    0, hash, buf ) ) != 0 ) {
        printf(" FAILED\n ! rsa_pkcs1_sign (%d)", ret);
        goto exit;
    }

    f = fopen(outputfile, "wb+");
    if (f == NULL) {
        printf(" FAILED\n ! file (%s) not found", outputfile);
        ret = 1;
        goto exit;
    }

    fwrite(buf, sizeof(char), rsa.len, f);
    fwrite(pubkey, sizeof(char), filesize, f);

    printf("\n + Success ~~~> %s !!!", outputfile);
exit:
    printf("\n");
    fflush(stdout);
    return ret;
}
