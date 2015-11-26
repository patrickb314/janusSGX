#include <sgx-lib.h>
#include <egate.h>

#include <polarssl/net.h>
#include <polarssl/aes.h>
#include <polarssl/dhm.h>
#include <polarssl/pk.h>
#include <polarssl/rsa.h>
#include <polarssl/sha256.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "libut/include/uthash.h"
#include "libut/include/utlist.h"

#include "kvserver.h"
#include "kvstore.h"


#define SERVER_PORT 11988

#define MAX_DHM_CLIENTS 10

/* the private key of the server, this is expected to be encrypted */
/* TODO use password instead, load private key from encrypted file */
const unsigned char private_key[] = "-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIICWgIBAAKBgHbkwOOsQBoTawUE3lAUQukdH2YZm9t56gBqpr4DpFpY2ZndNk6T\r\n"
"uEZ8mgeGxwrDkGJdL405bl4CoYN5BawFbL7hUPXu0h0vqrJUmD5vueChgOy/kch0\r\n"
"SNMziYRqjnUOVmUW8Vphdeh1lWrlEID1IkEF3VL5ZcrwgR+4A2KJ0qHRAgMBAAEC\r\n"
"gYBiD1f8L+SK3TsmX5aQi7WIGSn9ht+ijJHwmAZAsDZNAf0vR2F0O6gAEuLjlEj0\r\n"
"WsnqJxuCKj0aMqdODXIdKDhApfUnE/sZXgrNOJz3qh5IgmZ1IXYsWEsQegkfKLBI\r\n"
"T5x95ddq1efX/9ZbHPmnD8b/fCp6/kcKOg4xZbWcOlJrhQJBAOwuAHuuz70jPpXP\r\n"
"RJEzIUhnFVtjpsClE5b12iWIw4GYsxev3Yv3Ecl2nx00ue2GenFrVMz48DlKxRMD\r\n"
"+XHU4GMCQQCA3wT1t0LaIV1KGxWZQasnpF/R0IdHesSmfcnGZpWj9oan0Qt7yTIX\r\n"
"BFcnIX9PHR39CFbggDG1MCIpj5ZB5dk7AkAXNU4G2V7Ajz4PKpbqTcPvgXGv0VMJ\r\n"
"iy8pnm8ZUR8lFQRER5vVrSmqSmXIUO4UUSqnCo0Ct1OjzZ0gCTvx26FRAkBRaJEB\r\n"
"h9s7YIhGIAXs4ob0a+n76PcMOImxgxTLuFIfWcSGjo/qipaR47QKjCaYG5SuG26G\r\n"
"M3UzOEzcZFBPIJuxAkAy0Ceos46a6NvCsBhryUUVNCAG1+LdFU/hPXGuF7XAdJ9B\r\n"
"DDeAQIs+pKMu+zn9yGjHgDrPTlOe+3kZV3eh3hys\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const unsigned char dynac_pubkey[] = "-----BEGIN PUBLIC KEY-----\r\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAeSkie/h2PZ/HWKQ6IBE0XVnX\r\n"
"vLKLf3v3N94VsOFbFuVjTNUOEaVU/hl91psSn1TJx8C6BS4JsvpUsPeUeynzC+w9\r\n"
"ciHuKaHC5ucEjqKOhCnOxc9pS8fd6Ed0JIOHBC1rGLPD5F7bzQ5fXjozjriaMiV9\r\n"
"KTtn0NYtfcoUSfXc3wIDAQAB\r\n"
"-----END PUBLIC KEY-----\r\n";

/* generated with openssl. 1024 bits */
static const unsigned char dhparams[] = "-----BEGIN DH PARAMETERS-----\r\n"
"MIIBCAKCAQEAq2DnZFH4pID4eTtaCslVDlP4vP7avU5qM6ICHx3z+JV0bPJn7hCO\r\n"
"FsE9W8RtC5xmT9AEb1eGJYFyL7ZNrDrxZ7wxXCytQKDocE7ry2DEyz8PvvUHUK8t\r\n"
"HgdfcC7XVvqxVzAZkxrxLcJg4Iy7A0eJnC6+a07WckQjVuRsjFryVeQnWTxiZFsz\r\n"
"7Irx4FUrd1XZPfx+QFnvcuO8iH/KExPcOcz90V0PF2yZcFnXhl3AJiCtqatzYrd9\r\n"
"ZRVsLb+poYw4fNS8ZHk+ED8TwjDo15YLm4whWbV/om6enVAQ4pyUQopz7yvaBdxu\r\n"
"4eg5pwsPlS2m3eVpGjGAjNeT6wB7KUe9MwIBAg==\r\n"
"-----END DH PARAMETERS-----\r\n";

/* the rsa key */
rsa_context rsa_enclave;
rsa_context rsa_pub_dynac;

// set to 1 when rsa_enclave
unsigned char rsa_bool = 0;

int client_dhm_count = 0;

/* internal data structure for managing the client's current context */
typedef enum {
    CLIENT_SEND_DHM         = 0,
    CLIENT_GET_DHM_PUBKEY   = 1
} client_dhm_stage_t;

typedef struct {
    int cid;
    int index; // used to free from array
    client_dhm_stage_t stage;
    dhm_context * dhm;
    unsigned char key[KVSTORE_AESKEY_LEN];
    int dhm_n; // size of the dhm output
    ctr_drbg_context * ctr_drbg;
} client_dhm_t;

client_dhm_t * client_dhm_context[MAX_DHM_CLIENTS] = {NULL};

/* the key value data */
typedef struct {
    char key[KVSTORE_KEY_LEN];
    char val[KVSTORE_VAL_LEN];
    UT_hash_handle hh;
} kv_t;

kv_t * kvdata = NULL;

/* the login context of the client */
typedef struct {
    int sess_id;
    unsigned char enckey[KVSTORE_AESKEY_LEN]; // the encryption key
    unsigned char iv[KVSTORE_AESIV_LEN];
    aes_context * aes;
    /* this is to use in a doubly linked list */
    UT_hash_handle hh;
} client_ctx_t;

client_ctx_t * client_ctx_head = NULL; /* doubly linked-list of contexts */

static int __init_rsa(egate_t *g) {
    if (rsa_bool) {
        return 0;
    }

    int ret = 1;

    pk_context pk_ctx, pk_ctx1;
    pk_init(&pk_ctx);
    pk_init(&pk_ctx1);

    rsa_init(&rsa_enclave, RSA_PKCS_V15, POLARSSL_MD_SHA256);
    rsa_init(&rsa_pub_dynac, RSA_PKCS_V15, POLARSSL_MD_SHA256);

    // parse the private key
    if( ( ret = pk_parse_key (&pk_ctx, private_key, sizeof(private_key),
                    NULL, 0) ) !=0 ) {
        eg_printf(g, "! FAILED: parsing server private key (%x)\n", ret);
        goto exit;
    }

    if( ( ret = pk_parse_public_key(&pk_ctx1, dynac_pubkey,
                    sizeof(dynac_pubkey)) ) !=0 ) {
        eg_printf(g, "! FAILED: parsing dynac private key (%x)\n", ret);
        goto exit;
    }

    rsa_copy(&rsa_enclave, pk_rsa(pk_ctx));
    rsa_copy(&rsa_pub_dynac, pk_rsa(pk_ctx1));

    rsa_bool = 1;

    pk_free(&pk_ctx);
    pk_free(&pk_ctx1);

exit:
    return ret;
}

int process_kvstore(egate_t * g, kvstore_cmd_t * cmd)
{
    kv_t *data;
    char *err, *key, *val;
    client_ctx_t * ctx;
    int sess_id = cmd->sess_id;
    kvstore_cmd_t temp_cmd;

    // get the client context
    HASH_FIND_INT(client_ctx_head, &sess_id, ctx);
    if (ctx == NULL) {
        err = "client not found \n";
        goto err;
    }

    copyin(&temp_cmd, cmd, sizeof(kvstore_cmd_t));
    aes_setkey_dec(ctx->aes, ctx->enckey, KVSTORE_AESKEY_BITS);
    // now decrypt
    aes_crypt_cbc(ctx->aes, AES_DECRYPT, sizeof(kvstore_load_t),
            temp_cmd.iv, (const unsigned char *)&temp_cmd.payload,
            (unsigned char *)&temp_cmd.payload);

    key = temp_cmd.payload.key;
    val = temp_cmd.payload.val;

    switch (cmd->type) {
    case KVSTORE_SET:
        // copy the msg and key
        data = (kv_t *) malloc(sizeof(kv_t));
        memcpy(data->key, key, KVSTORE_KEY_LEN);
        memcpy(data->val, val, KVSTORE_VAL_LEN);
        HASH_ADD_STR(kvdata, key, data);
        break;

    case KVSTORE_GET:
        HASH_FIND_STR(kvdata, key, data);
        if (kvdata == NULL) {
            // let's just exit, nothing to copy
            // TODO come up with a sanitary value
            eg_printf(g, "key: %s not found", key);
            return 0;
        }

        // copy it to the kvstore
        memcpy(key, data->key, KVSTORE_KEY_LEN);
        memcpy(val, data->val, KVSTORE_VAL_LEN);

        // now encrypt and copy to E-
        memcpy(temp_cmd.iv, ctx->iv, KVSTORE_AESIV_LEN);
        aes_setkey_enc(ctx->aes, ctx->enckey, KVSTORE_AESKEY_BITS);
        aes_crypt_cbc(ctx->aes, AES_ENCRYPT, sizeof(kvstore_load_t),
                ctx->iv, (const unsigned char *)&temp_cmd.payload,
                (unsigned char *)&temp_cmd.payload);

        if (data) {
            copyout(cmd, &temp_cmd, KVSTORE_VAL_LEN);
        }
        break;

    default:
        err = "This should never happen :(... bye";
        goto err;
    }
    return 0;
err:
    eg_printf(g, "ERROR: %s\n", err);
    return 1;
}

static client_dhm_t * get_client_dhm(int client_id)
{
    int i, last_index;
    client_dhm_t * c_ret;

    last_index = 0;

    for (i = 0; i < MAX_DHM_CLIENTS; i++) {
        c_ret = client_dhm_context[i];
        if (c_ret) {
            last_index++;

            if (c_ret->cid == client_id) {
                return c_ret;
            }
        }
    }

    // allocate and return context
    c_ret = malloc(sizeof(client_dhm_t));
    if (c_ret == NULL) {
        return NULL;
    }

    memset(c_ret, 0, sizeof(client_dhm_t));
    c_ret->cid = client_id;
    c_ret->index = last_index;
    c_ret->stage = CLIENT_SEND_DHM; // we're calculating our dhm context

    client_dhm_context[last_index] = c_ret;
    client_dhm_count++;

    return c_ret;
}

static rsa_context *
__get_client_rsakey(egate_t * g,
                    unsigned char * pubkey_and_sign,
                    int pubkey_and_sign_len)
{
    int ret;
    pk_context client_pubkey;
    rsa_context * client_rsakey;
    unsigned char hash[32];
    // split it into signature and public key
    unsigned char * pubkeystr = pubkey_and_sign + rsa_pub_dynac.len;
    int pubkeylen = pubkey_and_sign_len - rsa_pub_dynac.len;

    /* compute hash of public key and check signature */
    sha256(pubkeystr, pubkeylen, hash, 0);

    if ( ( ret = rsa_pkcs1_verify(&rsa_pub_dynac, NULL, NULL, RSA_PUBLIC,
                    POLARSSL_MD_SHA256, 0, hash, pubkey_and_sign) ) != 0 ) {
        eg_printf(g, " FAILED\n ! rsa_pkcs1_verify (%04zx)\n\n", ret);
        goto exit;
    }

    /* instantial a public value */
    client_rsakey = malloc(sizeof(rsa_context));

    // parse the client's public key
    pk_init(&client_pubkey);
    if ( (ret = pk_parse_public_key(&client_pubkey, pubkeystr, pubkeylen))
            != 0 ) {
        eg_printf(g, " FAILED\n ! parsing client public value (%d, %04x)\n\n",
                pubkeylen, ret);
        goto exit;
    }
    rsa_init(client_rsakey, RSA_PKCS_V15, POLARSSL_MD_SHA256);
    rsa_copy(client_rsakey, pk_rsa(client_pubkey));

    pk_free(&client_pubkey);

    return client_rsakey;
exit:
    return NULL;
}

int process_dhm(egate_t *g, kvenclave_dhm_t *dhm_t)
{
    int ret = 0;
    int pubkeysize;
    size_t n, buflen, rsalen, dhmlen;

    unsigned char buf[KVSERVER_BUF_SIZE], hash[KVSERVER_HASH_SIZE], buf2[2],\
        *p, pubkey[KVSERVER_PUBKEY_SIZE];
    const char *pers = "";
    entropy_context entropy;
    ctr_drbg_context * ctr_drbg;
    dhm_context * dhm;
    //aes_context * aes;
    client_dhm_t * client_dhm;
    rsa_context * client_rsakey;

    /* get the client context */
    client_dhm = get_client_dhm(dhm_t->cfd);
    if (client_dhm == NULL) {
        eg_printf(g, "oops get_client_dhm returned null (count=%u)",
                client_dhm_count);
        goto exit1;
    }

    /* seed the rng */
    enclave_entropy_init(&entropy);

    switch (client_dhm->stage) {
    case CLIENT_SEND_DHM:
        break;
    case CLIENT_GET_DHM_PUBKEY:
        goto get_client_dhm_params;
    }

    /* for a new client we allocate our new data structures */
    dhm = malloc(sizeof(dhm_context));
    ctr_drbg = malloc(sizeof(ctr_drbg_context));

    client_dhm->dhm = dhm;
    client_dhm->ctr_drbg = ctr_drbg;

    dhm_init( dhm );
    // aes_init( &aes );
    __init_rsa(g);

    if ( ( ret = ctr_drbg_init( ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        eg_printf( g, " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    /* parse the dh parameters */
    if ( ( ret = dhm_parse_dhm(dhm, dhparams, sizeof(dhparams)) ) != 0 ) {
        eg_printf (g, " failed\n Invalid DH string %hx", ret);
        goto exit;
    }

    eg_printf(g, "\n  . Beginning Diffie-Hellman");

    if ( ( ret = dhm_make_params(dhm, (int) mpi_size(&dhm->P), buf, &n,
                    ctr_drbg_random, ctr_drbg) ) != 0 ) {
        eg_printf(g, " FAILED ! dhm_make_params (%d)\n\n", ret);
        goto exit;
    }

    eg_printf(g, "\n  . Hashing and signing DH (%d bytes)", (int) n);

    // hash the g^a
    memset(hash, 0, KVSERVER_HASH_SIZE);
    sha256(buf, n, hash, 0);

    // the size of the rsa output
    buf[n    ] = (unsigned char)(rsa_enclave.len >> 8);
    buf[n + 1] = (unsigned char)(rsa_enclave.len);

    if( ( ret = rsa_pkcs1_sign(&rsa_enclave, NULL, NULL, RSA_PRIVATE,
                    POLARSSL_MD_SHA256, 0, hash, buf + n + 2 ) ) != 0) {
        eg_printf(g, "! FAILED: rsa_pkcs1_sign (%d)\n", ret);
        goto exit;
    }

    buflen = n + 2 + rsa_enclave.len;
    buf2[0] = (unsigned char)(buflen >> 8);
    buf2[1] = (unsigned char)(buflen);

    // copy the buffer over to E-
    copyout(dhm_t->buf1, buf, KVSERVER_BUF_SIZE);
    copyout(dhm_t->buf2, buf2, 2);
    dhm_t->dhmlen = dhm->len;

    client_dhm->dhm_n = n;
    client_dhm->stage = CLIENT_GET_DHM_PUBKEY;
    goto exit1;

get_client_dhm_params:
    dhm = client_dhm->dhm;
    ctr_drbg = client_dhm->ctr_drbg;

    // copy all data from E-
    copyin(buf, dhm_t->buf1, KVSERVER_BUF_SIZE);
    copyin(buf2, dhm_t->buf2, 2);
    copyin(pubkey, dhm_t->pubkey, KVSERVER_PUBKEY_SIZE);
    pubkeysize = dhm_t->pubkeysize;

    dhm = client_dhm->dhm;
    dhmlen = client_dhm->dhm_n;
    ctr_drbg = client_dhm->ctr_drbg;

    // make sure the data has not been corrupted along the way
    buflen = (buf2[0] << 8) | buf2[1];
    rsalen = (buf[0] << 8) | buf[1];

    if (pubkeysize > KVSERVER_PUBKEY_SIZE) {
        eg_printf(g, "FAILED\n ! Incorrect parameters passed for public keys");
        ret = 1;
        goto exit;
    }

    if (buflen < 1 || buflen > KVSERVER_BUF_SIZE) {
        ret = 1;
        printf(" FAILED\n ! Got invalid buffer length (%zu)\n\n", buflen);
        goto exit;
    }

    /* extract the public key */
    client_rsakey = __get_client_rsakey(g, pubkey, pubkeysize);
    if (client_rsakey == NULL) {
        eg_printf(g, " parsing public key file FAILED\n");
        ret = 1;
        goto exit;
    }

    /* the size of the client name */
    n = buflen - rsalen - dhmlen - 2;

    p = buf + 2;

    /* compute hash and verify signature */
    sha256(p, dhmlen + n, hash, 0);

    if ( ( ret = rsa_pkcs1_verify(client_rsakey, NULL, NULL, RSA_PUBLIC,
                    POLARSSL_MD_SHA256, 0, hash, p + dhmlen + n) ) != 0 ) {
        printf(" FAILED\n ! rsa_pkcs1_verify (%04x)\n\n", ret);
        goto exit;
    }


    /* if the signature passes, let's derive the secret */

    // get the client value g^b mod p
    if( ( ret = dhm_read_public( dhm, p, dhm->len ) ) != 0 ) {
        eg_printf( g, " failed\n  ! dhm_read_public returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = dhm_calc_secret( dhm, p, &dhmlen, ctr_drbg_random,
                    &ctr_drbg ) ) != 0 ) {
        eg_printf( g, " failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    /* copy the key to the client buffer */
    memcpy(client_dhm->key, p, KVSTORE_AESKEY_LEN);

    // if it passes, we're done
    client_ctx_t * client_ctx = (client_ctx_t *)malloc(sizeof(client_ctx_t));
    memcpy(client_ctx->enckey, client_dhm->key, KVSTORE_AESKEY_LEN);

    enclave_entropy_init(&entropy);
    entropy_func(&entropy, client_ctx->iv, KVSTORE_AESIV_LEN);

    // TODO change this to a generated ID
    client_ctx->sess_id = dhm_t->cfd;

    // set the AES key
    client_ctx->aes = (aes_context *)malloc(sizeof(aes_context));
    aes_setkey_enc(client_ctx->aes, client_ctx->enckey, KVSTORE_AESKEY_BITS);
    aes_setkey_dec(client_ctx->aes, client_ctx->enckey, KVSTORE_AESKEY_BITS);

    // if we get here, we're good to release the dhm context
    client_dhm_context[client_dhm->index] = NULL;
    client_dhm_count--;
    free(client_dhm);

    HASH_ADD_INT(client_ctx_head, sess_id, client_ctx);

exit:
    entropy_free(&entropy);
    dhm_free(dhm);
    ctr_drbg_free(ctr_drbg);
exit1:
    dhm_t->status = ret;
    return ret;
}

void enclave_main(egate_t *g, kvenclave_ops_t op, void *data)
{
    int ret;

    /* egate_enclave_init(g); */
	eg_set_default_gate(g);
    switch(op) {
    case KVENCLAVE_DHM_OP:
        ret = process_dhm(g, (kvenclave_dhm_t *)data);
        break;

    case KVENCLAVE_STORE_OP:
        ret = process_kvstore(g, (kvstore_cmd_t *)data);
        break;

    default:
        eg_printf(g, "Invalid Op... byte\n");
        ret = 1; // TODO have valid return codes
    }
    eg_exit(g, ret);
}
