/**
 * Bookeeping functions for kvstore_server_sgx
 */
#include <polarssl/sha256.h>
#include "libut/include/uthash.h"

#include "kvserver.h"
#include "kvenclave.h"

typedef struct {
    char key[KVSTORE_KEY_LEN];
    char val[KVSTORE_VAL_LEN];
} __attribute__((packed)) dummy_kv_t;

kv_t * parse_client_file(egate_t * g, client_ctx_t * ctx, void * fptr)
{
    kv_t *data = NULL, *kvdata = NULL;
    dummy_kv_t *dummy;
    int ret;
    uint16_t i;
    void * ptr  = fptr;
    sha256_context sha256_ctx;
    uint8_t hash[32];

    /* parse the header file */
    kvserver_header_t * header = (kvserver_header_t *)ptr;

    if (header->magic != KVSTORE_MAGIC) {
        eg_printf(g, "FAILED\n ! magic header not found (%hx)", header->magic);
        goto exit;
    }

    sha256_init(&sha256_ctx);
    sha256_starts(&sha256_ctx, 0);

    ptr = (char *)ptr + sizeof(kvserver_header_t);

    dummy = ptr;

    /* read the key value as we go */
    for (i = 0; i < header->count; i++) {
        data = malloc(sizeof(kv_t));
        if (data == NULL) {
            eg_printf(g, "FAILED\n ! not enough memory :(");
            goto err;
        }
        /* TODO decrypt this */
        memcpy(data->key, dummy->key, KVSTORE_KEY_LEN);
        memcpy(data->val, dummy->val, KVSTORE_VAL_LEN);
        HASH_ADD_STR(kvdata, key, data);

        sha256_update(&sha256_ctx, (unsigned char *)dummy, sizeof(dummy_kv_t));

        dummy = (dummy_kv_t *)((char *)dummy + sizeof(dummy_kv_t));
    }

    sha256_update(&sha256_ctx, (unsigned char *)header,
            sizeof(header->magic) + sizeof(header->count));
    sha256_finish(&sha256_ctx, hash);
    sha256_free(&sha256_ctx);

    if ( (ret = rsa_pkcs1_verify(&rsa_enclave, NULL, NULL, RSA_PRIVATE,
            POLARSSL_MD_SHA256, 0, hash, header->signature) ) ) {
        eg_printf(g, "rsa_pkcs1 failed (%hx)\n", ret);
        goto err;
    }

    goto exit;

err:
    // TODO safely delete added values
    kvdata = NULL;
exit:
    return kvdata;
}

file_metadata_t * save_client_file(egate_t * g, client_ctx_t * ctx)
{
    kv_t * kvdata = ctx->kvdata;
    kv_t * data;
    int ret;
    uint16_t i = 0;
    uint16_t count = HASH_COUNT(kvdata);
    void * ptr;
    dummy_kv_t * dummy;
    kvserver_header_t * header;
    sha256_context sha256_ctx;
    file_metadata_t * saved_data;

    saved_data = malloc(sizeof(file_metadata_t));
    if (saved_data == NULL) {
        return NULL;
    }

    saved_data->len = count*sizeof(dummy_kv_t) + sizeof(header);

    ptr = malloc(saved_data->len);
    if (ptr == NULL) {
        eg_printf(g, "memory allocation failed\n");
        return NULL;
    }

    sha256_init(&sha256_ctx);
    sha256_starts(&sha256_ctx, 0);

    header = (kvserver_header_t *)ptr;
    header->magic = KVSTORE_MAGIC;
    header->count = count;

    dummy = (dummy_kv_t *)((char *)ptr + sizeof(kvserver_header_t));

    for (data = kvdata; data != 0; data = data->hh.next) {
        i++;
        // TODO encrypt this
        memcpy(dummy->key, data->key, KVSTORE_KEY_LEN);
        memcpy(dummy->val, data->val, KVSTORE_VAL_LEN);

        sha256_update(&sha256_ctx, (unsigned char *)dummy, sizeof(dummy_kv_t));

        dummy = (dummy_kv_t *)((char *)dummy + sizeof(dummy_kv_t));
    }

    /* update the header and then sign */
    sha256_update(&sha256_ctx, (unsigned char *)header,
            sizeof(header->magic) + sizeof(header->count));
    sha256_finish(&sha256_ctx, header->measurement);
    sha256_free(&sha256_ctx);

    if ( (ret = rsa_pkcs1_sign(&rsa_enclave, NULL, NULL, RSA_PRIVATE,
            POLARSSL_MD_SHA256, 0, header->measurement, header->signature) ) ) {
        eg_printf(g, "rsa_pkcs1 failed (%hx)\n", ret);
        return NULL;
    }

    saved_data->content = ptr;

    return saved_data;
}
