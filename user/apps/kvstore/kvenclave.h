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

#define MAX_DHM_CLIENTS         10
#define KVSTORE_RSA_SIZE        128 /* size of key */
#define KVSTORE_MAGIC           0x20152911

extern rsa_context rsa_enclave;
extern rsa_context rsa_pub_dynac;

typedef enum {
    CLIENT_SEND_DHM         = 0,
    CLIENT_GET_DHM_PUBKEY   = 1
} client_dhm_stage_t;

/* current dhm conxtext of user */
typedef struct {
    int cid;
    int index; // used to free from array
    client_dhm_stage_t stage;
    dhm_context * dhm;
    unsigned char key[KVSTORE_AESKEY_LEN];
    unsigned char pubkeyhash[32];
    int dhm_n; // size of the dhm output
    ctr_drbg_context * ctr_drbg;
} client_dhm_t;

/* the key value data */
typedef struct {
    char key[KVSTORE_KEY_LEN];
    char val[KVSTORE_VAL_LEN];
    UT_hash_handle hh;
} kv_t;

/* the login context of the client */
typedef struct {
    int sess_id;
    unsigned char enckey[KVSTORE_AESKEY_LEN]; // the encryption key
    unsigned char iv[KVSTORE_AESIV_LEN];
    aes_context * aes;
    kv_t * kvdata;
    unsigned char pubkeyhash[KVSERVER_HASH_SIZE + 1];
    /* this is to use in a doubly linked list */
    UT_hash_handle hh;
} client_ctx_t;

/* the header file of every stored file */
typedef struct {
    uint32_t    magic;
    uint16_t    count; /* number of elements in file */
    uint8_t     measurement[32];
    uint8_t     signature[KVSTORE_RSA_SIZE];
} __attribute__((packed)) kvserver_header_t;

typedef struct {
    uint32_t    len;
    void *      content;
} file_metadata_t;

/**
 * Parses the client file from disk. E- is suppose to mmap the file
 * in memory.
 * @param fptr is the memory mapped
 * @return the parsed key value
 */
kv_t * parse_client_file(egate_t * g, client_ctx_t * ctx, void * fptr);

/**
 * Converts in-memory hash table to file-ready format.
 * @return null if failed, else the pointer to the memory address
 */
file_metadata_t * save_client_file(egate_t * g, client_ctx_t * ctx);
