#ifndef _KVSERVER_H_
#define _KVSERVER_H_

#include "kvstore.h"

#define KVSERVER_HASH_SIZE  32
#define KVSERVER_BUF_SIZE   2048
#define KVSERVER_PUBKEY_SIZE    512
#define MAX_CLIENT_FILE_SIZE    1 << 10

/* used to decide what kind of operations are to be performed */
typedef enum {
    KVENCLAVE_DHM_OP    = 0,
    KVENCLAVE_STORE_OP  = 1,
    KVENCLAVE_FILE_OP   = 3
} kvenclave_ops_t;

typedef struct {
    int cfd;
    int status;
    int dhmlen;
    unsigned char * buf1;
    unsigned char * buf2;
    unsigned char * pubkey;
    int pubkeysize;
} __attribute__ ((packed)) kvenclave_dhm_t;

typedef struct {
    unsigned char pkhash[32]; /* name of data file, hash of pubkey */
    kvstore_cmd_t cmd;
} __attribute__ ((packed)) kvenclave_store_t;

typedef struct {
    int sess_id;
    int load; /* are we loading or saving */
    unsigned int cap; /* capacity of the non-enclave buffer (for save) */
    unsigned int size; /* the size of the content */
    void * data; /* non-enclave pointer */
} kvenclave_fileop_t;

int respond(int *cfd, unsigned char * cmd, size_t size);
int send_ack(int *cfd, kvstore_ack_t *ack);
int send_resp(int *cfd, kvstore_cmd_t *cmd);
void print_bytes(char * pre, void * ptr, int size);

#endif
