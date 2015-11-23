#ifndef _KVSERVER_H_
#define _KVSERVER_H_

#include "kvstore.h"

#define KVSERVER_HASH_SIZE  32
#define KVSERVER_BUF_SIZE   2048

/* used to decide what kind of operations are to be performed */
typedef enum {
    KVENCLAVE_DHM_OP    = 0,
    KVENCLAVE_STORE_OP  = 1
} kvenclave_ops_t;

typedef struct {
    int cfd;
    int status;
    int dhmlen;
    unsigned char * buf1;
    unsigned char * buf2;
} __attribute__ ((packed)) kvenclave_dhm_t;

#endif
