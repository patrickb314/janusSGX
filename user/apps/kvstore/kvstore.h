#ifndef _KVSTORE_H_
#define _KVSTORE_H_

// size of the encryption key
#define KVSTORE_AESKEY_LEN      16
#define KVSTORE_AESKEY_BITS     KVSTORE_AESKEY_LEN << 3
#define KVSTORE_AESIV_LEN       32

#define KVSTORE_KEY_LEN 32
#define KVSTORE_VAL_LEN 192

typedef enum {
    KVSTORE_EXIT    = 0x00,
    KVSTORE_NONE,
    KVSTORE_SET,
    KVSTORE_GET
} kvstore_type_t;

typedef enum {
    STATUS_OK = 0x00,
} kvstore_code_t;

typedef struct {
    kvstore_code_t code;
} __attribute__((packed)) kvstore_ack_t;

typedef struct {
    char key[KVSTORE_KEY_LEN];
    char val[KVSTORE_VAL_LEN];
} __attribute__((packed)) kvstore_load_t;

typedef struct {
    kvstore_type_t type;
    unsigned char sess_id;
    unsigned char iv[KVSTORE_AESIV_LEN];
    kvstore_load_t payload;
} __attribute__((packed)) kvstore_cmd_t;

#endif
