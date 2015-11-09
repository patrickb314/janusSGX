#ifndef _KVSTORE_H_
#define _KVSTORE_H_

#define KVSTORE_KEY_LEN 20
#define KVSTORE_MSG_LEN 180

typedef enum {
    KVSTORE_SET = 0x01,
    KVSTORE_GET = 0x02,
} kvstore_type_t;

typedef enum {
    STATUS_OK = 0x00,
} kvstore_code_t;

typedef struct {
    kvstore_code_t code;
} __attribute__((packed)) kvstore_ack_t;

typedef struct {
    kvstore_type_t type;
    char key[KVSTORE_KEY_LEN];
    char msg[KVSTORE_MSG_LEN];
} __attribute__((packed)) kvstore_cmd_t;

#endif
