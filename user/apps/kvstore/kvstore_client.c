#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/pk.h"
#include "polarssl/rsa.h"
#include "polarssl/sha256.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include <sgx.h>

#include "kvstore.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT 11988

#define WAIT_TIME 2

int kvstore_dhm(int, aes_context *, unsigned char *, int);

int pfd = -1;

static aes_context aes;
static unsigned char enckey[KVSTORE_AESKEY_LEN];
static unsigned char iv[KVSTORE_AESIV_LEN] = {0}; // computed using sha256

static int __init()
{
    int ret;

    printf("   .  Connecting to secure kvstore server\n");

    if( (ret = net_connect(&pfd, SERVER_NAME, SERVER_PORT)) ) {
        printf("   *  FAILED, net_connect %d\n", ret);
        goto exit;
    }

    return 0;

exit:
    return( ret );

}

static int response(int *cfd, unsigned char * cmd, size_t size)
{
    int ret;

    if( ( ret = net_recv(cfd, cmd, size) ) != size ) {
        printf("\n   FAILED net_recv (%d)", ret);
        return -1;
    }

    return 0;
}

static inline int get_ack(int *cfd, kvstore_ack_t *ack)
{
    return response(cfd, (unsigned char *)ack, sizeof(kvstore_ack_t));
}

static inline int get_resp(int *cfd, kvstore_cmd_t *cmd)
{
    return response(cfd, (unsigned char *)cmd, sizeof(kvstore_cmd_t));
}

static int send_data(int *cfd, kvstore_cmd_t * cmd, size_t size)
{
    int ret;
    // printf("\n  . Sending data... ");
    if( ( ret = net_send(cfd, (unsigned char *)cmd, size) ) != size ) {
        printf("FAILED net_send (%d)", ret);
        return -1;
    }
    // printf("OK");

    return 0;
}

void str_trim(char * c)
{
    char *p_c = c + strlen(c) - 1;

    if (p_c < c) {
        return;
    }

    while (*p_c == '\0' || *p_c == '\n' || *p_c == '\t') {
        *p_c = '\0';
        p_c--;
    }
}

static char * get_type_str(kvstore_type_t type)
{
    switch(type) {
    case KVSTORE_NONE:
        return "none";
    case KVSTORE_GET:
        return "get";
    case KVSTORE_SET:
        return "set";
    case KVSTORE_EXIT:
        return "exit";
    default:
        return "Unknown type";
    }
}

static kvstore_type_t get_type(char * op)
{
    char *p_op = op;
    while (*p_op) {
        *p_op = tolower(*p_op);
        p_op++;
    }

    if (strcmp("get", op) == 0) {
        return KVSTORE_GET;
    } else if (strcmp("set", op) == 0) {
        return KVSTORE_SET;
    } else if (strcmp("exit", op) == 0) {
        return KVSTORE_EXIT;
    }

    return KVSTORE_NONE;
}

void send_commands()
{
    kvstore_cmd_t cmd;
    kvstore_ack_t ack;
    char buf[100];
    const char *delims = " \0";
    char * parsed;

    /* FIXME for now. Improve this by using a more
     * appropriate parser */
    char *op, *kv_key, *kv_val;
    //int ret;

    memset(&cmd, 0, sizeof(kvstore_cmd_t));
    memset(&ack, 0, sizeof(kvstore_ack_t));

    do {
        memset(buf, 0, sizeof(buf));

        printf("\n> ");
        fflush(stdout);
        fgets(buf, sizeof(buf), stdin);

        parsed = strdup(buf);
        op = strtok(parsed, delims);

        // get the op
        kvstore_type_t kv_type = get_type(op);
        if (kv_type == KVSTORE_NONE) {
            printf("ERROR: Invalid Operation");
            continue;
        }

        switch (kv_type) {
            case KVSTORE_EXIT: return;
            default: break;
        }

        // get the key and message
        kv_key = strtok(NULL, delims);
        if (kv_key == NULL) {
            printf("ERROR: Invalid Operation");
            continue;
        }

        // if we're just using get
        if (kv_type == KVSTORE_GET) {
            kv_val = "";
        } else {
            kv_val = strtok(NULL, "\0");
        }

        str_trim(kv_key);
        str_trim(kv_val);

        // set the code and message then encrypt
        memset(&cmd, 0, sizeof(cmd));
        cmd.type = kv_type;
        strncpy((char *)&cmd.payload.key, kv_key, KVSTORE_KEY_LEN);
        strncpy((char *)&cmd.payload.val, kv_val, KVSTORE_VAL_LEN);

        cmd.payload.key[strlen(kv_key)] = '\0';
        // copy the IV
        memcpy(cmd.iv, iv, KVSTORE_AESIV_LEN);

        aes_setkey_enc(&aes, enckey, KVSTORE_AESKEY_BITS);
        aes_crypt_cbc(&aes, AES_ENCRYPT, sizeof(cmd.payload), iv,
                (const unsigned char *)&cmd.payload,
                (unsigned char *)&cmd.payload);

        if (send_data(&pfd, &cmd, sizeof(cmd))) {
            goto exit;
        }

        if (kv_type == KVSTORE_SET) {
            // just get the acknowledgement
            // TODO check content
            if (get_ack(&pfd, &ack)) {
                goto exit;
            }
            printf("OK");
        } else if (kv_type == KVSTORE_GET) {
            // get the data
            if(get_resp(&pfd, &cmd)) {
                goto exit;
            }
            aes_setkey_dec(&aes, enckey, KVSTORE_AESKEY_BITS);
            // now decrypt
            aes_crypt_cbc(&aes, AES_DECRYPT, sizeof(cmd.payload), cmd.iv,
                (const unsigned char *)&cmd.payload,
                (unsigned char *)&cmd.payload);
            printf("%s", cmd.payload.val);
        }

        // printf("op: %s, title: %s, data: %s\n", op, kv_key, kv_msg);
    } while(1);

exit:
    printf("error\n");
}

int main() {
    // initialize our AES context
    aes_init(&aes);

    //int ret;

    if(__init()) {
        printf("  * Exiting \n");
        goto exit;
    }

    if(kvstore_dhm(pfd, &aes, enckey, KVSTORE_AESKEY_LEN)) {
        printf("\n  ! DHM failed... Exiting");
        goto exit;
    }

    // to derive the IV, we just hash the key
    // assumed safe, the key IV is updated on each encryption
    sha256(enckey, KVSTORE_AESIV_LEN, iv, 0);

    send_commands();
exit:
    aes_free(&aes);
    printf("\n");
    return 0;
}
