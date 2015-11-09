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

#include <sgx.h>

#include "kvstore.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT 11988
#define PLAINTEXT "==Hello there!=="

#define WAIT_TIME 2

int pfd = -1;

char *data[] = {
    "CS0441", "DISCRETE STRUCTURES FOR COMPUTER SCIENCE",
    "CS0445", "DATA STRUCTURES",
    "CS0401", "INTERMEDIATE PROGRAMMING USING JAVA",
    "CS1501", "ALGORITHM IMPLEMENTATION",
    "CS1502", "FORMAL METHODS IN COMPUTER SCIENCE",
    "CS2210", "COMPILER DESIGN",
    "CS2750", "MACHINE LEARNING",
    "CS3550", "ADVANCED TOPICS IN MANAGEMENT OF DATA",
    NULL
};

static int __init()
{
    int ret;

    printf("   .  Connecting to secure kvstore server\n");

    if ( (ret = net_connect(&pfd, SERVER_NAME, SERVER_PORT)) ) {
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

    if ( ( ret = net_recv(cfd, cmd, size) ) != size ) { 
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
    printf("\n  . Sending data... ");
    if ( ( ret = net_send(cfd, (unsigned char *)cmd, size) ) != size ) { 
        printf("FAILED net_send (%d)", ret);
        return -1;
    }
    printf("OK");

    return 0;
}

int main() {
    kvstore_cmd_t kvstore;
    kvstore_ack_t kvack;
    int i = 0, x;
    char *code, *title;
    char **str = data;
    //int ret;

    if (__init()) {
        printf("  * Exiting \n");
        goto exit;
    }

    while (*str) {
        code = *str++;
        title = *str++;
        i++;

        memset(&kvstore, 0, sizeof(kvstore));
        kvstore.type = KVSTORE_SET;
        memcpy(kvstore.key, code, strlen(code));
        memcpy(kvstore.msg, title, strlen(title));
        if (send_data(&pfd, &kvstore, sizeof(kvstore))) {
            goto exit;
        }

        if (get_ack(&pfd, &kvack)) {
            goto exit;
        }
        printf(" ACK");
    }

    printf("\n.  Sent %d items", i);

    srand(time(NULL));

    for (x = 0; x < i; x++) {
        // let's retrieve the data
        memset(&kvstore, 0, sizeof(kvstore));
        kvstore.type = KVSTORE_GET;
        code = data[x << 1];
        memcpy(kvstore.key, code, strlen(code));

        if (send_data(&pfd, &kvstore, sizeof(kvstore))) {
            goto exit;
        }
        if (get_resp(&pfd, &kvstore)) {
            goto exit;
        }

        printf("\n  + %s -> %s\n", kvstore.key, kvstore.msg);
    }

exit:
    return 0;
}
