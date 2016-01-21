#include <stdio.h>

#include "polarssl/net.h"

#include "kvserver.h"
#include "kvstore.h"

int respond(int *cfd, unsigned char * cmd, size_t size)
{
    int ret;
    printf("      <-- Sending response to client... ");
    if ( ( ret = net_send(cfd, cmd, size) ) != size ) {
        printf("FAILED net_send (%d)", ret);
        return -1;
    }
    printf("OK");

    return 0;
}

int send_ack(int *cfd, kvstore_ack_t *ack)
{
    return respond(cfd, (unsigned char *)ack, sizeof(kvstore_ack_t));
}

int send_resp(int *cfd, kvstore_cmd_t *cmd)
{
    return respond(cfd, (unsigned char *)cmd, sizeof(kvstore_cmd_t));
}

void print_bytes(char * pre, void * ptr, int size)
{
    int i = 0;
    printf("%s", pre);
    for (; i < size; i++) {
        printf("%02x", *((unsigned char *)ptr + i));
    }
}

