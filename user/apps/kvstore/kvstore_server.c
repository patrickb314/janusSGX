/* Basic framework for actually starting a secure enclave with appropriate
 * communication. Really we'd like to run the enclave in a separate thread,
 * but qemu doesn't support that right now in user-level emulation.
 */
#include <getopt.h>
#include <string.h>
#include <sgx-kern.h>
#include <sgx-user.h>
#include <sgx-utils.h>
#include <sgx-signature.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/pk.h"
#include "polarssl/rsa.h"
#include "polarssl/sha256.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include "kvserver.h"
#include "kvstore.h"

#include <egate.h>
#define GDB_DEBUG 1
#define SERVER_PORT 11988

ENCCALL3(enclave_main, egate_t *, kvenclave_ops_t, void *)

egate_t e;


void usage(char *progname)
{
	fprintf(stderr, "usage: %s test.sgx [test.conf]\n", progname);
}


int setup_connection(int *lfd, int *cfd) {
    int ret;

    printf( "\n  . Waiting for a remote connection" );
    fflush( stdout );

    if( ( ret = net_bind( lfd, NULL, SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = net_accept( *lfd, cfd, NULL ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }

exit:
    return ret;
}

static int respond(int *cfd, unsigned char * cmd, size_t size)
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

static inline int send_ack(int *cfd, kvstore_ack_t *ack)
{
    return respond(cfd, (unsigned char *)ack, sizeof(kvstore_ack_t));
}

static inline int send_resp(int *cfd, kvstore_cmd_t *cmd)
{
    return respond(cfd, (unsigned char *)cmd, sizeof(kvstore_cmd_t));
}

void print_byte(char * pre, void * ptr, int size)
{
    int i = 0;
    printf("%s", pre);
    for (; i < size; i++) {
        printf("%02x", *((unsigned char *)ptr + i));
    }
}

int listen_command(int *cfd)
{
    int ret;
    kvstore_cmd_t cmd;
    kvstore_ack_t ack;
    printf("\n  .  Listening for commands");
    fflush(stdout);

    while(1) {
        memset(&cmd, 0, sizeof(cmd));
        ret = net_recv(cfd, (unsigned char *)&cmd, sizeof(cmd));
        if (ret != sizeof(cmd)) {
            printf ("\n*** net_recv(%d)... shutdown ***", ret);
            goto exit;
        }

        switch(cmd.type) {
        case KVSTORE_GET:
            printf("\n      --> GET CMD... ");
            break;
        case KVSTORE_SET:
            printf("\n      --> SET CMD... ");
            break;
        default:
            printf("\n   *** UNKNOWN CMD (%d) ***", cmd.type);
            // TODO change this
            ret = -1;
            goto exit;
        }

        print_byte("IV: ", cmd.iv, 5);
        print_byte(" KEY: ", cmd.payload.key, 5);
        print_byte(" VAL: ", cmd.payload.val, 5);
        fflush(stdout);
        // TODO this is suppose to be set by the client
        // using the socket number for now
        cmd.sess_id = (unsigned char)(*cfd);

        // now let's send a command to the enclave
        // TODO read return value to set ACK struct
        enclave_main(e.tcs, exception_handler, &e, KVENCLAVE_STORE_OP, &cmd);
        printf(" OK \n");
        //printf("Return from enclave_main %d\n", eret);

        // post processing
        switch (cmd.type) {
        case KVSTORE_GET:
            send_resp(cfd, &cmd);
            break;
        case KVSTORE_SET:
            ack.code = STATUS_OK; // TODO change this later
            send_ack(cfd, &ack);
            break;
        default: printf("\n  *** Illegal option ***");;
        }
    }
exit:
    return ret;
}

/*
 * Communicates with enclave in solving the DHM
 */
static int __dhm(int *cfd)
{
    int ret, buflen, dhmlen;
    unsigned char buf1[KVSERVER_BUF_SIZE];
    unsigned char buf2[2];
    kvenclave_dhm_t dhm_t;

    memset(&dhm_t, 0, sizeof(dhm_t));
    dhm_t.cfd = *cfd;
    dhm_t.buf1 = buf1;
    dhm_t.buf2 = buf2;

    enclave_main(e.tcs, exception_handler, &e, KVENCLAVE_DHM_OP, &dhm_t);
    if (dhm_t.status) {
        printf("! enclave_main returned an error \n\n");
        ret = dhm_t.status;
        goto exit;
    }

    buflen = (buf2[0] << 8) | buf2[1];
    dhmlen = dhm_t.dhmlen;

    /* first send operation, this is the size of the DH params */
    printf("\n . Sending size of dhm params (%hx, %hx)", buf2[0], buf2[1]);
    if ( ( ret = net_send( cfd, buf2, 2 ) ) != 2 ) {
        printf(" FAILED\n ! net_send returned %d, %d\n\n", ret, *cfd);
        goto exit;
    }

    /* this is a dummy wait operation to avoid successive packet sent */
    if ( ( ret = net_recv( cfd, buf2, 1) ) != 1 ) {
        printf(" FAILED\n ! dummy net_recv returned%d\n\n", ret);
        goto exit;
    }

    printf("\n . Sending DHM and signature ");
    if ( ( ret = net_send( cfd, buf1, buflen ) != (int) buflen ) ) {
        printf(" failed\n ! net_send returned %d\n\n", ret );
        goto exit;
    }

    printf("\n . Waiting for client's public value ");
    if ( ( ret = net_recv( cfd, buf1, dhmlen ) ) != dhmlen) {
        printf(" failed\n ! net_recv (%d, %d) \n\n", ret, dhmlen);
        goto exit;
    }

    printf("\n . Deriving shared secret");
    enclave_main(e.tcs, exception_handler, &e, KVENCLAVE_DHM_OP, &dhm_t);
    if (dhm_t.status) {
        printf("! enclave_main returned an error \n\n");
        ret = dhm_t.status;
        goto exit;
    }

    // stage 3
    printf("\n . Getting client's public key parameters");
    fflush(stdout);
    if ( ( ret = net_recv( cfd, buf2, 2 ) ) != 2) {
        printf(" failed\n ! net_recv (%d, %d) \n\n", ret, dhmlen);
        goto exit;
    }

    // compute the buflen
    buflen = (buf2[0] << 8) | buf2[1];
    if (buflen < 1 || buflen > KVSERVER_BUF_SIZE) {
        ret = 1;
        printf(" FAILED\n ! Got invalid buffer length (%d)\n\n", buflen);
        goto exit;
    }

    if ( ( ret = net_send( cfd, buf2, 1) ) != 1 ) {
        printf(" FAILED\n ! dummy net_recv returned%d\n\n", ret);
        goto exit;
    }

    if ( ( ret = net_recv( cfd, buf1, buflen ) ) != buflen) {
        printf(" failed\n ! net_recv (%d, %d) \n\n", ret, buflen);
        goto exit;
    }

    enclave_main(e.tcs, exception_handler, &e, KVENCLAVE_DHM_OP, &dhm_t);
    if (dhm_t.status) {
        printf("! enclave_main returned an error \n\n");
        ret = dhm_t.status;
        goto exit;
    }

    /* TODO: change this to enclave generated session id */
    buf2[0] = 1;

    printf("\n . Sending confirmation to client for login\n");
    if ( ( ret = net_send( cfd, buf2, 1) ) != 1 ) {
        printf(" FAILED\n ! dummy net_recv returned%d\n\n", ret);
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int main(int argc, char **argv)
{
	char *testenc, *testconf = NULL, tmpname[64];
	tcs_t *testtcs;
	echan_t *pchan[2];
	int fd;
	echan_t *channels;
	int zero;

    int listen_fd;
    int client_fd;
    //int ret;

	/* Parse options */
	if (argc < 2) {
		usage(argv[0]);
		exit(-1);
	}
	/* After options are done, get the test enclave and configuration file */
	testenc = argv[1];
	if (argc == 3) {
		testconf = argv[2];
	}

    sys_sgx_init(NULL);

	/* Now load and create the enclave question */
	testtcs = create_elf_enclave_conf(testenc, testconf, NULL, GDB_DEBUG);

	/* Create a gate to run and communicate with the test enclave */
	strcpy(tmpname, "/tmp/echan.XXXXXX");
	fd = mkstemp(tmpname);
	lseek(fd, 2*sizeof(echan_t) - sizeof(zero), SEEK_SET);
	write(fd, &zero, sizeof(zero));
	if (fd < 0) {
		perror("mkstemp");
		exit(-1);
	}

	channels = mmap(NULL, 2*sizeof(echan_t), PROT_READ|PROT_WRITE, MAP_SHARED,
			fd, 0);
	if (!channels) {
		perror("mmap");
		exit(-1);
	}
	close(fd);
	pchan[0] = channels;
	echan_init(pchan[0]);
	pchan[1] = channels + 1;
	echan_init(pchan[1]);

	egate_user_init(&e, testtcs, pchan);
	fprintf(stdout, "Start egate-proxy for file %s \n", tmpname);
	fflush(stdout);

	// enclave_main(e.tcs, exception_handler, &e);

    if (setup_connection(&listen_fd, &client_fd)) {
        goto exit;
    }


    fprintf(stdout, "\n . Setting up DHM in enclave (%d)", client_fd);
    fflush(stdout);


    if(__dhm(&client_fd)) {
        printf("\n FAILURE: DHM with client failed");
        goto exit;
    }

    listen_command(&client_fd);

exit:
    printf("\n");

	return 0;
}
