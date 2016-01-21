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
#include <sys/mman.h>
#include <pthread.h>

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/pk.h"
#include "polarssl/rsa.h"
#include "polarssl/sha256.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include "libut/include/uthash.h"
#include "libut/include/utlist.h"

#include "kvserver.h"
#include "kvstore.h"

#include <egate.h>
#define GDB_DEBUG 1
#define SERVER_PORT 11988

ENCCALL3(enclave_main, egate_t *, kvenclave_ops_t, void *)
void * handler(void * client_fd);
void handle_file(unsigned char * name, size_t id, int load);

egate_t egate;

typedef struct {
    int id;
    unsigned char fname[KVSERVER_HASH_SIZE + 1];
    UT_hash_handle hh;
} client_files_t;

client_files_t * clients = NULL;

void usage(char *progname)
{
	fprintf(stderr, "usage: %s test.sgx [test.conf]\n", progname);
}

int listen_command(int *cfd)
{
    int ret, id;
    kvstore_cmd_t cmd;
    kvstore_ack_t ack;

    client_files_t * ctx = NULL;

    printf("\n  .  Listening for commands");
    fflush(stdout);

    while(1) {
        memset(&cmd, 0, sizeof(cmd));
        ret = net_recv(cfd, (unsigned char *)&cmd, sizeof(cmd));

        if (ret != sizeof(cmd)) {
            id = *cfd;
            /* save the client data */
            HASH_FIND_INT(clients, &id, ctx);
            printf("\n . Client (%d) issues exit commmand", id);

            if (ctx == NULL) {
                printf("\n*** client file not found... bye ***");
                ret = 0;
                goto exit;
            }

            handle_file(ctx->fname, ctx->id, 0);
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

        print_bytes("IV: ", cmd.iv, 5);
        print_bytes(" KEY: ", cmd.payload.key, 5);
        print_bytes(" VAL: ", cmd.payload.val, 5);
        fflush(stdout);

        // TODO this is suppose to be set by the client
        // using the socket number for now
        cmd.sess_id = (unsigned char)(*cfd);

        // now let's send a command to the enclave
        // TODO read return value to set ACK struct
        enclave_main(egate.tcs, exception_handler, &egate, KVENCLAVE_STORE_OP, &cmd);
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
    /* memory map the region and write to file */
    return ret;
}

/*
 * Communicates with enclave in solving the DHM
 */
static int __dhm(int *cfd)
{
    int ret, buflen, dhmlen, filesize, len;
    unsigned char buf1[KVSERVER_BUF_SIZE], buf2[2], pubkey[KVSERVER_BUF_SIZE]={0};
    char * client_name;
    kvenclave_dhm_t dhm_t;
    char inputfile[50];
    FILE * f;

    memset(&dhm_t, 0, sizeof(dhm_t));
    dhm_t.cfd = *cfd;
    dhm_t.buf1 = buf1;
    dhm_t.buf2 = buf2;

    enclave_main(egate.tcs, exception_handler, &egate, KVENCLAVE_DHM_OP, &dhm_t);
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

    /* stage 2 */
    printf("\n . Getting client's DHM and public key parameters");
    fflush(stdout);
    if ( ( ret = net_recv( cfd, buf2, 2 ) ) != 2) {
        printf(" failed\n ! net_recv (ret=%d, dhmlen=%d) \n\n", ret, dhmlen);
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
        printf(" FAILED\n ! net_recv (%d, %d) \n\n", ret, buflen);
        goto exit;
    }

    client_name = (char *)(buf1 + 2 + dhmlen);
    len = buflen - ((buf1[0] << 8) | buf1[1]) - dhmlen - 2 - 1;
    if (len != strlen(client_name)) {
        printf(" FAILED\n ! corrupted buffer (len=%zu)", strlen(client_name));
        goto exit;
    }

    printf("\n . Connecting [%s]...", client_name);
    snprintf(inputfile, 50, "keys/%s_pub.sig.txt", client_name);

    f = fopen(inputfile, "rb");
    if (f == NULL) {
        printf(" FAILED\n ! Public file (%s) not found", inputfile);
        ret = 1;
        goto exit;
    }

    // read the client's public key
    filesize = fread(pubkey, sizeof(char), KVSERVER_PUBKEY_SIZE, f);
    if (filesize == 0) {
        printf(" FAILED\n ! public file not found");
        ret = 1;
        goto exit;
    }

    dhm_t.pubkey = pubkey;
    dhm_t.pubkeysize = filesize;

    enclave_main(egate.tcs, exception_handler, &egate, KVENCLAVE_DHM_OP, &dhm_t);
    if (dhm_t.status) {
        printf(" FAILED\n ! enclave_main returned an error \n\n");
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

    /* instantiate the client */
    client_files_t * cf = malloc(sizeof(client_files_t));
    if (cf == NULL) {
        printf(" FAILED\n ! No memory for client context");
    }

    memcpy(cf->fname, client_name, strlen(client_name));
    cf->id = *cfd;
    HASH_ADD_INT(clients, id, cf);
    // load the file into the enclave
    handle_file(cf->fname, cf->id, 1);
    ret = 0;
exit:
    return ret;
}

/**
 * Loads/saves the users file
 * @param name is the user's name
 *
 */
void handle_file(unsigned char * client_name, size_t id, int load) {
    FILE * cfile;
    void * cfile_data;
    kvenclave_fileop_t fileop;
    char filename[50];

    snprintf(filename, 50, "store/%s", client_name);

    if (load) {
        cfile = fopen(filename, "r");
    } else {
        cfile = fopen(filename, "w+");
    }

    if (cfile == NULL) {
        printf("\n*** FILE could not be opened ***");
        goto exit;
    }

    cfile_data = malloc(MAX_CLIENT_FILE_SIZE);
    if (cfile_data == NULL) {
        printf("\n*** Could not allocate memory ***");
        goto exit;
    }

    fileop.load = load;
    fileop.sess_id = id;
    fileop.data = cfile_data;

    if (load) {
        fileop.size = fread(fileop.data, 1, MAX_CLIENT_FILE_SIZE, cfile);

        enclave_main(egate.tcs, exception_handler, &egate,
                KVENCLAVE_FILE_OP, &fileop);
    } else {
        enclave_main(egate.tcs, exception_handler, &egate,
                KVENCLAVE_FILE_OP, &fileop);

        fwrite(fileop.data, 1, MAX_CLIENT_FILE_SIZE, cfile);
    }

exit:
    fflush(stdout);
}

void * handler(void *client_fd) {
    int cfd = *((int *)client_fd);

    fprintf(stdout, "\n . Setting up DHM in enclave (%d)", cfd);

    if(__dhm(&cfd)) {
        printf("FAILURE: DHM with client (%d) failed", cfd);
        goto exit;
    }

    fflush(stdout);
    listen_command(&cfd);
exit:
    return (void *)1;
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
    int ret;

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

	egate_user_init(&egate, testtcs, pchan);
	fprintf(stdout, "Start egate-proxy for file %s \n", tmpname);
	fflush(stdout);


    // bind the connection
    if ( ( ret = net_bind( &listen_fd, NULL, SERVER_PORT ) ) != 0 ) {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    printf( "\n  . Waiting for a remote connections" );
    fflush( stdout );


    {
        ret = net_accept( listen_fd, &client_fd, NULL );

        if (ret) {
            printf( " failed\n ! net_accept returned %d\n\n", ret );
            goto exit;
        }

        printf("\n ^ New connection");

        handler(&client_fd);
        /*
        pthread_t thread;

        if (pthread_create(&thread, NULL, handler, &client_fd) != 0) {
            perror("Could not create thread");
            return 1;
        }

        //pthread_join(thread, NULL);
        */
    }

exit:
    printf("\n");

	return 0;
}
