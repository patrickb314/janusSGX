/* Code to do I/O proxying for an enclave through a shared buffer in an
 * mmapped file. Note that any state we have is soft - each request may
 * recreate it if the proxy dies and restarts.
 */

#include <getopt.h>
#include <string.h>
#include <sgx-kern.h>
#include <sgx-user.h>
#include <sgx-utils.h>
#include <sgx-signature.h>
#include <egate.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

struct option options[] = {
        {"key"       , required_argument, 0, 'k'},
        {"quote"     , required_argument, 0, 'q'},
        {"quoteconf" , required_argument, 0, 'Q'},
        {0, 0, 0, 0}
};

void usage(char *progname)
{
	fprintf(stderr, "usage: %s [-q quote.sgx ] [-Q quote.conf] [-k intel.key] filename\n", progname);
}

void parse_options(int argc, char **argv, char **qe, char **qc, char **ik,
                   int *optend)
{
        int optind = 0;
        *qe = "bootstrap/quoting-enclave.sgx";
        *qc = "bootstrap/quoting-enclave.conf";
        *ik = "conf/intel.key";

        while (1) {
                char c = getopt_long(argc, argv, "k:q:Q:",
                                     options, &optind);
                if (c == -1)
                        break;

                switch (c) {
                case 'k':
                        *ik = optarg;
                        break;
                case 'q':
                        *qe = optarg;
                        break;
                case 'Q':
                        *qc = optarg;
                        break;
                }
        }
        if (optend) *optend = optind + 1;
        return;
}

int main(int argc, char **argv)
{
	int fd, ret;
	egate_t e;
	echan_t *channels;
	echan_t *pchan[2]; 
	int done = 0;
	char *quoteenc, *quoteconf, *intelkey;
        unsigned char intel_pubkey[KEY_LENGTH], intel_seckey[KEY_LENGTH];
        int optend;
	tcs_t *quotetcs;
	sigstruct_t *quotess;

        /* Parse options */
        parse_options(argc, argv, &quoteenc, &quoteconf, &intelkey, &optend);
        if (optend > argc - 1) {
                usage(argv[0]);
                exit(-1);
        }
        /* After options are done, get teh test enclave and configuration file */
	fd = open(argv[1], O_RDWR);

	if (fd < 0) {
		perror("open");
		exit(-1);
	}
	
	load_rsa_keys(intelkey, intel_pubkey, intel_seckey, KEY_LENGTH_BITS);
        sys_sgx_init(intel_pubkey);

	channels = mmap(NULL, 2*sizeof(echan_t), PROT_READ|PROT_WRITE, MAP_SHARED,
			fd, 0);
	pchan[0] = channels;
	pchan[1] = channels + 1;

        quotetcs = create_elf_enclave_conf(quoteenc, quoteconf, &quotess, 1);
        if (!quotetcs) {
                fprintf(stdout, "Unable to create quoting enclave.\n");
                fflush(stdout);
                exit(-1);
        } else {
                fprintf(stdout, "Created quoting enclave.\n"); fflush(stdout);
        }

	if (!channels) {
		perror("mmap");
		exit(-1);
	}

	egate_proxy_init(&e, quotetcs, quotess, pchan);
	
	fprintf(stdout, "Proxy reading commands.\n");
	/* Now do the while loop that serves the buffer. */
	while (!done) {
		ecmd_t c;
		char buffer[2048];
                ret = egate_user_poll(&e, &c, buffer, 2048);
                if (ret) break;
                if (c.t <= ECMD_LAST_SYSTEM) {
                        // Handle predefined cmd
                        printf("Handling communication from enclave: CMD %d"
			       " LEN %lu.\n", c.t, c.len);
                        egate_user_cmd(&e, &c, buffer, 2048, &done);
                } else {
                        printf("User-specific communication from enclave: CMD %d"
			       " LEN %lu.\n", c.t, c.len);
                }
	}
	fprintf(stdout, "Proxy shutting down.\n");
}
