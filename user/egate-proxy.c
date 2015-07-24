/* Code to do I/O proxying for an enclave through a shared buffer in an
 * mmapped file. Note that any state we have is soft - each request may
 * recreate it if the proxy dies and restarts.
 */

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

void usage(char *progname)
{
	fprintf(stderr, "usage: %s filename\n", progname);
}

int main(int argc, char **argv)
{
	int fd, ret;
	egate_t e;
	echan_t *channels;
	echan_t *pchan[2]; 
	int done = 0;

	if (argc < 2) {
		usage(argv[0]);
		exit(-1);
	}
	fd = open(argv[1], O_RDWR);

	if (fd < 0) {
		perror("open");
		exit(-1);
	}
	
	channels = mmap(NULL, 2*sizeof(echan_t), PROT_READ|PROT_WRITE, MAP_SHARED,
			fd, 0);
	pchan[0] = channels;
	pchan[1] = channels + 1;

	if (!channels) {
		perror("mmap");
		exit(-1);
	}

	egate_init(&e, NULL, pchan);
	
	/* Now do the while loop that serves the buffer. */
	while (!done) {
		ecmd_t c;
		char buffer[2048];
                ret = egate_user_dequeue(&e, &c, buffer, 2048);
                if (ret) break;
                if (c.t <= ECMD_LAST_SYSTEM) {
                        // Handle predefined cmd
                        egate_user_cmd(&e, &c, buffer, 2048, &done);
                } else {
                        printf("User-specific communication from enclave: CMD %d"
			       " LEN %lu.\n", c.t, c.len);
                }
	}
}
