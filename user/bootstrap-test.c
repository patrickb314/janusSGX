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

#include <egate.h>

ENCCALL1(enclave_main, egate_t *)

void usage(char *progname)
{
	fprintf(stderr, "usage: %s test.sgx test.conf\n", progname);
}

int main(int argc, char **argv)
{
	char *testenc, *testconf, tmpname[64];
	sigstruct_t testss __attribute__((aligned(PAGE_SIZE))), *tmpss;
	einittoken_t testeit __attribute__((aligned(EINITTOKEN_ALIGN_SIZE))), *tmpeit;
	tcs_t *testtcs;
	egate_t e;
	echan_t *pchan[2];
	int fd;
	echan_t *channels;
	int zero;
	int optend, ret;

	/* Parse options */ 
	if (argc != 3) {
		usage(argv[0]);
		exit(-1);
	}
	/* After options are done, get teh test enclave and configuration file */
	testenc = argv[1];
	testconf = argv[2];

    	sys_sgx_init(NULL);

	/* Now load and create the enclave question */
	testtcs = create_elf_enclave_conf(testenc, testconf, NULL, 0);

	/* Create a gate to run and communicate with the test enclave */
	strcpy(tmpname, "/tmp/echan.XXXXXX");
	fd = mkstemp(tmpname);
	lseek(fd, 2*sizeof(echan_t), SEEK_SET);
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
	enclave_main(e.tcs, exception_handler, &e);
	
	return 0;
}
