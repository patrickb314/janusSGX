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
#include <sys/types.h>
#include <sys/socket.h>

#include <egate.h>

ENCCALL1(enclave_main, egate_t *)

tcs_t *create_elf_enclave(char *enc, sigstruct_t *ss, einittoken_t *ei)
{
	size_t npages;
	void *entry;
	void* pages = load_elf_enclave(enc, &npages, &entry);
	int keid;
	keid_t stat;

        keid = create_enclave(entry, pages, npages, ss, ei);

        if (syscall_stat_enclave(keid, &stat) < 0)
                err(1, "failed to stat enclave");

    	return stat.tcs;
}

struct option options[] = {
	{"key"       , required_argument, 0, 'k'},
	{"launch"    , required_argument, 0, 'l'},
	{"launchconf", required_argument, 0, 'L'},
	{"quote"     , required_argument, 0, 'q'},
	{"quoteconf" , required_argument, 0, 'Q'},
	{0, 0, 0, 0}
};

void usage(char *progname)
{
	fprintf(stderr, "usage: %s [-l launch.sgx] [-L launch.conf] [-q quote.sgx ] [-Q quote.conf] [-k intel.key] test.sgx test.conf\n", progname);
}

void parse_options(int argc, char **argv, char **le, char **lc, 
		   char **qe, char **qc, char **ik, int *optend)
{
	int optind = 0;
	*le = "bootstrap/launch-enclave.sgx"; 
	*lc = "bootstrap/launch-enclave.conf";
	*qe = "bootstrap/quoting-enclave.sgx"; 
	*qc = "bootstrap/quoting-enclave.conf";
	*ik = "conf/intel.key";

	while (1) {
        	char c = getopt_long(argc, argv, "k:hp:m:s:M:S:E:r:c:Q:", 
				     options, &optind);
        	if (c == -1)
            		break;

        	switch (c) {
		case 'k':
			*ik = optarg;
			break;
		case 'l':
			*le = optarg;
			break;
		case 'L':
			*lc = optarg;
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

int save_conf(char *conf, sigstruct_t *ss, einittoken_t *token)
{
	FILE *fp = fopen(conf, "a");
	if (!fp) return -1;

	/* Save the inittoken */
	char *s = dbg_dump_einittoken(token);
	fprintf(fp, "# EINITTOKEN START\n");
	fprintf(fp, "%s\n", s);
	fprintf(fp, "# EINITTOKEN END\n");
	free(s);
	fclose(fp);

	return 0;
}

ENCCALL1(sign_einittoken, einittoken_t *)

int create_einittoken(einittoken_t *token, sigstruct_t *ss, char *conf,
		      char *launchenc, char *launchconf)
{
	FILE *fp = fopen(conf, "a");
	if (!fp) return -1;
	sigstruct_t *launchss;
	einittoken_t *launcheit;
	tcs_t *launchtcs;

	/* Initialize the token */
	init_einittoken(token, ss, false);

	/* Load a launch enclave and sign the token */
        launchss = load_sigstruct(launchconf);
        launcheit = load_einittoken(launchconf);
	launchtcs = create_elf_enclave(launchenc, launchss, launcheit);

	sign_einittoken(launchtcs, exception_handler, token);

	return 0;
}

int main(int argc, char **argv)
{
	char *testenc, *testconf;
	sigstruct_t testss __attribute__((aligned(PAGE_SIZE))), *tmpss;
	einittoken_t testeit __attribute__((aligned(EINITTOKEN_ALIGN_SIZE))), *tmpeit;
	tcs_t *testtcs;
	egate_t e;
	int done;
	char *launchenc, *launchconf, *quoteenc, *quoteconf, *intelkey;
	unsigned char intel_pubkey[KEY_LENGTH], intel_seckey[KEY_LENGTH];
	int optend, ret;

	/* Parse options */ 
	parse_options(argc, argv, &launchenc, &launchconf, &quoteenc, 
		      &quoteconf, &intelkey, &optend);
	if (optend > argc) {
		usage(argv[0]);
		exit(-1);
	}
	/* After options are done, get teh test enclave and configuration file */
	testenc = argv[optend];
	testconf = argv[optend + 1];

	/* Register the intel key so that we can load "intel" enclaves, and
	 * bring up the SGX "hardware" */
    	load_rsa_keys(intelkey, intel_pubkey, intel_seckey, KEY_LENGTH_BITS);
    	sys_sgx_init(intel_pubkey);

	/* Get the sigstruct for the test enclave and see if we have an 
	 * inittoken, too */
	tmpss =  load_sigstruct(testconf);
	if (!tmpss) {
		usage(argv[0]);
		exit(-1);
	}
	testss = *tmpss;
	free(tmpss);

	tmpeit = load_einittoken(testconf);
	if (tmpeit) {
		testeit = *tmpeit;
		free(tmpeit);
	} else {
    		fprintf(stdout, "Creating new einittoken %s/%s.\n",
			launchenc, launchconf); fflush(stdout);
		ret = create_einittoken(&testeit, &testss, testconf,
					launchenc, launchconf);
		if (ret) {
			usage(argv[0]);
			exit(-1);
		}
		ret = save_conf(testconf, &testss, &testeit);
		if (ret) {
			fprintf(stderr, "Unable to save new launch token.\n");
		} else {
			printf("Updated %s with a launch-enclave signed EIT.\n", testconf);
		}
	}

	/* Now load and create the enclave question */
	testtcs = create_elf_enclave(testenc, &testss, &testeit);

	/* Create a gate to run and communicate with the test enclave */
	egate_init(&e, testtcs);
	done = 0;
	while (!done) {
		int buffer[2048];
		ecmd_t c;
		int ret;

		enclave_main(e.tcs, exception_handler, &e);

		/* When we leave the enclave, see what, if anything, it wants
		 * us to do */
		ret = egate_user_dequeue(&e, &c, buffer, 2048); 
		if (ret) break;
		if (c.t <= ECMD_LAST_SYSTEM) {
			// Handle predefined cmd
			egate_user_cmd(&e, &c, buffer, 2048, &done); 
		} else {
			printf("User-specific communication from enclave %d.\n",
				c.t);
		}
	}

	return 0;
}
