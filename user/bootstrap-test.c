/* Basic framework for actually starting a secure enclave with appropriate communication
 * and such so that it can actually acquire and use secrets and do useful things. */

#include <pthread.h>
#include <string.h>
#include <sgx-kern.h>
#include <sgx-user.h>
#include <sgx-utils.h>
#include <sgx-signature.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <egate.h>

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


void usage(char *progname)
{
	fprintf(stderr, "usage: %s [-l launch.sgx] [-L launch.conf] [-q quote.sgx ] [-Q quote.conf] [-K intel.key] test.sgx test.conf\n", progname);
}

void parse_options(int argc, char **argv, char **le, char **lc, 
		   char **qe, char **qc, char **ik, int *optend)
{
	*le = "bootstrap/launch-enclave.sgx"; 
	*lc = "bootstrap/launch-enclave.conf";
	*qe = "bootstrap/quoting-enclave.sgx"; 
	*qc = "bootstrap/quoting-enclave.conf";
	*ik = "user/intel.key";
	*optend = 1;
}

int save_conf(char *conf, sigstruct_t *ss, einittoken_t *token)
{
	FILE *fp = fopen(conf, "w+");
	if (!fp) return -1;
	
	/* TODO */
	return -1;
}

int create_einittoken(einittoken_t *token, sigstruct_t *ss, 
		      char *launchenc, char *launchconf)
{
	return -1;
}

int main(int argc, char **argv)
{
	char *testenc, *testconf;
	sigstruct_t testss, *tmpss;
	einittoken_t testeit, *tmpeit;
	tcs_t *testtcs;
	pthread_t ethr;
	egate_t e;
	int done;
	char *launchenc, *launchconf, *quoteenc, *quoteconf, *intelkey;
	unsigned char intel_pubkey[DEVICE_KEY_LENGTH], intel_seckey[DEVICE_KEY_LENGTH];
	int optend, ret;

	/* Parse options */ 
	parse_options(argc, argv, &launchenc, &launchconf, &quoteenc, 
		      &quoteconf, &intelkey, &optend);
	if (optend < argc + 1) {
		usage(argv[0]);
		exit(-1);
	}
	/* After options are done, get teh test enclave and configuration file */
	testenc = argv[optend];
	testconf = argv[optend + 1];

	/* Register the intel key so that we can load "intel" enclaves, and
	 * bring up the SGX "hardware" */
    	load_rsa_keys(intelkey, intel_pubkey, intel_seckey, KEY_LENGTH_BITS);
    	fprintf(stdout, "Read Intel key.\n"); fflush(stdout);
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
		ret = create_einittoken(&testeit, &testss, 
					launchenc, launchconf);
		if (ret) {
			usage(argv[0]);
			exit(-1);
		}
		ret = save_conf(testconf, &testss, &testeit);
		if (ret) {
			fprintf(stderr, "Unable to save new launch token.\n");
		} else {
			printf("Updated testconf with a launch-enclave signed EIT.\n");
		}
	}

	/* Now load and create the enclave question */
	testtcs = create_elf_enclave(testenc, &testss, &testeit);

	/* Create a gate to run and communicate with the test enclave */
	egate_init(&e, testtcs, 1);

	/* Once it's up, we run it launch it *in its own thread* and then
	 * talk with it asynchronously so that we're not always enter/exiting
	 * it. */
	pthread_create(&ethr, NULL, egate_thread, &e);
	
	done = 0;
	while (!done) {
		int buffer[2048];
		ecmd_t c;
		int ret;
		ret = egate_dequeue(&e, &c, buffer, 2048, ECHAN_FROMENCLAVE); 
		if (!ret) break;
		if (c.t <= ECMD_LAST_SYSTEM) {
			// Handle predefined cmd
			egate_handle_cmd(&e, &c, buffer, 2048, &done); 
		} else {
			printf("User-specific communication from enclave %d.\n",
				c.t);
		}
	}

	pthread_join(ethr, NULL);
	return 0;
}
