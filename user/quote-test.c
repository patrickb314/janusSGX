#include <string.h>
#include <sgx-kern.h>
#include <sgx-user.h>
#include <sgx-utils.h>
#include <sgx-signature.h>
#include <sys/types.h>
#include <sys/socket.h>

#define is_aligned(addr, bytes) \
     ((((uintptr_t)(const void *)(addr)) & (bytes - 1)) == 0)

void enclave_start();

ENCCALL2(request_quote, report_t *, quote_t *)
ENCCALL3(request_report, targetinfo_t *, unsigned char *, report_t *)


tcs_t *create_elf_enclave(char *enc, char *conf)
{
	size_t npages;
	void *entry;
	void* pages = load_elf_enclave(enc, &npages, &entry);
	int keid;
	keid_t stat;

        keid = create_enclave_conf(entry, pages, npages, conf);

        if (syscall_stat_enclave(keid, &stat) < 0)
                err(1, "failed to stat enclave");

    	return stat.tcs;
}


void usage(char *progname)
{
	fprintf(stderr, "usage: %s test.sgx test.conf quote.sgx quote.conf intel.key\n", progname);
}

int main(int argc, char **argv)
{
	tcs_t *test_tcs, *quote_tcs;
	char *ikey, *testenc, *testconf, *quoteenc, *quoteconf;
	sigstruct_t *quotesig;
	targetinfo_t t;
	report_t r;
	quote_t q;
	unsigned char nonce[64];
    	unsigned char intel_pubkey[KEY_LENGTH];
    	unsigned char intel_seckey[KEY_LENGTH];

	if (argc < 6) {
		usage(argv[0]);
		exit(-1);
    	} else {
		testenc = argv[1];
		testconf = argv[2];
		quoteenc = argv[3];
		quoteconf = argv[4];
		ikey = argv[5];
	}
	

	/* Use the device key as the intel key for now. Set the intel
	 * key for the hardware to whatever we claim it should be. */
	load_rsa_keys(ikey, intel_pubkey, intel_seckey, KEY_LENGTH_BITS);
	fprintf(stdout, "Read Intel key.\n"); fflush(stdout);
 
	sys_sgx_init(intel_pubkey);
	fprintf(stdout, "Inited SGX.\n"); fflush(stdout);

	quote_tcs = create_elf_enclave(quoteenc, quoteconf);
	if (!quote_tcs) {
		fprintf(stdout, "Unable to create quoting enclave.\n"); 
		fflush(stdout);
		exit(-1);
	} else {
		fprintf(stdout, "Created quoting enclave.\n"); fflush(stdout);
	}

	test_tcs = create_elf_enclave(testenc, testconf);
	if (!test_tcs) {
		fprintf(stdout, "Unable to create test enclave.\n"); 
		fflush(stdout);
		exit(-1);
	} else {
		fprintf(stdout, "Created test enclave.\n"); fflush(stdout);
	}

	/* Now generate a targetinfo for the quoting enclave */
	quotesig = load_sigstruct(quoteconf); //XXX change interface to create
					      //enclave to return this!
	memset(&t, 0, sizeof(targetinfo_t));
	memcpy(&t.measurement, &quotesig->enclaveHash, 32);
	memset(nonce, 0x3b, 64);
	t.attributes = quotesig->attributes;
	t.miscselect = quotesig->miscselect;

	memset(&r, 1, sizeof(report_t));

	fprintf(stdout, "Created report request.\n"); fflush(stdout);
	fprintf(stdout, "Requesting report.\n"); fflush(stdout);

	/* And get the report */
	request_report(test_tcs, exception_handler,
		       &t, nonce, &r);

	fprintf(stdout, "Requesting quote.\n"); fflush(stdout);
	/* Now get a quote from the report */
	request_quote(quote_tcs, exception_handler,
		      &r, &q);

	/* And print out the results */
	char *rep;
	rep = dbg_dump_ereport(&q.report);
	char *sig = fmt_bytes(q.sig, sizeof(rsa_sig_t));
	fprintf(stdout, "Quoted report from test enclave: %s\n", 
		rep);
	fprintf(stdout, "RSA SIGNATURE:       %s\n", sig);
	free(rep);
	free(sig);
 
	return 0;
}
