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

ENCCALL1(sign_einittoken, einittoken_t *)

extern void *ENCT_START, *ENCT_END, *ENCD_START, *ENCD_END;

tcs_t *create_launch_enclave(char *myconf)
{
    //XXX n_of_pages should be set properly
    //n_of_pages = n_of_enc_code + n_of_enc_data
    //improper setting of n_of_pages could contaminate other EPC area
    //e.g. if n_of_pages mistakenly doesn't consider enc_data section,
    //memory write access to enc_data section could make write access on other EPC page.
    int keid;
    keid_t stat; 
    void *codes = (void *)(uintptr_t)&ENCT_START;
    unsigned long ecode_size = (unsigned long)&ENCT_END - (unsigned long)&ENCT_START;
    unsigned long edata_size = (unsigned long)&ENCD_END - (unsigned long)&ENCD_START;
    unsigned long ecode_page_n = ((ecode_size - 1) / PAGE_SIZE) + 1;
    unsigned long edata_page_n = ((edata_size - 1) / PAGE_SIZE) + 1;
    unsigned long n_of_pages = ecode_page_n + edata_page_n;

    assert(is_aligned((uintptr_t)codes, PAGE_SIZE));

    /* Need to pass extra arguments here to make an intel enclave */
    keid = create_enclave((void *)(unsigned long)enclave_start, codes,
			  n_of_pages, myconf);
    if (syscall_stat_enclave(keid, &stat) < 0)
        err(1, "failed to stat enclave");
    return stat.tcs;
}

void usage(char *progname)
{
	fprintf(stderr, "usage: %s my.conf intel.key sign.conf\n", progname);
}

int main(int argc, char **argv)
{
    tcs_t *tcs;
    einittoken_t *token;
    char *key, *myconf, *signconf;

    unsigned char intel_pubkey[KEY_LENGTH];
    unsigned char intel_seckey[KEY_LENGTH];

    if (argc < 4) {
	usage(argv[0]);
	exit(-1);
    } else {
	myconf = argv[1];
	key = argv[2];
	signconf = argv[3];
        fprintf(stdout, "running %s myconf: %s, key: %s, signconf: %s\n", 
		argv[0], myconf, key, signconf);
    }

    /* Use the device key as the intel key for now. Set the intel
     * key for the hardware to whatever we claim it should be. */
    load_rsa_keys(key, intel_pubkey, intel_seckey, KEY_LENGTH_BITS);
    fprintf(stdout, "Read Intel key.\n"); fflush(stdout);
 
    sys_sgx_init(intel_pubkey);
    fprintf(stdout, "Inited SGX.\n"); fflush(stdout);

    tcs = create_launch_enclave(myconf);
    fprintf(stdout, "Created Launch enclave.\n"); fflush(stdout);

    /* Read in the unsigned inittoken */
    token = load_einittoken(signconf);
    fprintf(stdout, "Read inittoken.\n"); fflush(stdout);
 
    /* Sign it */  
    sign_einittoken(tcs, exception_handler, token);
    fprintf(stdout, "Signed inittoken.\n"); fflush(stdout);

    /* Print out the resulting signature */
    char *msg = dbg_dump_einittoken(token);
    printf("# EINITTOKEN START\n");
    printf("%s\n", msg);
    printf("# EINITTOKEN END\n");

    return 0;
}
