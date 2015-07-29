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

tcs_t *create_launch_enclave(char *enc, char *conf)
{
	size_t npages;
	void *entry;
	void* pages = load_elf_enclave(enc, &npages, &entry, 0);
	int keid;
	keid_t stat;

        fprintf(stdout, "Creating launch enclave of %d pages at address %p.\n", (int)npages, pages);
        keid = create_enclave_conf(entry, pages, npages, conf);

        if (syscall_stat_enclave(keid, &stat) < 0)
                err(1, "failed to stat enclave");

    	return stat.tcs;
}

void usage(char *progname)
{
	fprintf(stderr, "usage: %s launch.sgx my.conf intel.key sign.conf\n", progname);
}

int main(int argc, char **argv)
{
    tcs_t *tcs;
    einittoken_t *token;
    char *key, *launchenc, *launchconf, *signconf;

    unsigned char intel_pubkey[KEY_LENGTH];
    unsigned char intel_seckey[KEY_LENGTH];

    if (argc < 5) {
	usage(argv[0]);
	exit(-1);
    } else {
	launchenc = argv[1];
	launchconf = argv[2];
	key = argv[3];
	signconf = argv[4];
        fprintf(stdout, "running %s launchenc: %s launchconf: %s, key: %s, signconf: %s\n", 
		argv[0], launchenc, launchconf, key, signconf);
    }

    /* Use the device key as the intel key for now. Set the intel
     * key for the hardware to whatever we claim it should be. */
    load_rsa_keys(key, intel_pubkey, intel_seckey, KEY_LENGTH_BITS);
    fprintf(stdout, "Read Intel key.\n"); fflush(stdout);
 
    sys_sgx_init(intel_pubkey);
    fprintf(stdout, "Inited SGX.\n"); fflush(stdout);

    tcs = create_launch_enclave(launchenc, launchconf);
    fprintf(stdout, "Created Launch enclave.\n"); fflush(stdout);

    /* Read in the unsigned inittoken */
    token = load_einittoken(signconf);
    fprintf(stdout, "Read inittoken.\n"); fflush(stdout);
    fprintf(stdout, "Original MAC token:");
    hexdump(stdout, token->mac, MAC_SIZE);
    
    fprintf(stdout, "Zeroing MAC token:");
    memset(token->mac, 0, MAC_SIZE);
    hexdump(stdout, token->mac, MAC_SIZE);

    /* Sign it */  
    sign_einittoken(tcs, exception_handler, token);
    fprintf(stdout, "Signed inittoken.\n"); fflush(stdout);

    /* Launch-enclave generated MAC */
    fprintf(stdout, "Launch enclave MAC token:");
    hexdump(stdout, token->mac, MAC_SIZE);

    return 0;
}
