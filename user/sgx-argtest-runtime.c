#include <string.h>
#include <sgx-kern.h>
#include <sgx-user.h>
#include <sgx-utils.h>
#include <sgx-signature.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <asm/ptrace.h>

#include <dlfcn.h>

#include <sgx-lib.h>

#define is_aligned(addr, bytes) \
     ((((uintptr_t)(const void *)(addr)) & (bytes - 1)) == 0)

void enclave_start();

int a_val = 0;

ENCCALL1(enclave1_call, int *)

void usage(char *progname)
{
    fprintf(stderr, "usage: %s enclavefile\n", progname);
    fflush(stderr);
}

extern void *ENCT_START, *ENCT_END, *ENCD_START, *ENCD_END;

int main(int argc, char **argv)
{
    void *entry = enclave_start;

    if(!sgx_init())
        err(1, "failed to init sgx");

    //XXX n_of_pages should be set properly
    //n_of_pages = n_of_enc_code + n_of_enc_data
    //improper setting of n_of_pages could contaminate other EPC area
    //e.g. if n_of_pages mistakenly doesn't consider enc_data section,
    //memory write access to enc_data section could make write access on other EPC page.
    void *codes = (void *)(uintptr_t)&ENCT_START;
    unsigned long ecode_size = (unsigned long)&ENCT_END - (unsigned long)&ENCT_START;
    unsigned long edata_size = (unsigned long)&ENCD_END - (unsigned long)&ENCD_START;
    unsigned long ecode_page_n = ((ecode_size - 1) / PAGE_SIZE) + 1;
    unsigned long edata_page_n = ((edata_size - 1) / PAGE_SIZE) + 1;
    unsigned long n_of_pages = ecode_page_n + edata_page_n;

    assert(is_aligned((uintptr_t)codes, PAGE_SIZE));

    int keid = create_enclave(entry, codes, n_of_pages, NULL);

    keid_t stat; 
    if (syscall_stat_enclave(keid, &stat) < 0)
        err(1, "failed to stat enclave");

    fprintf(stdout, "a_val = %d.\n", a_val);
    enclave1_call(stat.tcs, exception_handler, &a_val);
    fprintf(stdout, "a_val = %d.\n", a_val);

    return 0;
}

