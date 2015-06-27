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

#include <sys/stat.h>

int a_val = 0;

ENCCALL1(enclave1_call, int *)

int main(int argc, char **argv)
{
	void *conf, *enclave;
	void *pages, *entry;
	size_t npages;
	int keid;
	keid_t stat;
	int j;

    	if (argc < 1) {
        	fprintf(stderr, "Please specify enclave binary to load\n");
		exit(-1);
	}
	enclave = argv[1];

	if (argc > 2) {
		conf = argv[2];
	} else {
		conf = NULL;
	}
	
    	if(!sgx_init())
        	err(1, "failed to init sgx");

	pages = load_elf_enclave(enclave, &npages, &entry);

	fprintf(stdout, "Creating enclave of %d pages at address %p.\n", npages, pages);
    	keid = create_enclave(entry, pages, npages, conf);

    	if (syscall_stat_enclave(keid, &stat) < 0)
        	err(1, "failed to stat enclave");

    	fprintf(stdout, "a_val = %d.\n", a_val);
    		enclave1_call(stat.tcs, exception_handler, &a_val);
    		fprintf(stdout, "a_val = %d.\n", a_val);

    	return 0;
}

