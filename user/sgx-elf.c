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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <gelf.h>

int elf_to_mmap_flags(int eflags)
{
	int r = PROT_NONE;
	if (eflags & PF_R) r |= PROT_READ;
	if (eflags & PF_W) r |= PROT_WRITE;
	if (eflags & PF_X) r |= PROT_EXEC;
	return r;
}

void *load_elf_enclave(char *filename, size_t *npages, void **entry)
{
	int fd;
	Elf *e;
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	int i;
	size_t n;
	void *addr = (void *)-1UL;

	*npages = 0;

	/* Read an elf binary, mapping it into our memory for loading as
	 * an enclave - it's a straight binary that cannot require relocation */

	/* ELF sanity checks */
	if (elf_version( EV_CURRENT ) == EV_NONE ) {
		fprintf(stderr, "ELF library initialization failed: %s\n",
			elf_errmsg(-1));
		return NULL;
	}
	if ((fd = open(filename, O_RDONLY, 0)) < 0) {
		fprintf(stderr,"open \"%s\" failed\n", filename);
		return NULL;
	}
	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL ) {
		fprintf(stderr, "elf_begin() failed: %s.\n" ,
			elf_errmsg(-1));
		return NULL;
	}
	if (elf_kind(e) != ELF_K_ELF) {
		fprintf(stderr,"\"%s\" is not an ELF object.\n" ,
			filename);
		return NULL;
	}
	if (gelf_getehdr(e, &ehdr ) == NULL ) {
		fprintf(stderr, "getehdr() failed: %s.\n" ,
			elf_errmsg(-1));
		return NULL;
	}

	/* Now pick out the entry point */
	*entry = (void *)ehdr.e_entry;
	
	/* Now map in the loadable program segments */
	if ( elf_getphdrnum(e, &n) != 0) {
		fprintf(stderr, "getphdrnum() failed: %s.\n",
			elf_errmsg(-1));
			return NULL;
	}
	for (i = 0; i < n; i++) { 
		unsigned long start, fdataend, fend, mend;
		int pflags;
		void *p;

		if (gelf_getphdr(e, i, &phdr ) != &phdr ) {
			fprintf(stderr, "getphdr() failed: %s.\n" ,
				elf_errmsg(-1));
			return NULL;
		}
		if (phdr.p_type != PT_LOAD)
			continue;
		
		start = round_down(phdr.p_vaddr, PAGE_SIZE);
		fdataend = phdr.p_vaddr + phdr.p_filesz;
		fend  = round_up(phdr.p_vaddr + phdr.p_filesz, PAGE_SIZE);
		mend = round_up(phdr.p_vaddr + phdr.p_memsz, PAGE_SIZE);
		pflags = elf_to_mmap_flags(phdr.p_flags) | PROT_WRITE;
		
		/* First, get a zeroed memory range for all the memory we 
		 * need. We do this to make sure we don't overlap with
		 * other existing page ranges (like the EPC)  */
		p = mmap((void *)start, mend-start, pflags, MAP_PRIVATE|MAP_ANONYMOUS, 
			 -1, 0);
		if (p != (void *) start) {
			fprintf(stderr, "WARNING: Could not get enough memory "
				"at addr %p for segment.\n", (void *)start); }
		/* Now remap the file into the part of the mapping we just
		 * made that should come from the file */
		p = mmap(p, fend-start, pflags, MAP_PRIVATE|MAP_FIXED, 
			 fd, round_down(phdr.p_offset, PAGE_SIZE));
		if (!p) {
			perror("mmap");
			return NULL;
		}
		if (start < phdr.p_vaddr) {
			memset((void *)p, 0, start - phdr.p_vaddr);
		}
		if (fend > fdataend) {
			memset((char *)p + (fdataend - start), 0, 
			       fend - fdataend);
		}
		/* We should really make this return a list of ranges */
		if (p < addr) {
			addr = p;
			*npages += (mend-start)/PAGE_SIZE;
		}
	}
	if (addr != (void *)-1UL)
		return addr;
	else 
		return NULL;
}
	
