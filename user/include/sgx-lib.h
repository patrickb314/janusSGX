#pragma once

#include <sgx.h>
#include <sgx-user.h>
#include <sgx-kern.h>

#define sgx_exit() {                         \
    asm volatile(".byte 0x0F\n\t"               \
                 ".byte 0x01\n\t"               \
                 ".byte 0xd7\n\t"               \
                 :                              \
                 :"a"((uint32_t)ENCLU_EEXIT),   \
		  "b"((uint64_t)0)); 		\
}

#define sgx_report(tgtinfo, rptdata, output) {  \
    asm volatile("movl %0, %%eax\n\t"           \
                 "movq %1, %%rbx\n\t"           \
                 "movq %2, %%rcx\n\t"           \
                 "movq %3, %%rdx\n\t"           \
                 ".byte 0x0F\n\t"               \
                 ".byte 0x01\n\t"               \
                 ".byte 0xd7\n\t"               \
                 :                              \
                 :"a"((uint32_t)ENCLU_EREPORT), \
                  "b"((uint64_t)tgtinfo),       \
                  "c"((uint64_t)rptdata),       \
                  "d"((uint64_t)output));       \
}

#define sgx_getkey(keyreq, output) {            \
    asm volatile("movl %0, %%eax\n\t"           \
                 "movq %1, %%rbx\n\t"           \
                 "movq %2, %%rcx\n\t"           \
                 ".byte 0x0F\n\t"               \
                 ".byte 0x01\n\t"               \
                 ".byte 0xd7\n\t"               \
                 :                              \
                 :"a"((uint32_t)ENCLU_EGETKEY), \
                  "b"((uint64_t)keyreq),        \
                  "c"((uint64_t)output));       \
}

/* Following macros taken with permission from
 * from Kitten include/lwk/macros.h */
#define round_up(x,y) (((x) + (y) - 1) & ~((y)-1))
#define round_down(x,y) ((x) & ~((y)-1))

extern unsigned long cur_heap_ptr;
extern unsigned long heap_end;


extern void _enclu(enclu_cmd_t leaf, uint64_t rbx, uint64_t rcx, uint64_t rdx,
           out_regs_t *out_regs);
extern void aes_cmac(unsigned char *key, unsigned char *input, size_t bytes, unsigned char *mac);
extern void rsa_sign(rsa_context *ctx, unsigned char *input, size_t bytes, 
              	    unsigned char *sig);

void *copyin(void *dest, const void *src, size_t size);
void *copyout(void *dest, const void *src, size_t size);
void *copyenclave(void *dest, const void *src, size_t size);
void *copyuser(void *dest, const void *src, size_t size);
