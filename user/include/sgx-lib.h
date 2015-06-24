#pragma once

#include <sgx.h>
#include <sgx-user.h>
#include <sgx-kern.h>

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

extern unsigned long cur_heap_ptr;
extern unsigned long heap_end;


extern void _enclu(enclu_cmd_t leaf, uint64_t rbx, uint64_t rcx, uint64_t rdx,
           out_regs_t *out_regs);
extern size_t sgx_strlen(const char *string);
extern int sgx_strcmp (const char *str1, const char *str2);
extern int sgx_memcmp (const void *ptr1, const void *ptr2, size_t num);
extern void *sgx_memset (void *ptr, int value, size_t num);
extern void *sgx_memcpy (void *dest, const void *src, size_t size);
extern void sgx_cmac(unsigned char *key, unsigned char *input, size_t bytes, unsigned char *mac);
