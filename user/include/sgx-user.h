#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>
#include <sgx.h>

//about a page
#define STUB_ADDR       0x80800000
#define HEAP_ADDR       0x80900000
#define SGXLIB_MAX_ARG  512

extern int sgx_init(void);
void *load_elf_enclave(char *filename, size_t *npages, void **entry, int *entoff);
tcs_t *create_elf_enclave(char *enc, sigstruct_t *ss, einittoken_t *ei, int debug);
tcs_t *create_elf_enclave_conf(char *enc, char *conf, sigstruct_t **ss, int debug);

/* Macros to define user-side enclave calls with different argument
 * numbers */
#define ENCCALL0(name)                                          \
int name(tcs_t *tcs, void (*aep)()) {                           \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                \
                ".byte 0x01\n\t"                                \
                ".byte 0xd7\n\t"                                \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL1(name, type1)                                   \
void name(tcs_t *tcs, void (*aep)(), type1 arg1) {              \
        register type1 rdi asm("rdi") __attribute((unused));    \
        rdi = arg1;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep),					\
		  "r"(rdi)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL2(name, type1, type2)                            \
void name(tcs_t *tcs, void (*aep)(), type1 arg1, type2 arg2) {  \
        register type1 rdi asm("rdi") __attribute((unused));                          \
        register type2 rsi asm("rsi") __attribute((unused));                          \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep),					\
		  "r"(rdi),					\
		  "r"(rsi)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL3(name, type1, type2, type3)                     \
void name(tcs_t *tcs, void (*aep)(), type1 arg1, type2 arg2, 	\
	 type3 arg3) {                  			\
        register type1 rdi asm("rdi");    \
        register type2 rsi asm("rsi");    \
        register type3 rdx asm("rdx");    \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        rdx = arg3;              				\
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                \
                ".byte 0x01\n\t"                                \
                ".byte 0xd7\n\t"                                \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep),					\
		  "r"(rdi),					\
		  "r"(rsi),					\
		  "r"(rdx)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL4(name, type1, type2, type3, type4)              \
void name(tcs_t tcs, void (*aep)(), type1 arg1, type2 arg2, type3 arg3, type4 arg4) {      \
        int status;                                             \
        register type1 rdi asm("rdi") __attribute((unused));                          \
        register type2 rsi asm("rsi") __attribute((unused));                          \
        register type3 rdx asm("rdx") __attribute((unused));                          \
        register type4 r10 asm("r10") __attribute((unused));                          \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        rdx = arg3;                                             \
        r10 = arg4;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep),					\
		  "r"(rdi),					\
		  "r"(rsi),					\
		  "r"(rdx),					\
		  "r"(r10)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL5(name, type1, type2, type3, type4, type5)       \
void name(tcs_t *tcs, void (*aep)(), type1 arg1, type2 arg2, type3 arg3, type4 arg4,        \
         type5 arg5) {                                          \
        register type1 rdi asm("rdi");                          \
        register type2 rsi asm("rsi");                          \
        register type3 rdx asm("rdx");                          \
        register type4 r10 asm("r10");                          \
        register type5 r8  asm("r8");                           \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        rdx = arg3;                                             \
        r10 = arg4;                                             \
        r8  = arg5;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep),					\
		  "r"(rdi),					\
		  "r"(rsi),					\
		  "r"(rdx),					\
		  "r"(r10),					\
		  "r"(r8)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL6(name, type1, type2, type3, type4, type5, type6)\
void name(tcs_t *tcs, void (*aep)(), type1 arg1, type2 arg2, type3 arg3, type4 arg4,        \
         type5 arg5, type6 arg6) {                              \
        int status;                                             \
        register type1 rdi asm("rdi");                          \
        register type2 rsi asm("rsi");                          \
        register type3 rdx asm("rdx");                          \
        register type4 r10 asm("r10");                          \
        register type5 r8  asm("r8");                           \
        register type6 r9  asm("r9");                           \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        rdx = arg3;                                             \
        r10 = arg4;                                             \
        r8  = arg5;                                             \
        r9  = arg6;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep),					\
		  "r"(rdi),					\
		  "r"(rsi),					\
		  "r"(rdx),					\
		  "r"(r10),					\
		  "r"(r8),					\
		  "r"(r9)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

