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
        register type1 rdi asm("rdi") __attribute((unused));                          \
        rdi = arg1;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL2(name, type1, type2)                            \
void name(tcs_t *tcs, void (*aep)(), type1 arg1, type2 arg2) {  \
        register type1 rdi asm("rdi");                          \
        register type2 rsi asm("rsi");                          \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "a"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
}

#define ENCCALL3(name, type1, type2, type3)                     \
void name(tcs_t *tcs, void (*aep)(), type1 arg1, type2 arg2, 	\
	 type3 arg3) {                  			\
        register type1 rdi asm("rdi");                          \
        register type2 rsi asm("rsi");                          \
        register type3 rdx asm("rdx");                          \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        rdx = arg3;              				\
        asm volatile(                                           \
                ".byte 0x0F\n\t"                                    \
                ".byte 0x01\n\t"                                    \
                ".byte 0xd7\n\t"                                    \
		: "=c"(aep)					\
                : "0"((uint32_t)ENCLU_EENTER),			\
		  "b"(tcs),					\
		  "c"(aep)					\
                : "memory", "r11", "cc" 			\
        );                                                      \
        return status;                                          \
}

#define SYSCALL4(name, type1, type2, type3, type4)              \
int name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {      \
        int status;                                             \
        register type1 rdi asm("rdi");                          \
        register type2 rsi asm("rsi");                          \
        register type3 rdx asm("rdx");                          \
        register type4 r10 asm("r10");                          \
        rdi = arg1;                                             \
        rsi = arg2;                                             \
        rdx = arg3;                                             \
        r10 = arg4;                                             \
        asm volatile(                                           \
                "syscall"                                       \
                : "=a" (status)                                 \
                : "0" (__NR_##name),                            \
                  "r" (rdi),                                    \
                  "r" (rsi),                                    \
                  "r" (rdx),                                    \
                  "r" (r10)                                     \
                : "memory", "rcx", "r11", "cc"                  \
        );                                                      \
        return status;                                          \
}

#define SYSCALL5(name, type1, type2, type3, type4, type5)       \
int name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,        \
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
                "syscall"                                       \
                : "=a" (status)                                 \
                : "0" (__NR_##name),                            \
                  "r" (rdi),                                    \
                  "r" (rsi),                                    \
                  "r" (rdx),                                    \
                  "r" (r10),                                    \
                  "r" (r8)                                      \
                : "memory", "rcx", "r11", "cc"                  \
        );                                                      \
        return status;                                          \
}

#define SYSCALL6(name, type1, type2, type3, type4, type5, type6)\
int name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,        \
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
                "syscall"                                       \
                : "=a" (status)                                 \
                : "0" (__NR_##name),                            \
                  "r" (rdi),                                    \
                  "r" (rsi),                                    \
                  "r" (rdx),                                    \
                  "r" (r10),                                    \
                  "r" (r8),                                     \
                  "r" (r9)                                      \
                : "memory", "rcx", "r11", "cc"                  \
        );                                                      \
        return status;                                          \
}

