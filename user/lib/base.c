#include <sgx-lib.h>
#include <asm/ptrace.h>

// one 4k page : enclave page & offset

void _enclu(enclu_cmd_t leaf, uint64_t rbx, uint64_t rcx, uint64_t rdx,
           out_regs_t *out_regs)
{
   out_regs_t tmp;
   asm volatile(".byte 0x0F\n\t"
                ".byte 0x01\n\t"
                ".byte 0xd7\n\t"
                :"=a"(tmp.oeax),
                 "=b"(tmp.orbx),
                 "=c"(tmp.orcx),
                 "=d"(tmp.ordx)
                :"a"((uint32_t)leaf),
                 "b"(rbx),
                 "c"(rcx),
                 "d"(rdx)
                :"memory");

    // Check whether function requires out_regs
    if (out_regs != NULL) {
        asm volatile ("" : : : "memory"); // Compile time Barrier
        asm volatile ("movl %%eax, %0\n\t"
            "movq %%rbx, %1\n\t"
            "movq %%rcx, %2\n\t"
            "movq %%rdx, %3\n\t"
            :"=a"(out_regs->oeax),
             "=b"(out_regs->orbx),
             "=c"(out_regs->orcx),
             "=d"(out_regs->ordx));
    }
}

size_t strlen(const char *string) {
    size_t len = 0;
    asm volatile("" ::: "memory");
    asm volatile("push  %%rdi\n\t"
                 "xor   %%rcx, %%rcx\n\t"
                 "movq  %1, %%rdi\n\t"
                 "not   %%ecx\n\t"
                 "xor   %%eax, %%eax\n\t"
                 "xor   %%al, %%al\n\t"
                 "cld\n\t"
                 "repne scasb\n\t"
                 "not   %%ecx\n\t"
                 "pop   %%rdi\n\t"
                 "lea   -0x1(%%ecx), %%eax\n\t"
                 :"=a"(len)
                 :"r"((uint64_t) string)
                 :"%rdi");
    return len;
}

int strcmp (const char *str1, const char *str2)
{
    int result = 0;
    asm volatile("" ::: "memory");
    asm volatile("push %%rsi\n\t"
                 "push %%rdi\n\t"
                 "movq %1, %%rsi\n\t"
                 "movq %2, %%rdi\n\t"

                 "REPEAT :\n\t"
                 "movzbl (%%rsi), %%eax\n\t"
                 "movzbl (%%rdi), %%ebx\n\t"
                 "sub %%bl, %%al\n\t"

                 "ja END\n\t"
                 "jb BELOW\n\t"
                 "je EQUAL\n\t"

                 "EQUAL :\n\t"
                 "inc %%rsi\n\t"
                 "inc %%rdi\n\t"
                 "test %%bl, %%bl\n\t"
                 "jnz REPEAT\n\t"

                 "BELOW :\n\t"
                 "neg %%rax\n\t"
                 "neg %%al\n\t"

                 "END :\n\t"
                 "pop %%rdi\n\t"
                 "pop %%rsi\n\t"
                 :"=a"(result)
                 :"r"((uint64_t)str1),
                  "r"((uint64_t)str2)
                 :"%rsi", "%rdi");


    return result;
}

unsigned char tolower(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	else
		return c;
}

int strcasecmp(const char *str1, const char *str2)
{
 	char *s1 = str1, *s2 = str2;
	while (tolower(*s1) == tolower(*s2))
		if (*s1++ || !*s2++)
			return 0;
	return tolower(*s1) - tolower(*s2);
}

int memcmp (const void *ptr1, const void *ptr2, size_t num)
{
    int result = 0;
    asm volatile("" ::: "memory");
    asm volatile("push %%rsi\n\t"
                 "push %%rdi\n\t"
                 "movq %1, %%rsi\n\t"
                 "movq %2, %%rdi\n\t"
                 "movq %3, %%rcx\n\t"
                 "xor %%rax,%%rax\n\t"
                 "cld\n\t"
                 "cmp %%rcx, %%rcx\n\t"
                 "repe cmpsb\n\t"

                 "jb CMP_BELOW\n\t"
                 "ja CMP_ABOVE\n\t"
                 "je CMP_END\n\t"

                 "CMP_ABOVE :\n\t"
                 "seta %%al\n\t"
                 "jmp END\n\t"

                 "CMP_BELOW :\n\t"
                 "setb %%al\n\t"
                 "neg %%rax\n\t"
                 "jmp END\n\t"

                 "CMP_END :\n\t"
                 "pop %%rdi\n\t"
                 "pop %%rsi\n\t"
                 :"=a"(result)
                 :"r"((uint64_t)ptr1),
                  "r"((uint64_t)ptr2),
                  "c"(num)
                 :"%rsi", "%rdi");


    return result;
}

void *memset (void *ptr, int value, size_t num)
{
    asm volatile("" ::: "memory");
    asm volatile("xor %%rax, %%rax\n\t"
                 "movq %0, %%rdi\n\t"           
                 "movb %1, %%al\n\t"            
                 "movq %2, %%rcx\n\t"           
                 "body:"                        
                    "mov %%al, 0x0(%%rdi)\n\t"  
                    "lea 0x1(%%rdi), %%rdi\n\t" 
                    "loop body\n\t"             
                 :                              
                 :"r"((uint64_t) ptr),          
                  "r"((uint8_t) value),         
                  "r"((uint64_t) num)           
                 :"%rdi", "%al", "%rcx");       

    return ptr;
}

void *memcpy (void *dest, const void *src, size_t size)
{
    asm volatile("" ::: "memory");
    asm volatile("movq %0, %%rdi\n\t"
                 "movq %1, %%rsi\n\t"           
                 "movl %2, %%ecx\n\t"           
                 "rep movsb \n\t"               
                 :                              
                 :"a"((uint64_t)dest),          
                  "b"((uint64_t)src),           
                  "c"((uint32_t)size));

    return dest;
}

void enclave_exception (void *prev_cssa)
{
	// For now, just return to the trampoline, which will eexit out
	// of the enclave. Longer term, we should examine the stack in 
	// prev_cssa to see if there's an actual enclave-side exception
	// we need to handle. For now, though, we just assume that
	// it was an external interrupt and the enclave just needs to be
	// eresumed.
	return; 
}
