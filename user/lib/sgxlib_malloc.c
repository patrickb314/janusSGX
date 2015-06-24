#include <sgx-lib.h>

char *heap_base = 0;
char *heap_top = 0;
char *heap_limit = 0;

int sgx_malloc_init(void *start, size_t len)
{
	heap_base = heap_top = start;
	heap_limit = heap_top + len;
}

extern void *ENCD_END;
void *sgx_malloc(size_t len)
{
	char *newtop, *val;

	if (heap_base == 0) {
		char *top = (char *)&ENCD_END + STACK_PAGE_FRAMES*PAGE_SIZE;
		sgx_malloc_init(top, HEAP_PAGE_FRAMES*PAGE_SIZE);
        }

	if (len <= 0) return NULL;
	val = heap_top;
	newtop = (char *)((unsigned long)(heap_top + len + 7) & ~0x7);

	if (newtop + len >= heap_limit) return NULL;

	heap_top = newtop;
	return val;
}

void sgx_free(void *p)
{
	return NULL;
}

void *sgx_realloc(void *ptr, size_t size)
{
    void *new;
    if(ptr == NULL){
        return sgx_malloc(size);
    }
    else{
        if (size == 0){
             sgx_free(ptr);
             return NULL;
        }
        new = sgx_malloc(size);
        if(new != NULL){
            //if new size > old size, old_size+alpha is written to new. Thus, some of garbage values would be copied
            //if old size > new size, new_size is written to new. Thus, some of old values would be lossed
            //sgx_print_hex(new);
            sgx_memcpy(new, ptr, size);
            return new;
        }
        else{
            return NULL;
        }
    }

}

