// The simplest function pointer usage inside the enclave.

#include "test.h"

int fp_in_enclave(int a)
{
    return a + 2;
}

int (*fp)(int a) = fp_in_enclave;

void enclave_main(int *a)
{
	*a = fp(*a);
}
