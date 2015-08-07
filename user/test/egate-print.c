// Simple test case using the enclave gate mechanism

#include "test.h"
#include <sgx-lib.h>
#include <egate.h>

void enclave_main(egate_t *g)
{
	static int done = 0;
	int i = 0;
	if (!done) {
		for (i = 10; i > 0; i--) {
			eg_printf(g, 
				  "Hello %d from the enclave %p.\n", i, g);
		}
	}
	done = 1;
	eg_exit(g, 0);
}
