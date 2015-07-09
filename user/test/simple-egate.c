// The simplest enclave enter/exit.

#include "test.h"
#include <sgx-lib.h>
#include <egate.h>

void enclave_main(egate_t *g)
{
	static int done = 0;
	while (!done) {
		eg_printf(g, "Hello from the enclave through egate %p.\n", g);
		done = 1;
		eg_exit(g, 0);
	}
}
