// Simple test case using the enclave gate mechanism

#include "test.h"
#include <sgx-lib.h>
#include <egate.h>

void enclave_main(egate_t *g)
{
	int random;
	entropy_context ectx;
	ctr_drbg_context rctx;
	enclave_entropy_init(&ectx);
	ctr_drbg_init(&rctx, entropy_func, &ectx, NULL, 0);
	ctr_drbg_random(&rctx, &random, sizeof(int));
	eg_printf(g, 
		  "Random number %d from the enclave.\n", random);
}
