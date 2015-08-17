#include <sgx-lib.h>

void aes_cmac(unsigned char *key, unsigned char *input, size_t bytes, 
	      unsigned char *mac)
{
    aes_cmac128_context ctx;
    aes_cmac128_starts(&ctx, key);
    aes_cmac128_update(&ctx, input, bytes);
    aes_cmac128_final(&ctx, mac);
}

/* XXX PGB Should we use SHA1 here or switch to a bigger hash and 
 * SHA256? */
void rsa_sign(rsa_context *ctx, unsigned char *input, size_t bytes, 
	      unsigned char *sig)
{
	unsigned char hash[HASH_SIZE];

        sha1((unsigned char *)input, bytes, hash);
        rsa_pkcs1_sign(ctx, NULL, NULL, RSA_PRIVATE,
                       POLARSSL_MD_SHA1, HASH_SIZE, hash, sig);
	return;
}

#define RDRAND_RETRY_LOOPS 10
static inline int rdrand_long(unsigned long *v)
{
        int ok;
        asm volatile("1: .byte 0x48,0x0f,0xc7,0xf0\n\t"
                     "jc 2f\n\t"
                     "decl %0\n\t"
                     "jnz 1b\n\t"
                     "2:"
                     : "=r" (ok), "=a" (*v)
                     : "0" (RDRAND_RETRY_LOOPS));
        return ok;
}

/* Consider switching to RDSEED when we know we have it... */
static int rdrand_data_source(void *data, unsigned char *output, size_t len, size_t *olen)
{
	int i;
	len = len & ~0x7;
	for (i = 0; i < len; i+=8)
	{
		uint64_t data;
		if (!rdrand_long(&data)) {
			break;
		}
		*(uint64_t *)(output + i) = data;
	}
	*olen = i;
	return 0;
}

int enclave_entropy_init( entropy_context *ctx )
{
	entropy_init(ctx);
	return entropy_add_source(ctx, rdrand_data_source, NULL, 8);
}
