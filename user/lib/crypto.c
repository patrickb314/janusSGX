#include <sgx-lib.h>

void aes_cmac(unsigned char *key, unsigned char *input, size_t bytes, 
	      unsigned char *mac)
{
    aes_cmac128_context ctx;
    aes_cmac128_starts(&ctx, key);
    aes_cmac128_update(&ctx, input, bytes);
    aes_cmac128_final(&ctx, mac);
}

void rsa_sign(unsigned char *key, unsigned char *input, size_t bytes, 
	      unsigned char *sig)
{
	unsigned char hash[HASH_SIZE];
	rsa_context ctx;

        rsa_init(&ctx, RSA_PKCS_V15, 0);
        sha1((unsigned char *)input, bytes, hash);
        rsa_pkcs1_sign(&ctx, NULL, NULL, RSA_PRIVATE,
                       POLARSSL_MD_SHA1, HASH_SIZE, hash, sig);
        rsa_free(&ctx);
	return;
}
