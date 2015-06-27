#include <sgx-lib.h>
#include <openssl/cmac.h>

void sgx_cmac(unsigned char *key, unsigned char *input, size_t bytes, unsigned char *mac)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    int outbytes;
    CMAC_Init(ctx, key, KEY_LENGTH, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, input, bytes);
    CMAC_Final(ctx, mac, &outbytes);
    CMAC_CTX_free(ctx);
}

