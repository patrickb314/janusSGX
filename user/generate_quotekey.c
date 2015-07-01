 * running sealed up get access to that key. In that way, the host code
 * (which doesn't in theory have access to the launch key) can't simply 
 * extract the private key and go to town.
 */

#include <sgx.h>

int encrypt_quoting_key(unsigned char *in, const unsigned char *key, 
			unsigned char *out)
{
	/* XXX check return values in here */
	aes_context aes;
	unsigned char iv[16];
	memset(iv, 0xde, 16);

	aes_init(&aes);
	aes_setkey_enc(&aes, key, DEVICE_KEY_LENGTH_BITS);
	aes_crypt_cbc(&aes, AES_ENCRYPT, KEY_LENGTH, iv, in, out);
	aes_free(&aes);
	return 0;
}

void usage(char *progname)
{
	fprintf(stderr, "usage: %s device.key intel.key", progname);
	return;
}

int main(int argc, char **argv)
{
	char *devkev, *intelkey;
	unsigned char device_pubkey[DEVICE_KEY_LENGTH],
		      device_seckey[DEVICE_KEY_LENGTH],
		      launch_key[DEVICE_KEY_LENGTH],
	              intel_pubkey[KEY_LENGTH],
		      intel_seckey[KEY_LENGTH],
		      encrypted_key[KEY_LENGTH];

	if (argc < 3) {
		usage(argv[0]);
		exit(-1);
	}
	devkey = argv[1];
	intelkey = argv[2];

    	load_rsa_keys(devkey, device_pubkey, device_seckey, 
		      DEVICE_KEY_LENGTH_BITS);
    	load_rsa_keys(intelkey, intel_pubkey, intel_seckey, 
		      KEY_LENGTH_BITS);

    	generate_launch_key(device_seckey, launch_key);

	/* Now encrypt the intel secret key with the launch key */
	encrypt_quoting_key(intel_seckey, launch_key, encrypted_key);

	/* And print the resulting encrypted data */
	fprintf(stdout, "#define ENCRYPTED_QUOTING_KEY {");
	for (i = 0; i < DEVICE_KEY_LENGTH; i++) {
		fprintf(stdout, "%02x, ", encrypted_key[i]);
	}
	fprintf(stdout, "}");
	return;
}
