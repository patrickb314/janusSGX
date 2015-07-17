/* A simple launch enclave that accepts EINITTOKENS and signs them with the 
 * Intel key. */

/* Questions:
 * 1. Where do I get my cpusvnLE and isvprodIDLE, and other non-MACed attributes
 * from, or does the caller fill these in since they're all in my SECS (which
 * he set up and were mac-ed to launch me anyway? 
 * 2. Look into signing of debug enclaves. Is there a seperate signer for those?
 */
#include <sgx-lib.h>
void enclave_main(einittoken_t *inittoken)
{
	einittoken_t tok;
	keyrequest_t keyreq;
	unsigned char launch_key[128];
	unsigned char mac[MAC_SIZE];
	int i;
	void *retp;
	
	memset(inittoken->mac, -1, MAC_SIZE);
	retp = copyin(&tok, inittoken, sizeof(einittoken_t));
	if (!retp) goto fail;

	memset(inittoken->mac, -2, MAC_SIZE);
	/* Only sign non-intel enclaves */
	if (!tok.valid) {
		goto fail;
	} 

	memset(inittoken->mac, -3, MAC_SIZE);
	for (i = 0; i < 44; i++) {
		if (tok.reserved1[i] != 0) {
			goto fail;
		} 
	}

	memset(inittoken->mac, -4, MAC_SIZE);
	if (tok.attributes.reserved1 != 0) {
		goto fail;
	}

#if 1
	/* Whey does the inittoken for simple enclaves list as
	 * one with an inittoken key? XXX */
	memset(inittoken->mac, -5, MAC_SIZE);
	/* Don't sign new launch enclaves */
	if (tok.attributes.einittokenkey) {
		goto fail;
	}

	memset(inittoken->mac, -6, MAC_SIZE);
	/* Should we sign debug enclaves? */
	if (tok.attributes.debug) {
		goto fail;
	}
#endif

	memset(inittoken->mac, -7, MAC_SIZE);
	/* Get the launch key -
	 * in the request, the attribute mask, cpusvn, isvsvn, and 
	 * keyid come from the request! */
	memset(&keyreq, 0, sizeof(keyreq));
	keyreq.keyname = LAUNCH_KEY;
	memcpy(keyreq.cpusvn, &tok.cpuSvnLE, 16);
	keyreq.isvsvn = tok.isvsvnLE;
	memcpy(&keyreq.keyid, &tok.keyid, 32);
	sgx_getkey(&keyreq, launch_key);

	memset(inittoken->mac, -8, MAC_SIZE);
	/* Only the first 192 bytes of hte structure are signed */
	aes_cmac(launch_key, (unsigned char *)&tok, 192, mac); 
	memcpy(&tok.mac, mac, MAC_SIZE);

	/* And we're done. */
	copyout(inittoken, &tok, sizeof(einittoken_t));
	return;

    fail:
	return;
}
