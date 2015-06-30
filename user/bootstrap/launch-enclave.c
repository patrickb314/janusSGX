/* A simple launch enclave that accepts EINITTOKENS and signs them with the 
 * Intel key. */

/* Questions:
 * 1. Where do I get my cpusvnLE and isvprodIDLE, and other non-MACed attributes
 * from, or does the caller fill these in since they're all in my SECS (which
 * he set up and were mac-ed to launch me anyway? 
 * 2. Look into signing of debug enclaves. Is there a seperate signer for those?
 * 3. 
 */
#include <sgx-lib.h>
void enclave_main(einittoken_t *inittoken)
{
	keyrequest_t keyreq;
	unsigned char launch_key[128];
	unsigned char mac[MAC_SIZE];
	int i;

	/* Only sign non-intel enclaves */
	if (!inittoken->valid) {
		goto fail;
	} 

	for (i = 0; i < 44; i++) {
		if (inittoken->reserved1[i] != 0) {
			goto fail;
		} 
	}

	if (inittoken->attributes.reserved1 != 0) {
		goto fail;
	}

#if 0
	/* Don't sign new launch enclaves */
	if (inittoken->attributes.einittokenkey) {
		goto fail;
	}

	/* Should we sign debug enclaves? */
	if (inittoken->attributes.debug) {
		/* If this is a debug enclave, we probably want additional
		 * checks - what should those be? */
	}
#endif

	/* Get the launch key -
	 * in the request, the attribute mask, cpusvn, isvsvn, and 
	 * keyid come from the request! */
	memset(&keyreq, 0, sizeof(keyreq));
	keyreq.keyname = LAUNCH_KEY;
	memcpy(keyreq.cpusvn, &inittoken->cpuSvnLE, 16);
	keyreq.isvsvn = inittoken->isvsvnLE;
	memcpy(&keyreq.keyid, &inittoken->keyid, 32);
	sgx_getkey(&keyreq, launch_key);

	/* Only the first 192 bytes of hte structure are signed */
	cmac(launch_key, (unsigned char *)inittoken, 192, mac); 
	memcpy(inittoken->mac, mac, MAC_SIZE);

	/* Now we have to sign it! */
	
	/* And we're done. */
	return;

    fail:
	memset(inittoken->mac, 0xff, MAC_SIZE);
	return;
}
