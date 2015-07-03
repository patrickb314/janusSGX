/* A simple quoting enclave that accepts REPORTS and signs them with the 
 * Intel private key. */

/* Questions:
 * 1. How do we get the internal private key? EGETKEY returns keys that
 *    are too short for this, and in a real system it can't be stored in 
 *    in the enclave, since that's seen by the caller. 
 */

/* Current hacks:
 * - The private key we use for quoting is hard-coded here, so not actually
 * secure (since the untrusted host can see in here). To give some mediocum of
 * security, what's actually hardcoded here is the "Intel" private key
 * encrypted with the platform launch key; only Intel-signed enclaves
 * running sealed up get access to that key. In that way, the host code
 * (which doesn't in theory have access to the launch key) can't simply 
 * extract the private key and go to town.
 */

#include <sgx-lib.h>

int verify_report(report_t *report)
{
	keyrequest_t keyreq;
	unsigned char report_key[DEVICE_KEY_LENGTH];
	unsigned char mac[MAC_SIZE];

	/* Verify the report via local attestation */
	memset(&keyreq, 0, sizeof(keyreq));
	keyreq.keyname = REPORT_KEY;
	memcpy(&keyreq.keyid, &report->keyid, 32); // Only attribute used!
	sgx_getkey(&keyreq, report_key);

	/* Only the first 384 bytes of the structure are hashed */
	aes_cmac(report_key, (unsigned char *)report, 384, mac); 
	
	if (memcmp(mac, report->mac, MAC_SIZE) != 0) {
		return -1;
	} 

	/* What other checks do we do on the report? Do we
	 * check MRENCLAVE somehow or MRSIGNER? - if the CMAC
	 * succeeded the hardware had verified them already as
	 * correct. */
	return 0;
}

void sign_quote(quote_t *q)
{
#if 0
	keyrequest_t keyreq;

	unsigned char launch_key[DEVICE_KEY_LENGTH];

	/* Get the platform launch key. */
        memset(&keyreq, 0, sizeof(keyreq));
        keyreq.keyname = LAUNCH_KEY;
        memset(keyreq.cpusvn, 0, 16);
        keyreq.isvsvn = 0;
        memset(&keyreq.keyid, 0, 32);
        sgx_getkey(&keyreq, launch_key);

	/* Get the quoting key and sign. */
	decrypt_quoting_key(&ctx, launch_key, crypt_quoting_key);

	/* Now we wouldsign that thing... */
	rsa_sign(&ctx, (unsigned char *)&q->report, 384,
		       (unsigned char *)q->sig);
#endif
	return;
}

void enclave_main(report_t *report, quote_t *quote)
{
	report_t *r; 
	quote_t *q;

	r = malloc(sizeof(report_t));
	q = malloc(sizeof(quote_t));
	
	memset(quote->sig, 0x1, sizeof(rsa_sig_t));

	/* First, copy what we're working with to enclave memory
	 * to avoid complications with the host racing with us 
	 * to try and get odd results */
	memcpy(r, report, sizeof(report_t));

	/* Check that the report is actually locally. */
	if (verify_report(report) != 0) {
		goto fail;
	}

	/* Copy the report to the quote */
	memcpy(&q->report, r, sizeof(report_t));

	/* Now sign the quote */
	sign_quote(q);

	/* Copy the signed quote out */
	memcpy(quote, q, sizeof(quote_t));
out:
	free(q);
	free(r);
	return;
fail: 
	memset(&quote, -1, sizeof(quote_t));
	goto out;
}
