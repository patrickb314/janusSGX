/* A simple quoting enclave that accepts REPORTS and signs them with the 
 * Intel private key. */

/* Questions:
 * 1. How do we get the internal private key? EGETKEY returns keys that
 *    are too short for this, and in a real system it can't be stored in 
 *    in the enclave, since that's seen by the caller. 
 */

/* Current hacks:
 * - The private key we use for quoting is hard-coded here, so not actually
 * secure (since the untrusted host can see in here). 
 */

#include <sgx-lib.h>
#include <polarssl/pk.h>

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

char *quoting_key = "-----BEGIN RSA PRIVATE KEY-----\n"
"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\n"
"-----END RSA PRIVATE KEY-----\n";

void sign_quote(quote_t *q)
{
	pk_context ctx;
	pk_init(&ctx);

	pk_parse_key(&ctx, (unsigned char *)quoting_key, 
		     strlen(quoting_key), NULL, 0);
	rsa_sign(pk_rsa(ctx), (unsigned char *)&q->report, 384,
                 (unsigned char *)q->sig);
	pk_free(&ctx);
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
	copyin(r, report, sizeof(report_t));

	/* Check that the report is actually locally. */
	if (verify_report(report) != 0) {
		goto fail;
	}

	/* Copy the report to the quote */
	memcpy(&q->report, r, sizeof(report_t));

	/* Now sign the quote */
	sign_quote(q);

	/* Copy the signed quote out */
	copyout(quote, q, sizeof(quote_t));
out:
	free(q);
	free(r);
	return;
fail: 
	memset(&quote, -1, sizeof(quote_t));
	goto out;
}
