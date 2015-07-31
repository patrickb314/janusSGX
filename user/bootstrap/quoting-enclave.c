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

char *quoting_key = "-----BEGIN PRIVATE KEY-----\n"
"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANz3dKRct1i5Zdty\n"
"njID/t2VdJEQNlUZ4SH4TYypDSs//eTheYskPIXIshW4ynstTeHN2iZEdF4qqFTJ\n"
"4IcrYgtK5wF6eMiLNSw78UWjObJZ9W830cRWJJNDzDnfvPkLE4F53r+IcumHb8nf\n"
"E9W/qwz4LqKpZ5srZbQRmdosy9HhAgMBAAECgYEAhZBWQxt///Ng7DrmAJmFru6u\n"
"HRlNnjccbGoohgORYDk4AOeBjmeC5eMgMh0W10nVL848NLFgHaNvSIEWZN4GTmlN\n"
"G9QqZmUSZpKNKFeIlsmRtL413v3cKCfA0wm9xuQKFmJr8cyMQwDmJLNVxmbX+6YX\n"
"WMwo9QMtqPadt5cEIdkCQQD5Amg+Qp+gZWzi1XUxo6Ow04Uu0w7xyPLZ8KmrXUZ3\n"
"X2fkAiY3Qp4UcDS4eER7/rsJ5arsYCxEtcC7LDACUH+DAkEA4yuCXPYZ7Y8w1Xwp\n"
"itJ3IVRHovNGfJjnEtRExbGzaxMlR2tge+Q8Ud1piIJnmp2BT/ayNOGveN/f3wZ/\n"
"jGNnywJAS7trsOPaYJH4V9TL29kFA9aQ/vi55tdS5O3I7JFlyRB/LF1q+guMwHKP\n"
"1jrduUhz4kKzhUiKrisI/uQlhc6tuQJAAVaGRAnnCTEotnkuvXST4wxeB6WrKpyz\n"
"77Z0WT28ssrAE3Wccd5cRJcrQfSSq6R12IS5c/pIUEvxQ50EL01+lQJACnARLTmm\n"
"EPAjYgpzMaI1y/jjoJsYuW32T9Ai2fCS6KyGtFtk+Z/ptO1gJPMQNDhLz351QKRT\n"
"TxHQ0wmh08tb9Q==\n"
"-----END PRIVATE KEY-----";
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
