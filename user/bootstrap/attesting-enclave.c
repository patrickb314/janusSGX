/* A minimal enclave that creates a report for local then remote
 * attestation. */

#include <sgx-lib.h>

void enclave_main(targetinfo_t *dest_enc, unsigned char *nonce, 
		  report_t *report)
{
	targetinfo_t t;
	unsigned char n[64];
	report_t r;

	memset(report, 2, sizeof(report_t));
	memset(&r, -1, sizeof(report_t));

	/* Copy arguments from user space into enclave space. 
	 * EREPORT requires that all arguments be in this enclave. */
	copyin(&t, dest_enc, sizeof(targetinfo_t));
	copyin(n, nonce, 64);

	/* Generate a report for the target enclave */
	sgx_report(&t, n, &r);

	copyout(report, &r, sizeof(report_t));
	return;
}
