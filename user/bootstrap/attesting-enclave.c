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
	memcpy(&t, dest_enc, sizeof(targetinfo_t));
	memcpy(n, nonce, 64);

	/* Generate a report for the target enclave */
	sgx_report(&t, n, &r);

	/* Copy out the generated report. Should we check that 
	 * report is *not* in this enclave? Basically, do we need a
	 * proper copyout? Probably we should check this; otherwise
	 * user space could give us an address here to try and get
	 * us to corrupt ourself? */
	memcpy(report, &r, sizeof(report_t));
	return;
}
