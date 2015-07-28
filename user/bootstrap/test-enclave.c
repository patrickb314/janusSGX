// Simple test case using the enclave gate mechanism to launch an enclave
// that actually includes a secret of some sort. It requires an enclave proxy
// running that handles commands enqueue on the gate, because the enclave doesn't
// actually return to user space until it's actually all the easy set up.

#include <sgx-lib.h>
#include <egate.h>

char buffer[4096];
void enclave_main(egate_t *g)
{
	/* What encryption is needed along hte way in here to:
	 * 1) Make sure we're talking to the destination we think we are
	 * 2) Get a diffie hellman key from them for later use?
	 */
	eg_printf(g, "Test enclave starting up.\n");

#if 0
	/* Request the special sekrit, encrypt with destination public key */
	eg_sendto(g, DESTINATION, 
		  "Give me secrets, here's a nonce and initial seqn");
	eg_recvfrom(g, DESTINATION, buffer);

	CHECK_RESPONSE_VALIDITY(buffer, remoteID, seq++);

	if (is_quote_request(buffer)) 
		
		extract_nonse(buffer, nonce);
		eg_quote_request(g, extracbuffer);
		eg_quote_recv(g, quote);
		eg_sendto(g, DESTINATION, quote);
	}

	eg_recvfrom(g, DESTINATION, sekrit);
	CHECK_RESPONSE(buffer, remoteID, seq++);

	/* If we get here, we have our secret */
#endif
}
