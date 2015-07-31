// Simple test case using the enclave gate mechanism to launch an enclave
// that actually includes a secret of some sort. It requires an enclave proxy
// running that handles commands enqueue on the gate, because the enclave doesn't
// actually return to user space until it's actually all the easy set up.

#include <sgx-lib.h>
#include <egate.h>

char buffer[2048];
void enclave_main(egate_t *g)
{
	char nonce[64];
	quote_t quote;
	eg_set_default_gate(g);
	/* What encryption is needed along hte way in here to:
	 * 1) Make sure we're talking to the destination we think we are
	 * 2) Get a diffie hellman key from them for later use?
	 */
	eg_printf(g, "Test enclave starting up.\n");

#if 0
	fd = socket(...);
	bind(fd, ...);
	connect(fd, ...
	/* Request the special sekrit, encrypt with destination public key */
	sendto(g, DESTINATION, 
		  "Give me secrets, here's a nonce and initial seqn");
	recvfrom(g, DESTINATION, buffer);

	CHECK_RESPONSE_VALIDITY(buffer, remoteID, seq++);
	if (is_quote_request(buffer)) 
		extract_nonce(buffer, nonce);
#endif
	memset(nonce, 0x41, 64);
	eg_request_quote(g, nonce, &quote);
#if 0
		sendto(fd, g, DESTINATION, quote);
	}

	recvfrom(fd, DESTINATION, sekrit);
	CHECK_RESPONSE(buffer, remoteID, seq++);

	/* If we get here, we have our secret! */
#endif
}
