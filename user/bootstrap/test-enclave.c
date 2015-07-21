// Simple test case using the enclave gate mechanism

#include <sgx-lib.h>
#include <egate.h>

/* This is basically a finite state machine that is in one of 
 * a few startup states, or processing requests. Ideally, this would
 * be running in a separate thread and just exchanging info over the 
 * enclave gate, but we qemu user code doesn't support multi-threading
 * right now, so we just let the main thread keep pinging doing the main
 * loop */

enum bootstrap_state {BS_UNINIT = 0, BS_QUOTING, BS_PROVISIONED, BS_INITED};
bsst_t state = BSST_UNINIT;

void enclave_main(egate_t *g)
{
	switch (state) {
	case BS_UNINIT:
		/* We start by communicating with a remote who will
		 * give us //sekrits// 
		 */
		eg_sendto(DESTINATION, "Enclave starting up.\n");
		state = BS_STARTUP;
		break;
	case BS_STARTUP:
		/* We get the info we need from the remote, and now
		 * request a quote using the diffie hellman nonce it 
		 * provides */
		eg_recvfrom(DESTINATION, buffer);
		eg_quote_request(buffer);
		break;
	case BS_QUOTING:
		/* We've requested a quote and we're waiting for 
	         * a response. Once we get it, send it to our 
		 * destination, which should actually give us what
		 * we need to set up a TLS channel */
		eg_quote_response(quote);
		eg_sendto(DESTINATION, quote);
		
		break;	
	case BS_COMMUNICATING:
		/* We have a communication channel with the remote
		 * set up, awaiting it to provision secrets to us */
		eg_recvfrom(DESTINATION, sekrit);
		break;
	case BS_INITED:
	}
}
