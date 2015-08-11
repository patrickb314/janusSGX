/* Simple test case using the enclave gate mechanism to launch an enclave
 * that actually includes a secret of some sort. It requires an enclave proxy
 * running that handles commands enqueue on the gate, because the enclave doesn't
 * actually return to user space until it's actually all the easy set up.
 * - Derived from mbed TLS 1.3.11 dh_client.c, GPL 2.0, by ARM Inc.
 */

#include <sgx-lib.h>
#include <egate.h>

#include <polarssl/net.h>
#include <polarssl/aes.h>
#include <polarssl/dhm.h>
#include <polarssl/pk.h>
#include <polarssl/rsa.h>
#include <polarssl/sha1.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

char *provisioner_hostname = "localhost";
int provisioner_port = 11298;
/* XXX PGB Put a key in, dummy. */
char *provisioner_key = "";

int setup_connection(egate_t *g, int *pfd, 
		     entropy_context *entropy, ctr_drbg_context *ctr_drbg,
		     rsa_context *rsa)
{
	const char *pers = "Enclave Client.\n";
	pk_context pk;
	int ret = 0;

	memset(&pk, 0, sizeof(pk));
	/* Set up random number generation */
	eg_printf(g, "ENCLAVE: Seeding the random number generator.\n");
	enclave_entropy_init(entropy);
	ret = ctr_drbg_init( ctr_drbg, entropy_func, &entropy,
                             (const unsigned char *) pers,
                             strlen( pers ) );
	if (ret != 0) {
        	eg_printf(g, "ENCLAVE FAIL (%d): Could not initialize RNG.\n", ret);
        	goto exit;
    	}
	/* Import the server's public key */
	eg_printf(g, "ENCLAVE: Importing the provisioning server's public key.\n");

	pk_init(&pk);
        ret = pk_parse_key(&pk, (unsigned char *)provisioner_key,
                           strlen(provisioner_key), NULL, 0);
	if (ret != 0 ) {
        	eg_printf(g, "ENCLAVE FAIL (%d): Could not parse RSA key RNG.\n", ret);
        	goto exit;
	}
	rsa_copy(rsa, pk_rsa(pk));

	eg_printf(g, "ENCLAVE: Connecting to provisioning server %s:%d.\n", 
		  provisioner_hostname, provisioner_port);
	ret = net_connect(pfd, provisioner_hostname, provisioner_port);
	if (ret != 0) {
		eg_printf(g, "ENCLAVE FAIL (%d): Could not connect to provisioner.\n", ret);
		goto exit;
	}
exit:
	pk_free(&pk);
	return ret;
}

/* This routine does a diffie helman key exchange with the server, wrapping some of 
 * the exchange with the SGX quoting process to establish our identity as the 
 * appropriate signed enclave at the same time. The "nonce" we get from the server 
 * in SGX remote attestation speak is his diffie hellman parameters. The manifest 
 * we send back includes includes his parameters (so he knows he's talking not 
 * being replayed) and our diffie hellman parameters. The quote includes a hash of 
 * this manifest, as well as our MR_ENCLAVE info signed by the processor with the
 * Intel quoting key. */
int exchange_dhm_quote(egate_t *g, int fd, ctr_drbg_context *ctr_drbg, 
		       rsa_context *rsa, dhm_context *dhm)
{
	size_t n, buflen;
	unsigned char *p, *end;
	unsigned char buf[2048];
	unsigned char hash[64]; // hash only uses 20!
	unsigned char tmp[16];
	int manifest_len = 0;
	int ret = 0;
	quote_t q;
	memset(&q, 0, sizeof(q));
	memset(hash, 0, 64);
	dhm_init( dhm );

	eg_printf(g, "ENCLAVE: Receiving diffie-hellman paramters from server.\n");

	memset(buf, 0, sizeof(buf));
	ret = net_recv( &fd, buf, 2 );
	if ( ret != 2 ) {
		ret = -1;
        	eg_printf(g, "ENCLAVE FAIL: net_recv returned %d unexpectedly.\n", ret);
        	goto exit;
	}

	n = buflen = ( buf[0] << 8 ) | buf[1];
	if( buflen < 1 || buflen > sizeof( buf ) ) {
		eg_printf(g, "ENCLAVE FAIL: Got an invalid buffer length %d.\n", buflen );
		goto exit;
	}

	memset( buf, 0, sizeof( buf ) );
	ret = net_recv( &fd, buf, n);
	if( ret !=  n ) {
		ret = -1;
        	eg_printf(g, "ENCLAVE FAIL: net_recv returned %d unexpectedly.\n", ret);
        	goto exit;
    	}
	p = buf, end = buf + buflen;

	ret = dhm_read_params( dhm, &p, end );
	if (ret != 0 ) {
		eg_printf(g, "ENCLAVE FAIL(%d): dhm_read_params failed\n", ret );
		goto exit;
	}

	if( dhm->len < 64 || dhm->len > 512 ) {
        	ret = 1;
		eg_printf(g, "ENCLAVE FAIL: invalid DHM modulus size %d\n", dhm->len );
        	goto exit;
    	}
	manifest_len = buflen + dhm->len;

	eg_printf(g, "ENCLAVE: Verifying the server's RSA signature\n");
	p += 2;
	n = (size_t)(end - p);
	if( n != rsa->len ) {
        	ret = 1;
        	eg_printf(g, "ENCLAVE FAIL: Invalid RSA signature size %d\n", n);
        	goto exit;
    	}

    	sha1( buf, (int)( p - 2 - buf ), hash );

    	ret = rsa_pkcs1_verify( rsa, NULL, NULL, RSA_PUBLIC, POLARSSL_MD_SHA256, 
				0, hash, p ); 
	if (ret != 0 ) {
        	eg_printf(g,  "ENCLAVE FAIL(%d): rsa_pkcs1_verify failed.\n", ret );
        	goto exit;
    	}

	eg_printf(g, "ENCLAVE: Creating DHM public key\n");
	/* Now create our own diffie helman parameters into the buf as well, wiping
	 * out the old key sent by the server */ 
	ret = dhm_make_public( dhm, (int)dhm->len, buf + manifest_len - dhm->len, dhm->len,
			       ctr_drbg_random, ctr_drbg);
	if (!ret) {
        	eg_printf(g,  "ENCLAVE FAIL(%d): dhm_make_public failed.\n", ret );
        	goto exit;
	}

	eg_printf(g, "ENCLAVE: Getting quote with public key information\n");
	/* Now create a quote using the hash of the manifest (both sides DH info) 
	 * as contents */
    	sha1( buf, manifest_len, hash );

	ret = eg_request_quote(g, hash, &q);
	if (!ret) {
        	eg_printf(g,  "ENCLAVE FAIL(%d): failed to get quote.\n", ret );
        	goto exit;
	}

	eg_printf(g, "ENCLAVE: Sending manifest and quote back to server.\n");
	tmp[0] = (unsigned char) ((manifest_len >> 8) & 0xff);
	tmp[1] = (unsigned char) (manifest_len  & 0xff );
	ret = net_send(&fd, tmp, 2);
	if (ret != 2) {
		ret = -1;
        	eg_printf(g, "ENCLAVE FAIL: net_recv returned %d unexpectedly.\n", ret);
		goto exit;
	}

	ret = net_send(&fd, buf, manifest_len);
	if (ret != manifest_len) {
		ret = -1;
        	eg_printf(g, "ENCLAVE FAIL: net_recv returned %d unexpectedly.\n", ret);
		goto exit;
	}

	tmp[0] = (unsigned char) ((sizeof(quote_t) >> 8) & 0xff);
	tmp[1] = (unsigned char) (sizeof(quote_t) & 0xff);
	ret = net_send(&fd, tmp, 2);
	if (ret != 2) {
		ret = -1;
        	eg_printf(g, "ENCLAVE FAIL: net_recv returned %d unexpectedly.\n", ret);
		goto exit;
	}
	ret = net_send(&fd, (unsigned char *)&q, sizeof(quote_t));
	if (ret != sizeof(quote_t)) {
		ret = -1;
        	eg_printf(g, "ENCLAVE FAIL: net_recv returned %d unexpectedly.\n", ret);
		goto exit;
	}

exit:
	return ret;
}

int setup_aes_key(egate_t *g, int fd, ctr_drbg_context *ctr_drbg, 
		  dhm_context *dhm, aes_context *aes)
{
	size_t n;
	int ret = 0;
	aes_init(aes);
	unsigned char buf[2048];

	eg_printf(g, "ENCLAVE: Seting up AES channel using DES public key\n");
	n = dhm->len;
	ret = dhm_calc_secret( dhm, buf, &n, ctr_drbg_random, ctr_drbg );
	if (ret) {
        	eg_printf(g, "ENCLAVE_FAIL(%d): ghm_calc_secret failed.]\n", ret);
        	goto exit;
    	}

        /* This is an overly simplified example; best practice is
         * to hash the shared secret with a random value to derive
         * the keying material for the encryption/decryption keys,
         * IVs and MACs. */
	aes_setkey_dec(aes, buf, 256);

exit:
	return ret;
}

void enclave_main(egate_t *g)
{
	int ret = -1, fd = -1;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	rsa_context rsa;
	dhm_context dhm;
	aes_context aes;
	unsigned char buf[32];

	/* Zero out the ssl contexts so they free properly if there's an
	 * error */
	memset(&entropy, 0, sizeof(entropy));
	memset(&ctr_drbg, 0, sizeof(ctr_drbg));
	memset(&rsa, 0, sizeof(rsa));
	memset(&dhm, 0, sizeof(dhm));
	memset(&aes, 0, sizeof(aes));

	/* egate_enclave_init(g); */
	eg_set_default_gate(g);

	/* Set up the basic connection info, including the reading and initializing
	 * basic cryptography information such as the RNG and server RSA key */
	ret = setup_connection(g, &fd, &entropy, &ctr_drbg, &rsa);
	if (ret) goto exit;
	
	ret = exchange_dhm_quote(g, fd, &ctr_drbg, &rsa, &dhm);
	if (ret) goto exit;

	ret = setup_aes_key(g, fd, &ctr_drbg, &dhm, &aes);
	if (ret) goto exit;

	/* Now we have an AES key generated from the shared diffie-hellman secret, and
	 * the remote knows we're a proper enclave. Let's see what the secret is! */
	eg_printf(g, "ENCLAVE: Receiving secret from provisioner.\n");
	ret = net_recv(&fd, buf, 16);
	aes_crypt_ecb( &aes, AES_DECRYPT, buf, buf );
    	buf[16] = '\0';
	eg_printf(g, "ENCLAVE: I know something you don't know.\n");

exit:
	if( fd != -1 ) net_close( fd );
    	aes_free( &aes );
    	dhm_free( &dhm );
	rsa_free( &rsa);
    	ctr_drbg_free( &ctr_drbg );
    	entropy_free( &entropy );

	eg_exit(g, 0);
}
