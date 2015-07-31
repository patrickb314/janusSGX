#ifndef _EGATE_H_
#define _EGATE_H_

typedef struct ecmd ecmd_t;
typedef struct echan echan_t;
typedef struct egate egate_t;


enum echan_type {ECHAN_TO_ENCLAVE = 0, ECHAN_TO_USER};
enum ecmd_type {ECMD_NONE = 0, 
		/* From user to enclave */
		ECMD_REPORT_REQ, 
		ECMD_QUOTE_RESP, 
		ECMD_SOCK_OPEN_RESP, 
		ECMD_SOCK_CLOSE_RESP,
		ECMD_SOCK_BIND_RESP,
		ECMD_SOCK_CONNECT_RESP,
		ECMD_SOCK_ACCEPT_RESP,
		ECMD_SOCK_SEND_RESP, 
		ECMD_SOCK_RECV_RESP, 
		ECMD_CONS_READ_RESP,
		/* From enclave to user */
		ECMD_REPORT_RESP, 
		ECMD_QUOTE_REQ, 
		ECMD_SOCK_OPEN_REQ, 
		ECMD_SOCK_CLOSE_REQ,
		ECMD_SOCK_BIND_REQ,
		ECMD_SOCK_CONNECT_REQ,
		ECMD_SOCK_ACCEPT_REQ,
		ECMD_SOCK_SEND_REQ, 
		ECMD_SOCK_RECV_REQ, 
		ECMD_CONS_READ_REQ,
		ECMD_CONS_WRITE, 
		ECMD_DONE};
typedef enum echan_type echan_type_t;
typedef enum ecmd_type ecmd_type_t;

#define ECMD_FIRST_FROM_USER ECMD_REPORT_REQ
#define ECMD_LAST_FROM_USER EMD_CONS_READ_RESP
#define ECMD_FIRST_FROM_ENC (ECMD_LAST_FROM_USER + 1)
#define ECMD_LAST_FROM_ENC ECMD_DONE
#define ECMD_LAST_SYSTEM ECMD_LAST_FROM_ENC
#define ECMD_NUM ECMD_LAST_SYSTEM+1

struct ecmd {
	ecmd_type_t t;
	unsigned int val;
	size_t len; 
};

#define ECHAN_BUF_SIZE 2040
struct echan {
	int start, end;
	char buffer[ECHAN_BUF_SIZE];
};

struct egate {
	tcs_t *tcs;
	tcs_t *quotetcs;
	sigstruct_t *quotesig;
	echan_t *channels[2];
};

static inline int echan_length_internal(int start, int end)
{
        if (end >= start)
                return end - start;
        else
                return end + ECHAN_BUF_SIZE - start;
}
static inline int echan_length(echan_t *c) {
        return echan_length_internal(c->start, c->end);
}

int echan_init(echan_t *);
int egate_user_init(egate_t *, tcs_t *, echan_t *channels[2]);
int egate_proxy_init(egate_t *, tcs_t *, sigstruct_t *, echan_t *channels[2]);

int egate_user_peek(egate_t *, ecmd_t *);
int egate_user_dequeue(egate_t *, ecmd_t *, void *buf, size_t len);
int egate_user_poll(egate_t *g, ecmd_t *r, void *buf, size_t len);
int egate_user_enqueue(egate_t *, ecmd_t *, void *buf, size_t len);

int egate_user_cmd(egate_t *, ecmd_t *, void *buf, size_t len, int *done);
void *egate_thread(void *arg);	/* Function to run an encalve in a gate until done. */

int egate_enclave_peek(egate_t *, ecmd_t *);
int egate_enclave_dequeue(egate_t *, ecmd_t *, void *buf, size_t len);
int egate_enclave_enqueue(egate_t *, ecmd_t *, void *buf, size_t len);

int egate_enclave_cmd(egate_t *, ecmd_t *, void *buf, size_t len, int *done);

int eg_printf(egate_t *, char *, ...);
int eg_exit(egate_t *, int);

int eg_request_quote(egate_t *, char nonce[64], quote_t *);
int eg_set_default_gate(egate_t *g);

#endif /* _EGATE_H_ */
