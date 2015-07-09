#ifndef _EGATE_H_
#define _EGATE_H_

typedef struct ecmd ecmd_t;
typedef struct echan echan_t;
typedef struct egate egate_t;


enum echan_type {ECHAN_TO_ENCLAVE = 0, ECHAN_TO_USER};
enum ecmd_type {ECMD_NONE = 0, ECMD_REPORT_REQ, ECMD_RECV, ECMD_SEND, ECMD_PRINT, ECMD_EXIT};
typedef enum echan_type echan_type_t;
typedef enum ecmd_type ecmd_type_t;

#define ECMD_FIRST_FROM_USER ECMD_REPORT_REQ
#define ECMD_LAST_FROM_USER EMD_RECV
#define ECMD_FIRST_FROM_ENC ECMD_SEND
#define ECMD_LAST_FROM_ENC ECMD_EXIT
#define ECMD_LAST_SYSTEM ECMD_LAST_FROM_ENC

struct ecmd {
	ecmd_type_t t;
	size_t len; 
};

#define ECHAN_BUF_SIZE 2048
struct echan {
	int start, end;
	char buffer[ECHAN_BUF_SIZE];
};

struct egate {
	tcs_t *tcs;
	echan_t channels[2];
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

int egate_init(egate_t *, tcs_t *);

int egate_user_peek(egate_t *, ecmd_t *);
int egate_user_dequeue(egate_t *, ecmd_t *, void *buf, size_t len);
int egate_user_enqueue(egate_t *, ecmd_t *, void *buf, size_t len);

int egate_user_cmd(egate_t *, ecmd_t *, void *buf, size_t len, int *done);
void *egate_thread(void *arg);	/* Function to run an encalve in a gate until done. */

int egate_enclave_peek(egate_t *, ecmd_t *);
int egate_enclave_dequeue(egate_t *, ecmd_t *, void *buf, size_t len);
int egate_enclave_enqueue(egate_t *, ecmd_t *, void *buf, size_t len);

int egate_enclave_cmd(egate_t *, ecmd_t *, void *buf, size_t len, int *done);

int eg_printf(egate_t *, char *, ...);
int eg_exit(egate_t *, int);

#endif /* _EGATE_H_ */
