#ifndef _EGATE_H_
#define _EGATE_H_

typedef struct ecmd ecmd_t;
typedef struct echan echan_t;
typedef struct egate egate_t;


enum echan_type {ECHAN_TOENCLAVE = 0, ECHAN_FROMENCLAVE};
enum ecmd_type {ECMD_REPORT_REQ = 0, ECMD_RECV, ECMD_SEND, ECMD_PRINT};
typedef enum echan_type echan_type_t;
typedef enum ecmd_type ecmd_type_t;

#define ECMD_LAST_TOENC EMD_RECV
#define ECMD_LAST_FROMENC ECMD_PRINT
#define ECMD_LAST_SYSTEM ECMD_LAST_FROMENC

struct ecmd {
	ecmd_type_t t;
	int len; 
};

#define ECHAN_BUF_SIZE 2048
struct echan {
	int cstart, cend;
	long buffer[ECHAN_BUF_SIZE];
};

struct egate {
	tcs_t *tcs;
	echan_t channels[2];
};

int egate_init(egate_t *, tcs_t *tcs, int ntcs);
int egate_peek(egate_t *, ecmd_t *);
int egate_dequeue(egate_t *, ecmd_t *, void *buf, int len, echan_type_t dir);
int egate_enqueue(egate_t *, ecmd_t *);
int egate_handle_cmd(egate_t *, ecmd_t *, void *buf, int len, int *done);
void *egate_thread(void *arg);	/* Function to run an encalve in a gate until done. */

#endif /* _EGATE_H_ */
