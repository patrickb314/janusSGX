#include <sgx.h>
#include <sgx-lib.h>
#include <egate.h>
#include <stdarg.h>

/* We always work with a local copy of the enclave via copyin/copyout
 * to avoid any silly business racing with the user code (which we can't
 * trust synchronization with). XXX PGB We do have to worry about the user code 
 * running us with multiple TCSes and handing the same gate to different TCSes,
 * to get us to race with ourselves, corrupt the gate, and expose secrets; for now
 * we assume there's only one TCS in the enclave but we will need some form 
 * of enclave/enclave mutual exclusion here at some point.
 */

static inline int roundup2(int x, int y) {
	return (x + y - 1) & ~(y-1);
}

static inline int min(int a, int b)
{
	return a < b ? a : b;
}


static int echan_copytoenclave(echan_t *c, int start, void *dest, size_t len)
{
        int cnt = 0;
        int end = c->end;

        if (start == end) return -1;

        cnt = min(len, ECHAN_BUF_SIZE - start);
        /* Copy as much as we need towards the end of hte buffer */
        copyin(dest, &c->buffer[start], cnt);

        /* And then get ay part left at the start of the buffer */
        if (len - cnt > 0) {
                copyin((char *)dest+cnt, c->buffer, len - cnt);
        }
        return 0;
}

static int echan_copyfromenclave(echan_t *c, int end, void *src, size_t len)
{
	int cnt = 0;
	void *retp;

	end = end % ECHAN_BUF_SIZE;

	cnt = min(len, ECHAN_BUF_SIZE - end);
	/* Copy as much as we need towards the end of hte buffer */
	retp = copyout(&c->buffer[end], src, cnt);
	if (!retp) return -1;

	/* And then get ay part left at the start of the buffer */
	if (len - cnt > 0) {
		retp = copyout(c->buffer, (char *)src+cnt, len - cnt);
		if (!retp) return -1;
	}

	return 0;
}

/* Peek just gives the command itself */
int echan_enclave_peek(echan_t *c, ecmd_t *r)
{
        return echan_copytoenclave(c, c->start, r, sizeof(ecmd_t));
}

int egate_enclave_enqueue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	echan_t *c = g->channels[ECHAN_TO_USER];
	int start = c->start, end = c->end;
	int ret;

	if (r->len > len) return -1;

	if ((ECHAN_BUF_SIZE - echan_length_internal(start, end)) 
	    < (sizeof(ecmd_t) + r->len)) return -1;

	ret = echan_copyfromenclave(c, end, r, sizeof(ecmd_t));
	if (ret) return ret;
	end = (end + sizeof(ecmd_t)) % ECHAN_BUF_SIZE;

	ret = echan_copyfromenclave(c, end, buf, r->len);
	if (ret) return ret;
	end = roundup2((end + r->len), 8) % ECHAN_BUF_SIZE;

	/* XXX need a memory barrier here, though since hte copy is in a function
	 * call that hopefully isn't optimized away, we could be okay for now. */
	c->end = end;
	return 0;
}

int egate_enclave_dequeue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
        echan_t *c = g->channels[ECHAN_TO_USER];
        int ret, start, end;

        start = c->start;
	end = c->end;
        if (start == end) {
                r->t = ECMD_NONE;
                r->len = 0;
                return 0;
        }

        ret = echan_enclave_peek(c, r);
        if (ret) return ret;

        if (r->len > len) return 0;

        /* Now we know we actually have the space to dequeue the full command,
         * so get the data as well and then increment start by the full
         * amount */
        start += sizeof(ecmd_t);
        ret = echan_copytoenclave(c, start, buf, r->len);
        c->start = roundup2(start + r->len, 8) % ECHAN_BUF_SIZE;

        return ret;
}


int egate_enclave_cmd(egate_t *g, ecmd_t *r, void *buf, size_t len, int *done)
{
	switch(r->t) {
		default:
			return -1;
	}
	return 0;
}

int eg_console_write(egate_t *g, char *buf, int len)
{
	ecmd_t c;
	int ret;

	c.t = ECMD_CONS_WRITE;
	c.len = len; // +1 for trailing null
	ret = egate_enclave_enqueue(g, &c, buf, 512);
	if (ret) return -1;
	
	return len;
}

int eg_printf(egate_t *g, char *fmt, ...)
{
	va_list args;
	char buf[256];
	int len;

	va_start(args, fmt);
	len = vsnprintf(buf, 256, fmt, args);
	va_end(args);
	if (!len) return 0;
	return eg_console_write(g, buf, len + 1);
}

int eg_exit(egate_t *g, int val)
{
	ecmd_t c;
	c.t = ECMD_DONE;
	c.len = sizeof(int);
	egate_enclave_enqueue(g, &c, &val, sizeof(int));
	sgx_exit();
	return 0; /*NOTREACHED*/
}

static egate_t *default_gate;

int eg_set_default_gate(egate_t *g)
{
	default_gate = g;
	return 0;
}

