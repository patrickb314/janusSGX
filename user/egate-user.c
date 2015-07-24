#include <sgx.h>
#include <egate.h>

static inline int roundup2(int x, int y) {
	return (x + y - 1) & ~(y-1);
}

static inline int min(int a, int b)
{
	return a < b ? a : b;
}

/* For now, we assume only a single producer/consumer on both sides. Multiple
 * producers on the user side could result in corrupted data being moved, but
 * not corrupting the enclave code or leaking enclave data */
int echan_init(echan_t *c)
{
	c->start = c->end = 0;
	return 0;
}

static int echan_copyfromuser(echan_t *c, int end, void *src, size_t len)
{
        int cnt = 0;
        void *retp;

        end = end % ECHAN_BUF_SIZE;

        cnt = min(len, ECHAN_BUF_SIZE - end);
        /* Copy as much as we need towards the end of the buffer */
        retp = memcpy(&c->buffer[end], src, cnt);
        if (!retp) return -1;

        /* And then get ay part left at the start of the buffer */
        if (len - cnt > 0) {
                retp = memcpy(c->buffer, (char *)src+cnt, len - cnt);
                if (!retp) return -1;
        }

        return 0;
}

/* Need to add a way for this to use copyin/copyout like semantics */
static int echan_copytouser(echan_t *c, int start, void *dest, size_t len)
{
	int cnt = 0;
	int end = c->end;

	if (start == end) return -1;

	cnt = min(len, ECHAN_BUF_SIZE - start);
	/* Copy as much as we need towards the end of hte buffer */
	memcpy(dest, &c->buffer[start], cnt);

	/* And then get ay part left at the start of the buffer */
	if (len - cnt > 0) {
		memcpy((char *)dest+cnt, c->buffer, len - cnt);
	}
	return 0;
}

/* Peek just gives the command itself */
int echan_user_peek(echan_t *c, ecmd_t *r)
{
	return echan_copytouser(c, c->start, r, sizeof(ecmd_t));
}

int egate_user_dequeue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	echan_t *c = g->channels[ECHAN_TO_USER];
	int ret, start;

	start = c->start;
	if (start == c->end) {
		r->t = ECMD_NONE;
		r->len = 0;
		return 0;
	}

	ret = echan_user_peek(c, r);
	if (ret) return ret;

	if (r->len > len) return 0;

	/* Now we know we actually have the space to dequeue the full command, 
	 * so get the data as well and then increment start by the full 
	 * amount */
	start += sizeof(ecmd_t);
	ret = echan_copytouser(c, start, buf, r->len);
	c->start = roundup2(start + r->len, 8) % ECHAN_BUF_SIZE;
	
	return ret;
}

int egate_user_enqueue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
        echan_t *c = g->channels[ECHAN_TO_USER];
        int start = c->start, end = c->end;
        int ret;

        if (r->len > len) return -1;

        if ((ECHAN_BUF_SIZE - echan_length_internal(start, end))
            < (sizeof(ecmd_t) + r->len)) return -1;

        ret = echan_copyfromuser(c, end, r, sizeof(ecmd_t));
        if (ret) return ret;
        end = (end + sizeof(ecmd_t)) % ECHAN_BUF_SIZE;

        ret = echan_copyfromuser(c, end, buf, r->len);
        if (ret) return ret;
        end = roundup2((end + r->len), 8) % ECHAN_BUF_SIZE;

        /* XXX need a memory barrier here, though since hte copy is in a function
         * call that hopefully isn't optimized away, we could be okay for now. */
        c->end = end;
        return 0;
}

int egate_user_cmd(egate_t *g, ecmd_t *r, void *buf, size_t len, int *done)
{
	switch(r->t) {
		case ECMD_PRINT:
			printf("%s", buf);
			return 0;
		case ECMD_DONE:
			*done = 1;
			return 0;
		case ECMD_NONE:
			return 0;
		default:
			return -1;
	}
	return 0;
}

int egate_init(egate_t *g, tcs_t *tcs, echan_t *channels[2])
{
	g->tcs = tcs;
	g->channels[0] = channels[0];
	g->channels[1] = channels[1];
	return 0;
}
