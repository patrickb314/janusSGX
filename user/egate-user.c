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

/* Need to add a way for this to use copyin/copyout like semantics */
static int echan_copytouser(echan_t *c, void *dest, size_t len)
{
	int cnt = 0;
	int start = c->start, end = c->end;

	if (start == end) return -1;

	if (len < echan_length_internal(start, end)) return -1;

	cnt = min(len, ECHAN_BUF_SIZE - start);
	/* Copy as much as we need towards the end of hte buffer */
	memcpy(dest, &c->buffer[start], cnt);

	/* And then get ay part left at the start of the buffer */
	if (len - cnt > 0) {
		memcpy((char *)dest+cnt, c->buffer, len - cnt);
	}
	return 0;
}

/* Peek just givesthe command itself */
int echan_user_peek(echan_t *c, ecmd_t *r)
{
	return echan_copytouser(c, r, sizeof(ecmd_t));
}

int egate_user_dequeue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	echan_t *c = &g->channels[ECHAN_TO_USER];
	int ret;

	printf("user-dequeue: channel has start=%d, end=%d.\n", c->start, c->end);

	if (c->start == c->end) {
		r->t = ECMD_NONE;
		r->len = 0;
		return 0;
	}

	ret = echan_user_peek(c, r);
	if (ret) return ret;

	printf("user-dequeue: cmd has type=%d, len=%d.\n", r->t, r->len);

	if (r->len > len) return 0;
	ret = echan_copytouser(c, buf, r->len);
	c->start = roundup2(c->start + sizeof(ecmd_t) + r->len, 8) % ECHAN_BUF_SIZE;
	return ret;
}

int egate_user_cmd(egate_t *g, ecmd_t *r, void *buf, size_t len, int *done)
{
	switch(r->t) {
		case ECMD_PRINT:
			printf("%s", buf);
			return 0;
		case ECMD_EXIT:
			*done = 1;
			return 0;
		case ECMD_NONE:
			return 0;
		default:
			return -1;
	}
	return 0;
}

int egate_init(egate_t *g, tcs_t *tcs)
{
	g->tcs = tcs;
	echan_init(&g->channels[ECHAN_TO_ENCLAVE]);
	echan_init(&g->channels[ECHAN_TO_USER]);
	return 0;
}
