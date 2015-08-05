#include <errno.h>
#include <sgx.h>
#include <sgx-lib.h>
#include <egate.h>
#include <signal.h>
#include <stdarg.h>

/* We always work with a local copy of the enclave via copyin/copyout
 * to avoid any silly business racing with the user code (which we can't
 * trust synchronization with). XXX PGB We do have to worry about the user code 
 * running us with multiple TCSes and handing the same gate to different TCSes,
 * to get us to race with ourselves, corrupt the gate, and expose secrets; for now
 * we assume there's only one TCS in the enclave but we will need some form 
 * of enclave/enclave mutual exclusion here at some point.
 * 
 * In addition, a lot of this is exchanges that are really best characterized
 * as a FSM - writing them as such to get error/reset handling *provably* right
 * would be a really good thing to do.
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
	end = roundup2(end + sizeof(ecmd_t), 8) % ECHAN_BUF_SIZE;

	if (r->len) {
		ret = echan_copyfromenclave(c, end, buf, r->len);
		if (ret) return ret;
	}
	end = roundup2(end + r->len, 8) % ECHAN_BUF_SIZE;

	/* XXX need a memory barrier here, though since hte copy is in a function
	 * call that hopefully isn't optimized away, we could be okay for now. */
	c->end = end;
	return 0;
}

int egate_enclave_dequeue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
        echan_t *c = g->channels[ECHAN_TO_ENCLAVE];
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

int egate_enclave_poll(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
        do {
                int ret;
                ret = egate_enclave_dequeue(g, r, buf, len);
                if (ret) return ret;
        } while (r->t == ECMD_NONE);
        return 0;
}

int eg_console_write(egate_t *g, char *buf, int len)
{
	ecmd_t c;
	int ret;

	c.t = ECMD_CONS_WRITE;
	c.len = len;
	do {
	    ret = egate_enclave_enqueue(g, &c, buf, len);
	} while (ret < 0);

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

void eg_exit(egate_t *g, int val) 
{
	if (g) {
		ecmd_t c;
		c.t = ECMD_DONE;
		c.val = val;
		c.len = 0;
		egate_enclave_enqueue(g, &c, NULL, 0);
	}
	sgx_exit();
	exit(val); /*NOTREACHED - suppresses noreturn warning*/
}

/* Send when we get an unexpected response to a request. Should either be ignored
 * other side or cause them to fail out of whatever they were trying to do */
int egate_enclave_reset(egate_t *g)
{
	ecmd_t c;
	c.t = ECMD_RESET;
	c.len = 0;
	egate_enclave_enqueue(g, &c, 0, 0);
	return 0;
}

int egate_enclave_error(egate_t *g, char *msg)
{
	/* Reset the proxy if it was waiting on anything from us */
	egate_enclave_reset(g);
	/* Then send it a message to print */
	eg_console_write(g, msg, strlen(msg) + 1);
	return 0;
}

int eg_request_quote(egate_t *g, char nonce[64], quote_t *q)
{
	ecmd_t c;
	int ret;
	char lbuf[ECHAN_REQ_LIMIT];
	report_t r;
	/* Request a quote */
	c.t = ECMD_QUOTE_REQ;
	c.len = 64;
	egate_enclave_enqueue(g, &c, nonce, 64);

	ret = egate_enclave_poll(g, &c, lbuf, sizeof(targetinfo_t) + 64);
	if (ret || c.t != ECMD_REPORT_REQ 
	    || c.len != (sizeof(targetinfo_t) + 64)
	    || memcmp(nonce, lbuf + sizeof(targetinfo_t), 64)) {
		egate_enclave_error(g, "Invalid report request received.");
		return -1;
	}
	sgx_report(lbuf, lbuf+sizeof(targetinfo_t), &r);

	c.t = ECMD_REPORT_RESP;
	c.len = sizeof(report_t);
	egate_enclave_enqueue(g, &c, &r, sizeof(report_t));

	ret = egate_enclave_poll(g, &c, lbuf, sizeof(quote_t));
	if (ret || c.t != ECMD_QUOTE_RESP 
	    || c.len != sizeof(quote_t)
	    || memcmp( ((quote_t *)lbuf)->report.reportData, nonce, 64)) {
		egate_enclave_error(g, "Invalid quote reponse received.");
		return -1;
	}
	memcpy(q, lbuf, sizeof(quote_t));
	return 0;
}

/* UNIX Stub calls */
static egate_t *default_gate;

/* And now UNIX API versions of the calls above that use the default gate */
int eg_set_default_gate(egate_t *g)
{
	default_gate = g;
	return 0;
}

#define DEFAULT_GATE_CHECK { if (!default_gate) return -1; /*SET ERRNO*/ }
#define DEFINE_UNIX_STUB1(name, t1, v1) \
    int name(t1 v1) \
    { \
	DEFAULT_GATE_CHECK \
	return eg_##name(default_gate, v1);\
    }\
    int eg_##name(egate_t *g, t1 v1)

#define DEFINE_UNIX_STUB3(name, t1, v1, t2, v2, t3, v3) \
    int name(t1 v1, t2 v2, t3 v3) \
    { \
	DEFAULT_GATE_CHECK \
	return eg_##name(default_gate, v1, v2, v3);\
    }\
    int eg_##name(egate_t *g, t1 v1, t2 v2, t3 v3)

DEFINE_UNIX_STUB3(socket, int, domain, int, type, int, protocol)
{
	ecmd_t c;
	int ret;
	int lbuf[12];

	c.t = ECMD_SOCK_OPEN_REQ;
	*(int *)(lbuf) = domain;
	*(int *)(lbuf + 4) = type;
	*(int *)(lbuf + 8) = protocol;
	c.len = 12;
	egate_enclave_enqueue(g, &c, lbuf, 12);
	ret = egate_enclave_poll(g, &c, NULL, 0);
	if (ret || (c.t != ECMD_SOCK_OPEN_RESP) || c.len != 0) {
		egate_enclave_error(g, "Invalid socket response received.");
		errno = EINVAL;
		return -1;
	}
	if (c.val < 0) {
		errno = -c.val;
		return -1;
	}
	errno = 0;
	return c.val;
}

DEFINE_UNIX_STUB3(bind, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)
{
	ecmd_t c;
	int ret;
	if (addrlen > ECHAN_REQ_LIMIT) return -1;
	c.t = ECMD_SOCK_BIND_REQ;
	c.val = sockfd;
	c.len = addrlen;
	egate_enclave_enqueue(g, &c, (void *)addr, addrlen);
	ret = egate_enclave_poll(g, &c, NULL, 0);
	if (ret || (c.t != ECMD_SOCK_BIND_RESP) || c.len != 0) {
		egate_enclave_error(g, "Invalid bind response received.");
		errno = EINVAL;
		return -1;
	}
	if (c.val < 0) {
		errno = -c.val;
		return -1;
	}
	errno = 0;
	return 0;
}

DEFINE_UNIX_STUB3(accept, int, sockfd, struct sockaddr *, addr, socklen_t *, addrlen)
{
	ecmd_t c;
	int ret;
	if (!addrlen || *addrlen > ECHAN_REQ_LIMIT) {
		errno = EINVAL;
		return -1;
	}
	c.t = ECMD_SOCK_ACCEPT_REQ;
	c.val = sockfd;
	c.len = 0;
	egate_enclave_enqueue(g, &c, NULL, 0);
	ret = egate_enclave_poll(g, &c, addr, *addrlen);
	if (ret || (c.t != ECMD_SOCK_ACCEPT_RESP)) {
		egate_enclave_error(g, "Invalid accept response received.");
		return -1;
	}
	if (c.val < 0) {
		errno = -c.val;
		return -1;
	}
	errno = 0;
	*addrlen = c.len;
	return c.val;
}

DEFINE_UNIX_STUB1(close, int, fd)
{
	ecmd_t c;
	int ret;

	c.t = ECMD_SOCK_CLOSE_REQ;
	c.val = fd;
	c.len = 0;
	egate_enclave_enqueue(g, &c, NULL, 0);

	ret = egate_enclave_poll(g, &c, NULL, 0);
	if (ret || (c.t != ECMD_SOCK_CLOSE_RESP)) {
		egate_enclave_error(g, "Invalid close response received.");
		return -1;
	}
	if (c.val < 0) {
		errno = c.val;
		return -1;
	}
	errno = 0;
	return 0;
}

DEFINE_UNIX_STUB3(connect, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)
{
	ecmd_t c;
	int ret;
	if (addrlen > ECHAN_REQ_LIMIT) return -1;
	c.t = ECMD_SOCK_CONNECT_REQ;
	c.val = sockfd;
	c.len = addrlen;
	egate_enclave_enqueue(g, &c, (void *)addr, addrlen);
	ret = egate_enclave_poll(g, &c, NULL, 0);
	if (ret || (c.t != ECMD_SOCK_CONNECT_RESP) || c.len != 0) {
		egate_enclave_error(g, "Invalid connect response received.");
		errno = EINVAL;
		return -1;
	}
	if (c.val < 0) {
		errno = -c.val;
		return -1;
	}
	errno = 0;
	return c.val;
}
/*
	TODO:
                 U __errno_location
                 U fcntl
                 U freeaddrinfo
                 U getaddrinfo
                 U listen
                 U read
                 U setsockopt
                 U shutdown
                 U write
*/
typedef void (*sighandler_t)(int);
sighandler_t signal(int sig, sighandler_t h)
{
	return SIG_ERR;
}

void exit(int val)
{
	eg_exit(default_gate, val);
	exit(val); /*NOTREACHED - suppresses noreturn warning*/
}
