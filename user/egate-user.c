#include <sgx.h>
#include <sgx-user.h>
#include <egate.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

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

int egate_user_poll(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	do {
		int ret;
		ret = egate_user_dequeue(g, r, buf, len);
		if (ret) return ret;
	} while (r->t == ECMD_NONE);
	return 0;
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
	start += roundup2(sizeof(ecmd_t), 8);
	if (r->len) {
		ret = echan_copytouser(c, start, buf, r->len);
	}
	c->start = roundup2(start + r->len, 8) % ECHAN_BUF_SIZE;
	
	return ret;
}

int egate_user_enqueue(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
        echan_t *c = g->channels[ECHAN_TO_ENCLAVE];
        int start = c->start, end = c->end;
        int ret;

        if (r->len > len) return -1;

        if ((ECHAN_BUF_SIZE - echan_length_internal(start, end))
            < (sizeof(ecmd_t) + r->len)) return -1;

        ret = echan_copyfromuser(c, end, r, sizeof(ecmd_t));
        if (ret) return ret;
        end = roundup2(end + sizeof(ecmd_t), 8) % ECHAN_BUF_SIZE;

	if (r->len) {
        	ret = echan_copyfromuser(c, end, buf, r->len);
        	if (ret) return ret;
        	end = roundup2(end + r->len, 8) % ECHAN_BUF_SIZE;
	}

        /* XXX need a memory barrier here, though since hte copy is in a function
         * call that hopefully isn't optimized away, we could be okay for now. */
        c->end = end;
        return 0;
}

int egate_user_sock_open(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	ecmd_t resp;
	int fd = -1;
	int family, type, protocol;

	if (len != 3*sizeof(int)) {
		errno = EINVAL;
		goto done;
	}
	family = ((int *)buf)[0];
	type = ((int *)buf)[1];
	protocol = ((int *)buf)[2];

	fd = socket(family, type, protocol);
done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_OPEN_RESP;
	resp.len = 0;
	if (fd < 0) {
		resp.val = -errno;
	} else {
		resp.val = fd;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	
	return 0;
}

int egate_user_sock_close(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int ret;
	ecmd_t resp;

	ret = close(r->val);
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_CLOSE_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	
	return 0;
}

int egate_user_sock_shutdown(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int how = 0;
	int ret = 0;
	ecmd_t resp;
	if (r->len != sizeof(int)) {
		ret = -1; 
		errno = EINVAL;
		goto done;
	}
	how = *(int *)buf;
	ret = shutdown(sock, how);
done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_SHUTDOWN_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	return 0;
}

int egate_user_sock_bind(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int llen = r->len;
	struct sockaddr *sa = buf;
	ecmd_t resp;

	int ret = bind(sock, sa, llen);

	resp.t = ECMD_SOCK_BIND_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	
	return 0;
}

int egate_user_sock_accept(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	char lbuf[ECHAN_REQ_LIMIT];
	socklen_t llen = ECHAN_REQ_LIMIT;
	ecmd_t resp;

	int ret = accept(sock, (struct sockaddr *)lbuf, &llen);
	
	resp.t = ECMD_SOCK_ACCEPT_RESP;
	resp.len = llen;
	if (ret >= 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, lbuf, llen);

	return 0;
}

int egate_user_sock_connect(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	return 0;
	int sock = r->val;
	int llen = r->len;
	struct sockaddr *sa = buf;
	ecmd_t resp;

	int ret = connect(sock, sa, llen);
	resp.t = ECMD_SOCK_CONNECT_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	
	return 0;
}

int egate_user_sock_listen(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int backlog = 0;
	int ret = 0;
	ecmd_t resp;

	if (r->len != sizeof(int)) {
		ret = -1; 
		errno = EINVAL;
		goto done;
	}
	backlog = *(int *)buf;
	ret = listen(sock, backlog);
done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_LISTEN_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	return 0;
}

#ifndef MIN
#define MIN(a, b) (a) > (b) ? (a) : (b)
#endif

int egate_user_sock_read(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int ret = 0;
	char lbuf[ECHAN_REQ_LIMIT];
	size_t readlen;
	ecmd_t resp;

	if (r->len != sizeof(size_t)) {
		ret = -1; 
		errno = EINVAL;
		goto done;
	}
	readlen = *(size_t *)buf;
	readlen = MIN(readlen, ECHAN_REQ_LIMIT);
	ret = read(sock, lbuf, readlen);
done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_READ_RESP;
	resp.len = 0;
	if (ret >= 0) {
		resp.val = ret;
		resp.len = ret;
	} else {
		resp.val = -errno;
		resp.len = 0;
	}
	egate_user_enqueue(g, &resp, lbuf, resp.len);
	return 0;
}

int egate_user_sock_write(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int ret = 0;
	ecmd_t resp;

	ret = write(sock, buf, len);

	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_WRITE_RESP;
	resp.len = 0;
	if (ret >= 0) {
		resp.val = ret;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	return 0;
}

int egate_user_sock_setopt(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int level = 0;
	int optname = 0;
	char *opt;
	socklen_t optlen = 0;
	int ret = 0;
	ecmd_t resp;

	if (r->len < sizeof(level) + sizeof(optname)) {
		ret = -1; 
		errno = EINVAL;
		goto done;
	}

	level = *(int *)buf;
	optname = *(int *)((char *)buf + sizeof(level));
	optlen = len - sizeof(level) - sizeof(optname);
	opt = (char *)buf + sizeof(level) + sizeof(optlen);

	ret = setsockopt(sock, level, optname, opt, optlen);
done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_SETOPT_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	return 0;
}

int egate_user_sock_fcntl(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int sock = r->val;
	int cmd = 0;
	int optarg = 0;
	int ret = 0;
	ecmd_t resp;

	if (r->len != sizeof(cmd) + sizeof(optarg)) {
		ret = -1; 
		errno = EINVAL;
		goto done;
	}

	cmd = *(int *)buf;
	optarg = *(int *)((char *)buf + sizeof(cmd));

	ret = fcntl(sock, cmd, optarg);
done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_FCNTL_RESP;
	resp.len = 0;
	if (ret == 0) {
		resp.val = 0;
	} else {
		resp.val = -errno;
	}
	egate_user_enqueue(g, &resp, NULL, 0);
	return 0;
}

int pack_addrinfo(struct addrinfo *ai, char *lbuf, int *len)
{
	char *p = lbuf;
	while (ai) {
		struct addrinfo *ai_pack;
		struct sockaddr *sa_pack;
		char *cname_pack;
		int cname_len;

		memcpy(p, ai, sizeof(struct addrinfo));
		ai_pack = (struct addrinfo *)p;
		p += sizeof(struct addrinfo);

		memcpy(p, ai->ai_addr, ai->ai_addrlen);
		sa_pack = (struct sockaddr *)p;
		p += ai->ai_addrlen;

		cname_len = strlen(ai->ai_canonname) + 1;
		memcpy(p, ai->ai_canonname, cname_len);
		cname_pack = (char *)p;
		p += cname_len;

		ai_pack->ai_addr = (struct sockaddr *)(size_t)((char *)sa_pack - (char *)ai_pack);
		ai_pack->ai_canonname = (char *)(size_t)((char *)cname_pack - (char *)ai_pack);
		if (ai->ai_next) {
			ai_pack->ai_next = (struct addrinfo *)(size_t)(p - (char *)ai_pack);
		} else {
			ai_pack->ai_next = 0;
		}
		ai = ai->ai_next;
	}
	*len = p - lbuf;
	return 0;
}

int egate_user_getaddrinfo(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	int nl = 0, sl = 0, rl = 0;
	struct addrinfo *hint; 
	char *p, *node, *service;
	struct addrinfo *res = NULL;
	char lbuf[ECHAN_REQ_LIMIT];
	int ret = -1;
	ecmd_t resp;

	if (r->len < sizeof(int) + sizeof(int) + sizeof(struct addrinfo)) {
		ret = -1; 
		errno = EINVAL;
		goto done;
	}
	p = buf;
	nl = *(int *)p;
	p += sizeof(int);
	sl = *(int *)p;
	p += sizeof(int);
	node = p;
	p += nl;
	service = p;
	p += sl;
	hint = (struct addrinfo *)p;

	ret = getaddrinfo(node, service, hint, &res);
	rl = ECHAN_REQ_LIMIT;
	if (ret || pack_addrinfo(res, lbuf, &rl)) {
		ret = -1;
		errno = EINVAL;
		goto done;
	}

done:
	if (res) freeaddrinfo(res);
	res = NULL;
	resp.t = ECMD_GETADDRINFO_RESP;
	if (ret) {
		resp.val = -errno;
		resp.len = 0;
	} else {
		resp.val = 0;
		resp.len = rl;
	}
	egate_user_enqueue(g, &resp, lbuf, rl);
	
	return 0;
}

int egate_user_request_report(egate_t *g, targetinfo_t *t, char buf[64], report_t *r)
{
	char lbuf[ECHAN_REQ_LIMIT];
	ecmd_t c;
	c.t = ECMD_REPORT_REQ;
	c.len = sizeof(targetinfo_t) + 64;
	memcpy(lbuf, t, sizeof(targetinfo_t));
        memcpy(lbuf+sizeof(targetinfo_t), buf, 64);
	egate_user_enqueue(g, &c, lbuf, sizeof(targetinfo_t) + 64);

	/* Now we should dequeue a REPORT_RESP */
	egate_user_poll(g, &c, lbuf, ECHAN_REQ_LIMIT);
	if (c.t != ECMD_REPORT_RESP) {
		return -1;
	}
	if (c.len != sizeof(report_t)) {
		return -1;
	}

	memcpy(r, lbuf, sizeof(report_t));

	return 0;
}

ENCCALL2(request_quote, report_t *, quote_t *)

/* Here we need to call the quoting enclave */
int egate_user_quote(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	targetinfo_t t;
	report_t rpt;
	quote_t qt;
	ecmd_t c;
	int ret;

	if (!g->quotetcs) return -1;
	if (!g->quotesig) return -1;
	if (r->len != 64) return -1;

	/* The user has requested a quote. The nonce is provided. */
	memset(&t, 0, sizeof(targetinfo_t));
        memcpy(&t.measurement, &g->quotesig->enclaveHash, 32);
        t.attributes = g->quotesig->attributes;
        t.miscselect = g->quotesig->miscselect;
	ret = egate_user_request_report(g, &t, buf, &rpt);
	if (ret) return ret;

	/* So we have a report. Get it signed. */
	request_quote(g->quotetcs, exception_handler, &rpt, &qt);

	/* Now send the resulting request back */
	c.t = ECMD_QUOTE_RESP;
	c.len = sizeof(quote_t);
	egate_user_enqueue(g, &c, &qt, sizeof(quote_t));

	return 0;
}

int egate_user_cons_write(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	printf("%s", (char *)buf);
	return 0;
}

int egate_user_reset(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	printf("Reset received from enclave.\n");
	return 0;
}

typedef int (*req_handler_t)(egate_t *, ecmd_t *, void *buf, size_t len);

req_handler_t dispatch[ECMD_NUM] = { 
	[ECMD_RESET] = egate_user_reset,
	[ECMD_CONS_WRITE] = egate_user_cons_write,
	[ECMD_SOCK_OPEN_REQ] = egate_user_sock_open,
	[ECMD_SOCK_CLOSE_REQ] = egate_user_sock_close,
	[ECMD_SOCK_SHUTDOWN_REQ] = egate_user_sock_shutdown,
	[ECMD_SOCK_BIND_REQ] = egate_user_sock_bind,
	[ECMD_SOCK_CONNECT_REQ] = egate_user_sock_connect,
	[ECMD_SOCK_ACCEPT_REQ] = egate_user_sock_accept,
	[ECMD_SOCK_LISTEN_REQ] = egate_user_sock_listen,
	[ECMD_SOCK_READ_REQ] = egate_user_sock_read,
	[ECMD_SOCK_WRITE_REQ] = egate_user_sock_write,
	[ECMD_SOCK_WRITE_REQ] = egate_user_sock_setopt,
	[ECMD_SOCK_WRITE_REQ] = egate_user_sock_fcntl,
	[ECMD_GETADDRINFO_REQ] = egate_user_getaddrinfo,
	[ECMD_QUOTE_REQ] = egate_user_quote,
};

int egate_user_cmd(egate_t *g, ecmd_t *r, void *buf, size_t len, int *done)
{
	req_handler_t f;

	if (r->t > ECMD_LAST_SYSTEM) {
		return -1;
	}

	if (r->t == ECMD_DONE) {
		*done = 1;
		return 0;
	}

 	f = dispatch[r->t];

	if (f) {
		return f(g, r, buf, len);
	} else {
		return -1;
	}
}

/* This is called in the proxy */
int egate_proxy_init(egate_t *g, tcs_t *qtcs, sigstruct_t *qss, 
		     echan_t *channels[2])
{
	g->tcs = NULL;
	g->quotetcs = qtcs;
	g->quotesig = qss;
	g->channels[0] = channels[0];
	g->channels[1] = channels[1];
	return 0;
}

/* This is called in the program that sets up the egate and launches the
 * enclave */
int egate_user_init(egate_t *g, tcs_t *utcs, echan_t *channels[2])
{
	g->tcs = utcs;
	g->quotetcs = NULL;
	g->quotesig = NULL;
	g->channels[0] = channels[0];
	g->channels[1] = channels[1];
	return 0;
}
