#include <sgx.h>
#include <sgx-user.h>
#include <egate.h>

#include <errno.h>
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
	start += sizeof(ecmd_t);
	if (r->len) {
		ret = echan_copytouser(c, start, buf, r->len);
	}
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
	struct addrinfo *ai;
	struct sockaddr *sa;
	int fd = -1, err = 0, ret = -1;
	/* COmmand contains a struct addrinfo and a struct sockaddr_XXX with
	 * length in the struct addrinfo */
	if (len < sizeof(struct addrinfo)) {
		err = EINVAL;
		goto done;
	}

	ai = buf;
	if (len < (sizeof(struct addrinfo) + ai->ai_addrlen)) {
		err = EINVAL;
		goto done;
	}

	sa = (struct sockaddr *)((char *)buf + sizeof(struct addrinfo));
	fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (fd < 0) {
		err = errno;
		goto done;
	}
	
	ret = connect(fd, sa, ai->ai_addrlen);
	if (ret) {
		err = errno;
	}

done:
	/* Write the response back to the caller */
	resp.t = ECMD_SOCK_OPEN_RESP;
	resp.len = 0;
	if (!err) {
		resp.val = fd;
	} else {
		resp.val = -err;
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
	resp.t = ECMD_SOCK_CLOSE_RESP;;
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
	return 0;
}

int egate_user_sock_connect(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	return 0;
}

int egate_user_sock_accept(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	return 0;
}

int egate_user_sock_send(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	return 0;
}

int egate_user_sock_recv(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	return 0;
}

ENCCALL2(request_quote, report_t *, quote_t *)

/* Here we need to call the quoting enclave */
int egate_user_quote(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	/* The user has requested a quote. First we request he issue a
	 * report for the quoting enclave */
	ecmd_t c;
	char buffer[2048];
	targetinfo_t t;
	report_t rpt;
	quote_t qt;

	if (!g->quotetcs) return -1;
	if (!g->quotesig) return -1;

	memset(&t, 0, sizeof(targetinfo_t));
        memcpy(&t.measurement, &g->quotesig->enclaveHash, 32);
        t.attributes = g->quotesig->attributes;
        t.miscselect = g->quotesig->miscselect;
	memcpy(buffer, &t, sizeof(targetinfo_t));
        memset(buffer+sizeof(targetinfo_t), 0x3b, 64);
	
	c.t = ECMD_REPORT_REQ;
	c.len = sizeof(targetinfo_t) + 64;
	egate_user_enqueue(g, &c, buffer, sizeof(targetinfo_t) + 64);

	/* Now we should dequeue a REPORT_RESP */
	egate_user_poll(g, &c, buffer, 2048);
	if (c.t != ECMD_REPORT_RESP) {
		return -1;
	}
	memcpy(&rpt, buffer, sizeof(report_t));

	/* So we have a report. Get it signed. */
	request_quote(g->quotetcs, exception_handler, &rpt, &qt);
	c.t = ECMD_QUOTE_RESP;
	c.len = sizeof(quote_t);
	memcpy(buffer, &qt, sizeof(quote_t));

	egate_user_enqueue(g, &c, buffer, sizeof(quote_t));
	return 0;
}

int egate_user_cons_write(egate_t *g, ecmd_t *r, void *buf, size_t len)
{
	printf("%s", (char *)buf);
	return 0;
}

typedef int (*req_handler_t)(egate_t *, ecmd_t *, void *buf, size_t len);

req_handler_t dispatch[ECMD_NUM] = { 
	[ECMD_CONS_WRITE] = egate_user_cons_write,
	[ECMD_SOCK_OPEN_REQ] = egate_user_sock_open,
	[ECMD_SOCK_CLOSE_REQ] = egate_user_sock_close,
	[ECMD_SOCK_BIND_REQ] = egate_user_sock_bind,
	[ECMD_SOCK_CONNECT_REQ] = egate_user_sock_connect,
	[ECMD_SOCK_ACCEPT_REQ] = egate_user_sock_accept,
	[ECMD_SOCK_SEND_REQ] = egate_user_sock_send,
	[ECMD_SOCK_RECV_REQ] = egate_user_sock_recv,
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
int egate_user_init(egate_t *g, tcs_t *tcs, echan_t *channels[2])
{
	g->tcs = tcs;
	g->quotetcs = NULL;
	g->quotesig = NULL;
	g->channels[0] = channels[0];
	g->channels[1] = channels[1];
	return 0;
}
