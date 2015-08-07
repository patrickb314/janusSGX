// EGate networking test

#include "test.h"
#include <sgx-lib.h>
#include <egate.h>

#include <errno.h>
#include <unistd.h>

void enclave_main(egate_t *g)
{
	char *host = "www.cs.unm.edu";
	char *port = "80";
	struct addrinfo hints, *addr_list, *cur;
	int fd = -1;
	eg_set_default_gate(g);
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if ( getaddrinfo(host, port, &hints, &addr_list) ) {
		printf("Getaddrinfo for %s:%s failed.\n", host, port);
	} else {
		printf("Getaddrinfo for %s:%s succeeded.\n", host, port);
	}
	
	for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
		fd = socket(cur->ai_family, cur->ai_socktype, 
			    cur->ai_protocol);
		if (fd < 0) {
			printf("socket() failed %d.\n", errno);
		} else {
			printf("socket() succeeded %d.\n", fd);
		}

		if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
			printf("connect() succeeded for %d.\n", fd);
			break;
		} else {
			printf("connect() failed %d.\n", errno);
		}
	}
	if (fd > 0) {
		ret = write(fd, "GET ~bridges/index.html\n", 24);
		printf("Write %d bytes to fd %d.\n", ret, fd);
		do {
			char lbuf[1024];
			printf("Reading up to 1024 bytes from %d.\n", fd);
			ret = read(fd, lbuf, 1024);
			printf("read returned %d.\n", ret);
			if (ret > 0) {
				printf("%s", lbuf);
			}
		} while(ret > 0);
	}
}
