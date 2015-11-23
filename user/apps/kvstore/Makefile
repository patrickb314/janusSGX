BASE=../
include $(BASE)/Makefile.header

PROGRAMS = kvstore_server kvstore_server_sgx kvstore_client

kvstore_server_SRC = kvstore_server.c
kvstore_server_CFLAGS = -I/$(LIBSGXDIR)/include
kvstore_server_LDFLAGS = $(OSGXOBJS) -L$(USERSGXDIR) -lpolarssl-user -lelf

kvstore_server_sgx_SRC = kvstore_server_sgx.c
kvstore_server_sgx_LDFLAGS = -L$O/libut -lut

kvstore_client_SRC = kvstore_client.c kvstore_client_dhm.c
kvstore_client_CFLAGS = -I/$(LIBSGXDIR)/include
kvstore_client_LDFLAGS = -L$(USERSGXDIR) -lpolarssl-user

include $(BASE)/Makefile.footer
