SGX_RUNTIME := sgx-runtime.o sgx-test-runtime.o
SGX_OBJS := sgx-user.o sgx-elf.o sgx-kern.o sgx-kern-epc.o sgx-utils.o sgx-signature.o egate-user.o
SSL_OBJS := polarssl/rsa.o polarssl/entropy.o polarssl/ctr_drbg.o \
	polarssl/bignum.o polarssl/md.o polarssl/oid.o polarssl/asn1parse.o polarssl/sha1.o \
	polarssl/sha512.o polarssl/aes.o polarssl/entropy_poll.o polarssl/aesni.o \
	polarssl/timing.o polarssl/md_wrap.o polarssl/sha256.o polarssl/md5.o \
	polarssl/ripemd160.o polarssl/net.o polarssl/aes_cmac128.o
SGX_START=$(LIBSGXDIR)/sgx-entry.o
OPENSGX = ../opensgx
LDLIBS=-lelf

LIBSGXDIR=../libsgx
SGX_LDLIBS=-L. -L$(LIBSGXDIR) -lsgx -lpolarssl -lsgx
SGX_LIBS=$(LIBSGXDIR)/libpolarssl.a $(LIBSGXDIR)/libsgx.a $(LIBSGXDIR)/sgx-entry.o 

BASE_CFLAGS := -g -Iinclude -Wall -pedantic -Wno-unused-function -std=gnu11 
CFLAGS := $(BASE_CFLAGS)
ENC_CFLAGS := $(BASE_CFLAGS) -I$(LIBSGXDIR)/include -fno-stack-protector -static -fPIC -fvisibility=hidden
ENC_ASFLAGS := -D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC -g
ENC_LDFLAGS = -static -nostdlib -Wl,-T,sgx.lds

BOOTSTRAP_ENCS = bootstrap/launch-enclave.sgx bootstrap/launch-enclave.conf \
		 bootstrap/quoting-enclave.sgx bootstrap/quoting-enclave.conf \
		 bootstrap/attesting-enclave.sgx bootstrap/attesting-enclave.conf \
		bootstrap/test-enclave.sgx bootstrap/test-enclave.conf

HDRS := $(wildcard include/sgx*.h)
BINS := $(patsubst %.c,%.sgx,$(wildcard test/*.c)) \
        $(patsubst %.c,%.sgx,$(wildcard demo/*.c)) \
	launch-test sgx-test generate-launch bootstrap-test \
	egate-proxy
ALL  := $(BINS) $(BOOTSTRAP_ENCS) sgx-tool

all: $(ALL)

libsgx.a: $(LIBSGX_OBJS)
	$(AR) rs $@ $^

polarssl/%.o: polarssl/%.c
	$(CC) -c  $(CFLAGS) -o $@ $<

%.o: %.c $(HDRS)
	$(CC) -c $(CFLAGS) -o $@ $<

sgx-tool: sgx-tool.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $^ $(CFLAGS) -o $@ $(LDLIBS)

sgx-test: sgx-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

egate-proxy: egate-proxy.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

sgx-%.o: sgx-%.c $(HDRS)
	$(CC)  -c $(CFLAGS) $< -o $@

test/%.o: test/%.c
	$(CC) -c $(ENC_CFLAGS) -o $@ $<

demo/%.o: demo/%.c
	$(CC) -c $(ENC_CFLAGS) -o $@ $<

bootstrap/%.o: bootstrap/%.c $(HDRS)
	$(CC) -c $(ENC_CFLAGS) -o $@ $<

test/%.sgx: test/%.o $(SGX_LIBS)
	$(CC) $(ENC_LDFLAGS) $< $(SGX_START) -o $@  $(SGX_LDLIBS) -lgcc

demo/%.sgx: demo/%.o $(SGX_OBJS) $(SGX_LIBS)
	$(CC) $(ENC_LDFLAGS) $< $(SGX_START) -o $@  $(SGX_LDLIBS) -lgcc

bootstrap/%.sgx: bootstrap/%.o $(SGX_OBJS) $(SGX_LIBS)
	$(CC) $(ENC_LDFLAGS) $< $(SGX_START) -o $@  $(SGX_LDLIBS) -lgcc

bootstrap/launch-enclave.conf: bootstrap/launch-enclave.sgx sgx-tool
	$(OPENSGX) -s $< -I

bootstrap/quoting-enclave.conf: bootstrap/quoting-enclave.sgx sgx-tool
	$(OPENSGX) -s $< -I

bootstrap/%.conf: bootstrap/%.sgx $(SGXTOOL)
	$(OPENSGX) -s $^ --key ../sign.key

launch-test: launch-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

quote-test: quote-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

generate-launch: generate-launch.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

bootstrap-test: bootstrap-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

clean: 
	rm -f polarssl/*.o *.o $(ALL)

.PHONY: polarsslobjs all clean
