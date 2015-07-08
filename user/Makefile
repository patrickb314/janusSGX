SGX_LIBS := sgx-entry.o libsgx.a
SGX_RUNTIME := sgx-runtime.o sgx-test-runtime.o
SGX_OBJS := sgx-user.o sgx-elf.o sgx-kern.o sgx-kern-epc.o sgx-utils.o sgx-signature.o 
SSL_OBJS := polarssl/rsa.o polarssl/entropy.o polarssl/ctr_drbg.o \
	polarssl/bignum.o polarssl/md.o polarssl/oid.o polarssl/asn1parse.o polarssl/sha1.o \
	polarssl/sha512.o polarssl/aes.o polarssl/entropy_poll.o polarssl/aesni.o \
	polarssl/timing.o polarssl/md_wrap.o polarssl/sha256.o polarssl/md5.o \
	polarssl/ripemd160.o polarssl/net.o polarssl/aes_cmac128.o
SGX_START=sgx-entry.o
LDLIBS=-lelf
SGX_LDLIBS=-L. -lsgx -lsgxssl -lsgx

CFLAGS := -g -Iinclude -Iopenssl/include -Wall -pedantic -Wno-unused-function -std=gnu11 -fno-stack-protector -static -fPIC -fvisibility=hidden
ASFLAGS := -D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC

BOOTSTRAP_ENCS = bootstrap/launch-enclave.sgx bootstrap/quoting-enclave.sgx \
		 bootstrap/attesting-enclave.sgx

SSL_CRYPTO_OBJS := lib/polarssl/aes.o lib/polarssl/aesni.o  \
	lib/polarssl/aes_cmac128.o lib/polarssl/bignum.o \
	lib/polarssl/rsa.o lib/polarssl/md.o lib/polarssl/md_wrap.o\
	lib/polarssl/sha1.o lib/polarssl/md5.o lib/polarssl/sha256.o \
	lib/polarssl/sha512.o \
	lib/polarssl/oid.o lib/polarssl/asn1parse.o 
LIBSGX_OBJS := $(patsubst %.c,%.o,$(wildcard lib/*.c)) $(SSL_CRYPTO_OBJS)

HDRS := $(wildcard include/sgx*.h)
BINS := $(patsubst %.c,%.sgx,$(wildcard test/*.c)) \
        $(patsubst %.c,%.sgx,$(wildcard demo/*.c)) \
	quote-test launch-test sgx-test 
#bootstrap-test
ALL  := $(BINS) $(BOOTSTRAP_ENCS) sgx-tool

all: $(ALL)

libsgx.a: $(LIBSGX_OBJS)
	$(AR) rs $@ $^

lib/%.o: lib/%.c
	$(CC) -c $(CFLAGS) -o $@ $<

polarssl/%.o: polarssl/%.c
	$(CC) -c  $(CFLAGS) -o $@ $<

%.o: %.c $(HDRS)
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: %.S
	$(CC) -c $(ASFLAGS) -o $@ $<

sgx-tool: sgx-tool.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $^ $(CFLAGS) -o $@ $(LDLIBS)

sgx-test: sgx-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

sgx-%.o: sgx-%.c $(HDRS)
	$(CC)  -c $(CFLAGS) $< -o $@

example1: example1.S
	$(CC) -nostdlib $< -o $@ $(LDLIBS)

test/%.sgx: test/%.o $(SGX_LIBS)
	$(CC) $(CFLAGS) -nostdlib -Wl,-T,sgx.lds $< $(SGX_START) -o $@  $(SGX_LDLIBS) -lgcc

demo/%.sgx: demo/%.o $(SGX_OBJS) $(SGX_LIBS)
	$(CC) $(CFLAGS) -nostdlib -Wl,-T,sgx.lds $< $(SGX_START) -o $@  $(SGX_LDLIBS) -lgcc

bootstrap/%.o: bootstrap/%.c $(HDRS)
	$(CC) -c $(CFLAGS) -o $@ $<

launch-test: launch-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

quote-test: quote-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

bootstrap/%.sgx: bootstrap/%.o $(SGX_OBJS) $(SGX_LIBS) include/quoting-key.h
	$(CC) $(CFLAGS) -nostdlib -Wl,-T,sgx.lds $< -o $@ $(SGX_START) $(SGX_LDLIBS) -lgcc

clean: 
	rm -f polarssl/*.o *.o $(ALL)

.PHONY: polarsslobjs all clean
