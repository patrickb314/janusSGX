SGX_LIBS := sgx-entry.o libsgx.a libsgxssl.a
SGX_RUNTIME := sgx-runtime.o sgx-test-runtime.o
SGX_OBJS := sgx-user.o sgx-kern.o sgx-kern-epc.o sgx-utils.o sgx-signature.o 
SSL_OBJS := polarssl/rsa.o polarssl/entropy.o polarssl/ctr_drbg.o \
	polarssl/bignum.o polarssl/md.o polarssl/oid.o polarssl/asn1parse.o polarssl/sha1.o \
	polarssl/sha512.o polarssl/aes.o polarssl/entropy_poll.o polarssl/aesni.o \
	polarssl/timing.o polarssl/md_wrap.o polarssl/sha256.o polarssl/md5.o \
	polarssl/ripemd160.o polarssl/net.o polarssl/aes_cmac128.o

LIBSGX_OBJS := lib/sgxlib_base.o lib/sgxlib_crypto.o lib/sgxlib_malloc.o
SGX_START=sgx-entry.o
SGX_LDLIBS=-L. -lsgx -lsgxssl -lsgx

CFLAGS := -g -Iinclude -Iopenssl/include -Wall -pedantic -Wno-unused-function -std=gnu11 -fno-stack-protector -static -fPIC -fvisibility=hidden
ASFLAGS := -D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC

BOOTSTRAP_BINS = bootstrap/bootstrap-launch.sgx

#bootstrap-quote bootstrap-test

HDRS := $(wildcard include/sgx*.h)
BINS := $(patsubst %.c,%.sgx,$(wildcard test/*.c)) \
	$(patsubst %.c,%.sgx,$(wildcard test2/*.c)) \
        $(patsubst %.c,%.sgx,$(wildcard demo/*.c)) \
	sgx-mmap-runtime
ALL  := $(BINS) sgx-tool

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
	$(CC) $^ $(CFLAGS) -o $@

sgx-%.o: sgx-%.c $(HDRS)
	$(CC)  -c $(CFLAGS) $< -o $@

example1: example1.S
	$(CC) -nostdlib $< -o $@ $(LDLIBS)

test/%.sgx: test/%.o $(SGX_LIBS)
	$(CC) $(CFLAGS) -nostartfiles -Wl,-T,sgx2.lds $< $(SGX_START) -o $@  $(SGX_LDLIBS)

demo/%.sgx: demo/%.o $(SGX_OBJS) $(SSL_OBJS) $(SGX_LIBS)
	$(CC) $(CFLAGS) -nostartfiles -Wl,-T,sgx2.lds $< $(SGX_START) -o $@  $(SGX_LDLIBS)

bootstrap/%.o: bootstrap/%.c $(HDRS)
	$(CC) -c $(CFLAGS) -o $@ $<

bootstrap/launch-enclave.sgx: bootstrap/launch_enclave.o $(SGX_OBJS) $(SSL_OBJS) $(SGX_LIBS)
	$(CC) $(CFLAGS) -nostartfiles -Wl,-T,sgx2.lds $< -o $@ $(SGX_START) $(SGX_LDLIBS)

bootstrap-quote/quoting-enclave.sgx: bootstrap/quoting_enclave.o $(SGX_OBJS) $(SSL_OBJS) $(SGX_LIBS)
	$(CC) $(CFLAGS) -nostartfiles -Wl,-T,sgx2.lds $< -o $@ $(SGX_START) $(SGX_LDLIBS)

sgx-mmap-runtime: sgx-mmap-runtime.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lelf

clean: 
	rm -f polarssl/*.o *.o $(ALL)

.PHONY: polarsslobjs all clean
