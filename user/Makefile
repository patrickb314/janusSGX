TOP=$(PWD)
BASE_CFLAGS := -g -Iinclude -Wall -pedantic -Wno-unused-function -std=gnu11 

# Host code/tool build information
CFLAGS := $(BASE_CFLAGS)
SGX_RUNTIME := sgx-runtime.o sgx-test-runtime.o
SGX_OBJS := sgx-user.o sgx-elf.o sgx-kern.o sgx-kern-epc.o sgx-utils.o sgx-signature.o egate-user.o
SSL_OBJS := libpolarssl-user.a
#polarssl/rsa.o polarssl/entropy.o polarssl/ctr_drbg.o \
#	polarssl/bignum.o polarssl/md.o polarssl/oid.o polarssl/asn1parse.o polarssl/sha1.o \
#	polarssl/sha512.o polarssl/aes.o polarssl/entropy_poll.o polarssl/aesni.o \
#	polarssl/timing.o polarssl/md_wrap.o polarssl/sha256.o polarssl/md5.o \
#	polarssl/ripemd160.o polarssl/net.o polarssl/aes_cmac128.o
OPENSGX = ../opensgx
LDLIBS=-L. -lpolarssl-user -lelf

# Enclave code build information
LIBSGXDIR=../libsgx
ENC_CFLAGS=$(BASE_CFLAGS) -I$(LIBSGXDIR)/include -fno-stack-protector -static -fPIC -fvisibility=hidden
ENC_ASFLAGS=-D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC -g
ENC_LDFLAGS=-static -nostdlib -Wl,-T,sgx.lds
SGX_START=$(LIBSGXDIR)/sgx-entry.o
SGX_LDLIBS=-L$(LIBSGXDIR) -lsgx -lpolarssl-enc -lsgx
SGX_LIBS=$(LIBSGXDIR)/libpolarssl-enc.a $(LIBSGXDIR)/libsgx.a $(LIBSGXDIR)/sgx-entry.o 


BOOTSTRAP_ENCS = bootstrap/launch-enclave.sgx bootstrap/launch-enclave.conf \
		 bootstrap/quoting-enclave.sgx bootstrap/quoting-enclave.conf \
		 bootstrap/attesting-enclave.sgx bootstrap/attesting-enclave.conf \
		 bootstrap/test-enclave.sgx bootstrap/test-enclave.conf

HDRS := $(wildcard include/sgx*.h)
BINS := $(patsubst %.c,%.sgx,$(wildcard test/*.c)) \
        $(patsubst %.c,%.sgx,$(wildcard demo/*.c)) \
	launch-test sgx-test generate-launch egate-test \
	bootstrap-server \
	egate-proxy
ALL  := $(BINS) $(BOOTSTRAP_ENCS) sgx-tool

all: $(ALL)

libpolarssl-user.a: mbedtls-config-sgxusr.h
	CFLAGS="-g $(CFLAGS) -I$(TOP) -DPOLARSSL_CONFIG_FILE='<mbedtls-config-sgxusr.h>'" make -C ../mbedtls SHARED=1 clean lib
	rm -rf include/polarssl
	mkdir -p include
	cp -r ../mbedtls/include/polarssl include/
	cp mbedtls-config-sgxusr.h include/polarssl/config.h
	cp ../mbedtls/library/libpolarssl.a ./libpolarssl-user.a

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
	$(OPENSGX) -s $^ --key conf/test.key

launch-test: launch-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

quote-test: quote-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

generate-launch: generate-launch.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

egate-test: egate-test.o $(SGX_OBJS) $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean: 
	rm -f polarssl/*.o *.o $(ALL)

.PHONY: polarsslobjs all clean
