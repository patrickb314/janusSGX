LIBSGX_OBJS = base.o malloc.o egate-enclave.o crypto.o snprintf.o
BASE_CFLAGS = -g -Iinclude -I../user/include -Wall -pedantic -Wno-unused-function -std=gnu11
ENC_CFLAGS = -fno-stack-protector -static -fPIC -fvisibility=hidden
CFLAGS = $(BASE_CFLAGS) $(ENC_CFLAGS)
ASFLAGS = -D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC
all: libpolarssl-enc.a libsgx.a sgx-entry.o
TOP=$(PWD)
libsgx.a: $(LIBSGX_OBJS)
	$(AR) rs $@ $^

clean: 
	rm -rf libpolarssl-enc.a include/polarssl $(LIBSGX_OBJS)

$(LIBSGX_OBJS): libpolarssl-enc.a

libpolarssl-enc.a: mbedtls-config-libsgx.h
	CFLAGS="-g $(ENC_CFLAGS) -I$(TOP) -DPOLARSSL_CONFIG_FILE='<mbedtls-config-libsgx.h>'" make -C ../mbedtls SHARED=1 clean lib
	rm -rf include/polarssl
	mkdir -p include
	cp -r ../mbedtls/include/polarssl include/
	cp mbedtls-config-libsgx.h include/polarssl/config.h
	cp ../mbedtls/library/libpolarssl.a ./libpolarssl-enc.a
