LIBSGX_OBJS = base.o malloc.o egate-enclave.o crypto.o snprintf.o aes_cmac128.o
BASE_CFLAGS = -g -Iinclude -I../user/include -Wall -pedantic -Wno-unused-function -std=gnu11
ENC_CFLAGS = -fno-stack-protector -static -fPIC -fvisibility=hidden
CFLAGS = $(BASE_CFLAGS) $(ENC_CFLAGS)
ASFLAGS = -D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC
all: libsgx.a libpolarssl.a sgx-entry.o
TOP=$(PWD)
libsgx.a: $(LIBSGX_OBJS)
	$(AR) rs $@ $^

libpolarssl.a: mbedtls-config-libsgx.h
	CFLAGS="-O2 $(ENC_CFLAGS) -I$(TOP) -DPOLARSSL_CONFIG_FILE='<mbedtls-config-libsgx.h>'" make -C mbedtls-1.3.11 SHARED=1 lib
	cp mbedtls-1.3.11/library/libpolarssl.a .
	rm -rf include/polarssl
	cp -r mbedtls-1.3.11/include/polarssl include
	cp mbedtls-config-libsgx.h mbedtls-1.3.11/include/polarssl/config.h
