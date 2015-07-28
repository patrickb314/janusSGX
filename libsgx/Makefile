LIBSGX_OBJS = base.o malloc.o egate-enclave.o crypto.o snprintf.o aes_cmac128.o
BASE_CFLAGS = -g -Iinclude -I../user/include -Wall -pedantic -Wno-unused-function -std=gnu11
CFLAGS = $(BASE_CFLAGS) -fno-stack-protector -static -fPIC -fvisibility=hidden
ASFLAGS = -D__ASSEMBLY__ -Iinclude -Wall -fno-stack-protector -static -fPIC
all: libsgx.a libpolarssl.a sgx-entry.o

libsgx.a: $(LIBSGX_OBJS)
	$(AR) rs $@ $^

libpolarssl.a:
	export POLARSSL_CONFIG_FILE=$DIR/mbedtls-config-libsgx.h 
	(cd mbedtls-1.3.11; make SHARED=1 lib)
	cp mbedtls-1.3.11/library/libpolarssl.a .
	cp -r mbedtls-1.3.11/include/polarssl include
