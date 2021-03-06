DIR = $(shell pwd)
QEMU := $(DIR)/qemu/x86_64-linux-user/qemu-x86_64
USER := $(DIR)/user/test/simple
NJOB := $(shell nproc)

$(shell cp $(USER).c user/enclu.c)

all: $(USER) $(QEMU)
	(cd user; $(QEMU) $(USER))

$(USER): FORCE
	(cd user; make)

$(QEMU): FORCE
	(cd qemu; make -j $(NJOB))

.PHONY: FORCE
