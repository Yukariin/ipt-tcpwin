ifneq ($(KERNELRELEASE),)

obj-m := xt_TCPWIN.o

else

KDIR ?= /lib/modules/`uname -r`/build

all:	modules

modules:
	$(MAKE) -C $(KDIR) M=$$PWD $@

modules_install:
	$(MAKE) -C $(KDIR) M=$$PWD $@

clean:
	$(MAKE) -C $(KDIR) M=$$PWD $@

help:
	$(MAKE) -C $(KDIR) M=$$PWD $@

endif
