# /tmp/kvm_probe/Makefile
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
CC   := gcc

obj-m += kvm_probe_drv.o

all: module prober

module:
⭾$(MAKE) -C $(KDIR) M=$(PWD) modules

prober: kvm_prober.c
⭾$(CC) -o kvm_prober kvm_prober.c

clean:
⭾$(MAKE) -C $(KDIR) M=$(PWD) clean
⭾rm -f kvm_prober
