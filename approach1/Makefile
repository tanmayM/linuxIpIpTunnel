obj-m += ipipTransmit_Tunnel.o
ipipTunTxHook-objs := ipipTransmit_Tunnel.o helpers.o

KDIR:=/lib/modules/$(shell uname -r)/build M=$(PWD) modules
MAKE:=make

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
