MODULE_NAME := mapalloc

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := src/main.o src/interface_matching.o src/interface_non_matching.o src/parser.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(shell readlink -f .) modules

clean:
	make -C $(KDIR) M=$(shell readlink -f .) clean
