obj-m += test-pmu.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	insmod $(abspath test-pmu.ko)
	rmmod test-pmu
	dmesg | tail
