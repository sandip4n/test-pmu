# test-pmu
A kernel module for simple testing of x86 performance monitoring counters.
It exercises all available general-purpose core performance counters to measure
the number of instructions counted for a loop of a million instructions. The
test fails if the expected count is not recorded.

The test relies on writing to model-specific registers directly so any external
intervention from other programs or utilities that use performance monitoring
counters should be absent. A typical example is having the NMI Watchdog enabled
or running `perf` while the test is active.

The NMI Watchdog can be disabled as shown below.
```
$ sudo sysctl kernel.nmi_watchdog=0
```

The test does not produce any typical output as such. All information is written
to the kernel ring buffer instead. A simple way to run the test is shown below.
```
$ sudo insmod test-pmu.ko; sudo rmmod test-pmu; dmesg | tail -10
```
