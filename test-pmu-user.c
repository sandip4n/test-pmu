/* gcc -Wall -g -O0 test-pmu-user.c -o test-pmu-user -static */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <cpuid.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define CPUID_FAMILY(eax)		(((eax) & 0x0f00) >> 8)
#define CPUID_MODEL(eax)		(((eax) & 0x00f0) >> 4)
#define CPUID_EXT_FAMILY(eax)		(((eax) & 0x0ff00000) >> 20)
#define CPUID_EXT_MODEL(eax)		(((eax) & 0xf0000) >> 16)

#define X86_PERF_EVENT(e, u)		(((e) & 0xf00ULL) << 24) | (((u) & 0xffULL) << 8) | ((e) & 0xffULL)

#define PERF_COUNT_EX_RET_BRN		X86_PERF_EVENT(0x0c2, 0x00)
#define PERF_COUNT_EX_RET_COND		X86_PERF_EVENT(0x0d1, 0x00)
#define PERF_COUNT_EX_RET_UNCOND	X86_PERF_EVENT(0x1c9, 0x00)
#define PERF_COUNT_EX_RET_BRN_FAR	X86_PERF_EVENT(0x0c6, 0x00)
#define PERF_COUNT_EX_RET_INSTR		X86_PERF_EVENT(0x0c0, 0x00)
#define PERF_COUNT_LS_INT_TAKEN		X86_PERF_EVENT(0x02c, 0x00)

#define PERF_COUNT_BR_INST_RETIRED_ALL	X86_PERF_EVENT(0x0c4, 0x00)
#define PERF_COUNT_BR_INST_RETIRED_COND	X86_PERF_EVENT(0x0c4, 0x11)
#define PERF_COUNT_INVALID		X86_PERF_EVENT(0x000, 0x00)
#define PERF_COUNT_BR_INST_RETIRED_FAR	X86_PERF_EVENT(0x0c4, 0x40)
#define PERF_COUNT_INST_RETIRED_ANY	X86_PERF_EVENT(0x0c0, 0x00)

/* ioctl wrapper has extra branches, compensate after looking at objdump */
#define TEST_EXP_CTR_VAL		500001	/* expected counter value */
#define TEST_ITERATIONS			5000	/* number of iterations per counter */
#define TEST_HW_EVENTS			5	/* number of hardware events */
#define TEST_SW_EVENTS			2	/* number of software events */
#define TEST_EVENTS			(TEST_HW_EVENTS + TEST_SW_EVENTS)

#define min(a, b)			((a) < (b) ? (a) : (b))
#define max(a, b)			((a) > (b) ? (a) : (b))

#ifdef __always_inline
#undef __always_inline
#define __always_inline			inline __attribute__((__always_inline__))
#endif

#define HW_COUNT_RET_BR_ALL	0
#define HW_COUNT_RET_BR_COND	1
#define HW_COUNT_RET_BR_UNCOND	2
#define HW_COUNT_RET_BR_FAR	3
#define HW_COUNT_INT_TAKEN	4
#define SW_COUNT_EXCEPTION	5
#define SW_COUNT_SYSEXIT	6

const static unsigned long long zen_hw_event[TEST_HW_EVENTS] = {
	PERF_COUNT_EX_RET_BRN,
	PERF_COUNT_EX_RET_COND,
	PERF_COUNT_EX_RET_UNCOND,
	PERF_COUNT_EX_RET_BRN_FAR,
	PERF_COUNT_LS_INT_TAKEN
};

const static unsigned long long icx_hw_event[TEST_HW_EVENTS] = {
	PERF_COUNT_BR_INST_RETIRED_ALL,
	PERF_COUNT_BR_INST_RETIRED_COND,
	PERF_COUNT_INVALID,
	PERF_COUNT_BR_INST_RETIRED_FAR,
	PERF_COUNT_INVALID
};

const static unsigned long long *hw_event;

const static unsigned long long sw_event[TEST_SW_EVENTS] = {
	222,	/* exceptions:page_fault_user */
	452	/* raw_syscalls:sys_exit */
};

/*
 * Loop with a million instructions
 * Based on https://github.com/deater/perf_event_tests/blob/master/lib/instructions_testcode.c
 */
static __always_inline void pmc_test_loop(void)
{
	asm(
		"	xor	%%ecx,%%ecx\n"
		"	mov	$499999,%%ecx\n"
		"1:\n"
		"	dec	%%ecx\n"
		"	jnz	1b\n"
		:			/* no output registers */
		:			/* no inputs */
		: "cc", "%ecx"		/* clobbered */
	);
}

static void run_test(int fd[TEST_HW_EVENTS])
{
	unsigned long long cnt[TEST_EVENTS], min = ULLONG_MAX, max = 0;
	int nerr = 0, i, j;

	for (i = 0; i < TEST_ITERATIONS; i++) {
		ioctl(fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
		ioctl(fd[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

		pmc_test_loop();

		ioctl(fd[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
		for (j = 0; j < TEST_EVENTS; j++) {
			read(fd[j], &cnt[j], sizeof(cnt[j]));
#ifdef DEBUG
			printf("%llu%c", cnt[j], j < (TEST_EVENTS - 1) ? '\t' : '\n');
#endif
		}

		/*
		 * If the platform does not have a hardware event for counting
		 * unconditional branches or interrupts taken, try and bypass
		 * some of the test conditions
		 */
		if (!hw_event[HW_COUNT_RET_BR_UNCOND])
			cnt[HW_COUNT_RET_BR_UNCOND] = cnt[HW_COUNT_RET_BR_ALL] - cnt[HW_COUNT_RET_BR_COND] - cnt[HW_COUNT_RET_BR_FAR];

		if (!hw_event[HW_COUNT_INT_TAKEN])
			cnt[HW_COUNT_RET_BR_FAR] = cnt[SW_COUNT_EXCEPTION] + cnt[SW_COUNT_SYSEXIT];

		if ((cnt[HW_COUNT_RET_BR_COND] != TEST_EXP_CTR_VAL) ||
		    (cnt[HW_COUNT_RET_BR_ALL] != (cnt[HW_COUNT_RET_BR_COND] + cnt[HW_COUNT_RET_BR_UNCOND] + cnt[HW_COUNT_RET_BR_FAR])) ||
		    (cnt[HW_COUNT_RET_BR_FAR] != (cnt[HW_COUNT_INT_TAKEN] + cnt[SW_COUNT_EXCEPTION] + cnt[SW_COUNT_SYSEXIT])))
			nerr++;

		min = min(min, cnt[HW_COUNT_RET_BR_COND]);
		max = max(max, cnt[HW_COUNT_RET_BR_COND]);
	}

	printf("event reported %d counting errors in %d iterations, min = %llu, max = %llu\n",
		nerr, i, min, max);
}

static int perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			   int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
			group_fd, flags);
	return ret;
}

static int hw_event_open(unsigned long long config, int group_fd)
{
	struct perf_event_attr pe;
	int fd;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_RAW;
	pe.size = sizeof(pe);
	pe.config = config;
	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;

	fd = perf_event_open(&pe, 0, -1, group_fd, 0);
	if (fd == -1) {
		fprintf(stderr, "error opening hw event %llx\n", pe.config);
		exit(EXIT_FAILURE);
	}

	return fd;
}

static int sw_event_open(unsigned long long config, int group_fd)
{
	struct perf_event_attr pe;
	int fd;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_TRACEPOINT;
	pe.size = sizeof(pe);
	pe.config = config;
	pe.disabled = 1;

	fd = perf_event_open(&pe, 0, -1, group_fd, PERF_FLAG_FD_CLOEXEC);
	if (fd == -1) {
		fprintf(stderr, "error opening sw event %llx\n", pe.config);
		exit(EXIT_FAILURE);
	}

	return fd;
}

int main(void)
{
	unsigned int eax, ebx, ecx, edx, fam, mod;
	int fd[TEST_EVENTS], i;

	__get_cpuid(0x1, &eax, &ebx, &ecx, &edx);
	fam = CPUID_FAMILY(eax) + CPUID_EXT_FAMILY(eax);
	mod = CPUID_MODEL(eax) + (CPUID_EXT_MODEL(eax) << 4);

	if (fam == 6 && mod == 106)	/* icelake */
		hw_event = icx_hw_event;
	else if (fam == 25 && (mod >= 16 && mod <= 31))	/* genoa */
		hw_event = zen_hw_event;
	else
		return EXIT_SUCCESS;

	for (i = 0; i < TEST_HW_EVENTS; i++)
		fd[i] = hw_event_open(hw_event[i], i > 0 ? fd[0] : -1);
	for (i = 0; i < TEST_SW_EVENTS; i++)
		fd[i + TEST_HW_EVENTS] = sw_event_open(sw_event[i], fd[0]);

	run_test(fd);

	for (i = 0; i < TEST_EVENTS; i++)
		close(fd[i]);

	return EXIT_SUCCESS;
}
