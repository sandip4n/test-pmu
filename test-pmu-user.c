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

#define PERF_COUNT_BR_INST_RETIRED_ALL	X86_PERF_EVENT(0x0c4, 0x00)
#define PERF_COUNT_BR_INST_RETIRED_COND	X86_PERF_EVENT(0x0c4, 0x11)
#define PERF_COUNT_INVALID		X86_PERF_EVENT(0x000, 0x00)
#define PERF_COUNT_BR_INST_RETIRED_FAR	X86_PERF_EVENT(0x0c4, 0x40)
#define PERF_COUNT_INST_RETIRED_ANY	X86_PERF_EVENT(0x0c0, 0x00)

/* ioctl wrapper has extra branches, compensate after looking at objdump */
#define TEST_EXP_CTR_VAL		500001	/* expected counter value */
#define TEST_ITERATIONS			5000	/* number of iterations per counter */
#define TEST_EVENTS			5	/* number of events */

#define min(a, b)			((a) < (b) ? (a) : (b))
#define max(a, b)			((a) > (b) ? (a) : (b))

#ifdef __always_inline
#undef __always_inline
#define __always_inline			inline __attribute__((__always_inline__))
#endif

const static unsigned long long zen_events[TEST_EVENTS] = {
	PERF_COUNT_EX_RET_BRN,
	PERF_COUNT_EX_RET_COND,
	PERF_COUNT_EX_RET_UNCOND,
	PERF_COUNT_EX_RET_BRN_FAR,
	PERF_COUNT_EX_RET_INSTR
};

const static unsigned long long icx_events[TEST_EVENTS] = {
	PERF_COUNT_BR_INST_RETIRED_ALL,
	PERF_COUNT_BR_INST_RETIRED_COND,
	PERF_COUNT_INVALID,
	PERF_COUNT_BR_INST_RETIRED_FAR,
	PERF_COUNT_INST_RETIRED_ANY
};

const static unsigned long long *events;

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

static void pmc_run_test(int fd[TEST_EVENTS])
{
	unsigned long long cnt[TEST_EVENTS], res, min = ULLONG_MAX, max = 0;
	int nerr = 0, i, j;

	for (i = 0; i < TEST_ITERATIONS; i++) {
		ioctl(fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
		ioctl(fd[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

		pmc_test_loop();

		ioctl(fd[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
		for (j = 0; j < TEST_EVENTS; j++)
			read(fd[j], &cnt[j], sizeof(cnt[j]));

		/* IRET, SYSRET to usermode are counted as retired branches */
		res = cnt[0] - cnt[2] - cnt[3];
		if (!events[2])
			res = cnt[1];

		if ((cnt[1] != TEST_EXP_CTR_VAL) || (cnt[1] != res))
			nerr++;

		min = min(min, res);
		max = max(max, res);
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

static int pmc_raw_event_open(unsigned long long config, int group_fd)
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
		fprintf(stderr, "error opening leader %llx\n", pe.config);
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
		events = icx_events;
	else if (fam == 25 && (mod >= 16 && mod <= 31))	/* genoa */
		events = zen_events;
	else
		return EXIT_SUCCESS;

	for (i = 0; i < TEST_EVENTS; i++)
		fd[i] = pmc_raw_event_open(events[i], i > 0 ? fd[0] : -1);

	pmc_run_test(fd);

	for (i = 0; i < TEST_EVENTS; i++)
		close(fd[i]);

	return EXIT_SUCCESS;
}
