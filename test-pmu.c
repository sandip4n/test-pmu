#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/msr-index.h>
#include <asm/perf_event.h>

#if !defined(__i386__) && !(defined __x86_64__)
#error "unsupported processor!"
#endif

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(x)	"test-pmu: " x
#endif

#define PERF_CTL_EN		BIT_ULL(22)
#define PERF_CTL_USR		BIT_ULL(16)
#define PERF_CTL_OS		BIT_ULL(17)
#define PERF_CTL_UMASK(m)	((GENMASK_ULL(15, 8) & (m)) << 8)
#define PERF_CTL_EVENT(e)	((GENMASK_ULL(7, 0) & (e)) | ((GENMASK_ULL(11, 8) & (e)) << 32))

#define TEST_EXP_CTR_VAL	1000003	/* expected counter value */
#define TEST_ITERATIONS		5000	/* number of iterations per counter */

static __always_inline u64 __basic_rdmsr(u32 idx)
{
	u32 a, d;
	asm volatile("rdmsr" : "=a"(a), "=d"(d) : "c"(idx) : "memory");
	return a | ((u64)d << 32);
}

static __always_inline void __basic_wrmsr(u32 idx, u64 val)
{
	u32 a = val, d = val >> 32;
	asm volatile("wrmsr" : : "a"(a), "d"(d), "c"(idx) : "memory");
}

static __always_inline void amd_pmc_start(u32 idx, u32 event, u32 umask)
{
	u64 config = PERF_CTL_EN | PERF_CTL_OS | PERF_CTL_USR;

	config |= PERF_CTL_EVENT(event);
	config |= PERF_CTL_UMASK(umask);

	__basic_wrmsr(MSR_F15H_PERF_CTL + 2 * idx, config);
}

static __always_inline void intel_pmc_start(u32 idx, u32 event, u32 umask)
{
	u64 config = PERF_CTL_EN | PERF_CTL_OS | PERF_CTL_USR;

	config |= PERF_CTL_EVENT(event);
	config |= PERF_CTL_UMASK(umask);

	__basic_wrmsr(MSR_ARCH_PERFMON_EVENTSEL0 + idx, config);
}

static __always_inline void amd_pmc_stop(u32 idx)
{
	__basic_wrmsr(MSR_F15H_PERF_CTL + 2 * idx, 0);
}

static __always_inline void intel_pmc_stop(u32 idx)
{
	__basic_wrmsr(MSR_ARCH_PERFMON_EVENTSEL0 + idx, 0);
}

static __always_inline void amd_pmc_reset(u32 idx)
{
	__basic_wrmsr(MSR_F15H_PERF_CTR + 2 * idx, 0);
}

static __always_inline void intel_pmc_reset(u32 idx)
{
	__basic_wrmsr(MSR_ARCH_PERFMON_PERFCTR0 + idx, 0);
}

static __always_inline u64 amd_pmc_read(u32 idx)
{
	return __basic_rdmsr(MSR_F15H_PERF_CTR + 2 * idx);
}

static __always_inline u64 intel_pmc_read(u32 idx)
{
	return __basic_rdmsr(MSR_ARCH_PERFMON_PERFCTR0 + idx);
}

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

static __always_inline u64 amd_pmu_run_test(u32 idx)
{
	preempt_disable();
	local_irq_disable();

	amd_pmc_reset(idx);
	amd_pmc_start(idx, 0xc0, 0x0);		/* retired instructions */
	pmc_test_loop();
	amd_pmc_stop(idx);

	local_irq_enable();
	preempt_enable();

	return amd_pmc_read(idx);
}

static __always_inline u64 intel_pmu_run_test(u32 idx)
{
	preempt_disable();
	local_irq_disable();

	intel_pmc_reset(idx);
	intel_pmc_start(idx, 0xc0, 0x0);	/* retired instructions */
	pmc_test_loop();
	intel_pmc_stop(idx);

	local_irq_enable();
	preempt_enable();

	return intel_pmc_read(idx);
}

static int __init test_pmu_init(void)
{
	u64 cnt, min, max, (*run_test)(u32) = NULL;
	struct x86_pmu_capability cap;
	u32 i, j, nerr = 0;
	u64 global_ctrl;

	perf_get_x86_pmu_capability(&cap);

	if (static_cpu_has(X86_FEATURE_PERFCTR_CORE)) {
		run_test = &amd_pmu_run_test;
		global_ctrl = cap.version >= 2 ? MSR_AMD64_PERF_CNTR_GLOBAL_CTL : 0;
		pr_err("detected amd-pmu!\n");
	} else if (static_cpu_has(X86_FEATURE_ARCH_PERFMON)) {
		run_test = &intel_pmu_run_test;
		global_ctrl = cap.version >= 2 ? MSR_CORE_PERF_GLOBAL_CTRL : 0;
		pr_err("detected intel-pmu!\n");
	} else {
		pr_err("unsupported processor!\n");
		return -EOPNOTSUPP;
	}

	if (cap.version >= 2)
		__basic_wrmsr(global_ctrl, BIT_ULL(cap.num_counters_gp) - 1);

	for (i = 0; i < cap.num_counters_gp; i++) {
		min = U64_MAX;
		max = 0;
		for (j = 0, nerr = 0; j < TEST_ITERATIONS; j++) {
			cnt = run_test(i);
			if (cnt != TEST_EXP_CTR_VAL)
				nerr++;

			min = min(min, cnt);
			max = max(max, cnt);
		}

		pr_info("pmc %d reported %d counting errors in %d iterations, min = %llu, max = %llu\n",
			i, nerr, TEST_ITERATIONS, min, max);
	}

	if (cap.version >= 2)
		__basic_wrmsr(global_ctrl, 0);

	return 0;
}

static void __exit test_pmu_exit(void)
{
}

module_init(test_pmu_init);
module_exit(test_pmu_exit);
MODULE_LICENSE("GPL");
