/* SPDX-License-Identifier: GPL-2.0 */
/*
 */

#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum consts {
  NSEC_PER_USEC = 1000ULL,
  NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
  NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),
};

#define CLOCK_BOOTTIME 7

extern unsigned CONFIG_HZ __kconfig;

#define MAX_CPUS 1024

/*
 * Maximum task weight.
 */
#define MAX_TASK_WEIGHT 10000

/*
 * Maximum frequency of task wakeup events / sec.
 */
#define MAX_WAKEUP_FREQ 1024

/*
 * Maximum amount of voluntary context switches (this limit allows to prevent
 * spikes or abuse of the nvcsw dynamic).
 */
#define MAX_AVG_NVCSW 128

/*
 * Global DSQ used to dispatch tasks.
 */
#define SHARED_DSQ 0

/*
 * Minimum time slice that can be assigned to a task (in ns).
 */
#define SLICE_MIN (NSEC_PER_SEC / CONFIG_HZ)

/*
 * Task time slice range.
 */
const volatile __u64 slice_max = 20ULL * NSEC_PER_MSEC;
const volatile __u64 slice_lag = 20ULL * NSEC_PER_MSEC;

/*
 * When enabled always dispatch all kthreads directly.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long, but it may also
 * introduce interactivity issues or unfairness in scenarios with high kthread
 * activity, such as heavy I/O or network traffic.
 */
const volatile bool local_kthreads = true;

/*
 * Maximum threshold of voluntary context switches.
 */
const volatile __u64 nvcsw_max_thresh = 10ULL;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile __s64 cpufreq_perf_lvl;

/*
 * Amount of ruuning threads
 */
volatile __u64 nr_running;

/*
 * Amount of online CPUs.
 */
volatile __u64 nr_online_cpus;

/*
 * Amount of interactive threads
 */
volatile __u64 nr_interactive;

/*
 * Scheduling statistics.
 */
volatile __u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Current global vruntime.
 */
static __u64 vtime_now;

/*
 * Global DSQ used to dispatch tasks.
 */
#define SHARED_DSQ 0

/* Helper macro for cpumask initialization */
#define INIT_TASK_CPUMASK(ctx, cpumask, mask_ptr)                                                  \
  cpumask = bpf_cpumask_create();                                                                  \
  if (!cpumask)                                                                                    \
    return -ENOMEM;                                                                                \
  cpumask = bpf_kptr_xchg(&(ctx)->mask_ptr, cpumask);                                              \
  if (cpumask)                                                                                     \
    bpf_cpumask_release(cpumask);

/*
 * Specify a sibling CPU relationship for a specific scheduling domain.
 */
struct domain_arg {
  __s32 lvl_id;
  __s32 cpu_id;
  __s32 sibling_cpu_id;
};

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
  // primary cpumask
  struct bpf_cpumask __kptr *cpumask;

  // L2 cache cpumask for scheduling domains.
  struct bpf_cpumask __kptr *l2_cpumask;

  // LLC cpumask for scheduling domains.
  struct bpf_cpumask __kptr *llc_cpumask;

  /*
   * Voluntary context switches metrics.
   */
  __u64 nvcsw;
  __u64 nvcsw_ts;
  __u64 avg_nvcsw;

  /*
   * Frequency with which a task is blocked (consumer).
   */
  u64 blocked_freq;
  u64 last_blocked_at;

  /*
   * Task's average used time slice.
   */
  __u64 avg_runtime;
  __u64 sum_runtime;
  __u64 last_run_at;

  /*
   * Task's deadline.
   */
  __u64 deadline;

  /*
   * Frequency with which a task wakes other tasks (producer).
   */
  u64 waker_freq;
  u64 last_woke_at;

  /*
   * Set to true if the task is classified as interactive.
   */
  bool is_interactive;
};

/* Map that contains task-local storage. */
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
  __u64 tot_runtime;
  __u64 prev_runtime;
  __u64 last_running;

  struct bpf_cpumask __kptr *l2_cpumask;
  struct bpf_cpumask __kptr *llc_cpumask;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct cpu_ctx);
  __uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Allocate/re-allocate a new cpumask.
 */
static int
calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
  struct bpf_cpumask *cpumask;

  cpumask = bpf_cpumask_create();
  if (!cpumask)
    return -ENOMEM;

  cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
  if (cpumask)
    bpf_cpumask_release(cpumask);

  return 0;
}

/*
 * Evaluate the amount of online CPUs.
 */
__s32
get_nr_online_cpus(void)
{
  const struct cpumask *online_cpumask;
  int cpus;

  online_cpumask = scx_bpf_get_online_cpumask();
  cpus = bpf_cpumask_weight(online_cpumask);
  scx_bpf_put_cpumask(online_cpumask);

  return cpus;
}

/*
 * Return the DSQ ID associated to a CPU, or SHARED_DSQ if the CPU is not
 * valid.
 */
static u64
cpu_to_dsq(s32 cpu)
{
  if (cpu < 0 || cpu >= MAX_CPUS) {
    scx_bpf_error("Invalid cpu: %d", cpu);
    return SHARED_DSQ;
  }
  return (u64)cpu;
}

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static __u64
calc_avg(__u64 old_val, __u64 new_val)
{
  return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Evaluate the EWMA limited to the range [low ... high]
 */
static __u64
calc_avg_clamp(__u64 old_val, __u64 new_val, __u64 low, __u64 high)
{
  return CLAMP(calc_avg(old_val, new_val), low, high);
}

/*
 * Evaluate the average frequency of an event over time.
 */
static __u64
update_freq(__u64 freq, __u64 delta)
{
  u64 new_freq;

  new_freq = NSEC_PER_SEC / delta;
  return calc_avg(freq, new_freq);
}

/*MAX_AVG_NVCSW
 * Compare two vruntime values, returns true if the first value is less than
 * the second one.
 *
 * Copied from scx_simple.
 */
static inline bool
vtime_before(__u64 a, __u64 b)
{
  return (s64)(a - b) < 0;
}

/*
 * Return true if the target task @p is a kernel thread, false instead.
 */
static inline bool
is_kthread(const struct task_struct *p)
{
  return p->flags & PF_KTHREAD;
}

/*
 * Return the amount of tasks that are waiting to run.
 */
static inline __u64
nr_tasks_waiting(void)
{
  return scx_bpf_dsq_nr_queued(SHARED_DSQ) + 1;
}

/*
 * Return task's weight.
 */
static __u64
task_weight(const struct task_struct *p, const struct task_ctx *tctx)
{
  return p->scx.weight;
}

/*
 * Return a value proportionally scaled to the task's priority.
 */
static __u64
scale_up_fair(const struct task_struct *p, const struct task_ctx *tctx, __u64 value)
{
  /*
   * Scale the static task weight by the average amount of voluntary
   * context switches to determine the dynamic weight.
   */
  u64 prio = p->scx.weight * CLAMP(tctx->avg_nvcsw, 1, nvcsw_max_thresh ?: 1);

  return CLAMP(prio, 1, MAX_TASK_WEIGHT);
}

/*
 * Return a value inversely proportional to the task's priority.
 */
static __u64
scale_inverse_fair(const struct task_struct *p, const struct task_ctx *tctx, __u64 value)
{
  return value * 100 / task_weight(p, tctx);
}

/*
 * Return the task's allowed lag: used to determine how early its vruntime can
 * be.
 */
static __u64
task_lag(const struct task_struct *p, const struct task_ctx *tctx)
{
  return scale_up_fair(p, tctx, slice_lag);
}

/*
 * ** Taken directly from fair.c in the Linux kernel **
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 */
const int sched_prio_to_weight[40] = {
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */ 9548,  7620,  6100,  4904,  3906,
    /*  -5 */ 3121,  2501,  1991,  1586,  1277,
    /*   0 */ 1024,  820,   655,   526,   423,
    /*   5 */ 335,   272,   215,   172,   137,
    /*  10 */ 110,   87,    70,    56,    45,
    /*  15 */ 36,    29,    23,    18,    15,
};

static __u64
max_sched_prio(void)
{
  return ARRAY_SIZE(sched_prio_to_weight);
}

/*
 * Convert task priority to weight (following fair.c logic).
 */
static __u64
sched_prio_to_latency_weight(__u64 prio)
{
  __u64 max_prio = max_sched_prio();

  if (prio >= max_prio) {
    scx_bpf_error("invalid priority");
    return 0;
  }

  return sched_prio_to_weight[max_prio - prio - 1];
}

/*
 * Return a local task context from a generic task.
 */
static __always_inline struct task_ctx *
try_lookup_task_ctx(const struct task_struct *p)
{
  return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

/*
 * Return a CPU context.
 */
static __always_inline struct cpu_ctx *
try_lookup_cpu_ctx(s32 cpu)
{
  const u32 idx = 0;
  return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

static __always_inline __u64
task_deadline(struct task_struct *p, struct task_ctx *tctx)
{
  __u64 avg_run_scaled, lat_prio, lat_weight;
  __u64 freq_factor, waker_freq, blocked_freq;

  /*
   * Calculate the average scaled runtime inversely proportional
   * to the task's weight.
   */
  avg_run_scaled = scale_inverse_fair(p, tctx, tctx->avg_runtime);
  avg_run_scaled = log2_u64(avg_run_scaled + 1);

  /*
   * Evaluate wake-up and block frequencies for producer/consumer behavior.
   */
  waker_freq = CLAMP(tctx->waker_freq, 1, MAX_WAKEUP_FREQ);
  blocked_freq = CLAMP(tctx->blocked_freq, 1, MAX_WAKEUP_FREQ);
  freq_factor = (blocked_freq + 1) * (waker_freq + 1) * (waker_freq + 1);

  /*
   * Calculate latency priority based on both frequencies and runtime.
   * Favor producer-like tasks more.
   */
  lat_prio = log2_u64(freq_factor + 1);
  if (lat_prio > avg_run_scaled)
    lat_prio -= avg_run_scaled;
  else
    lat_prio = 0;

  if (tctx->is_interactive)
    lat_prio += CLAMP(waker_freq / 2, 1, 10);

  /*
   * Translate latency priority to a scheduling weight.
   */
  lat_weight = sched_prio_to_latency_weight(lat_prio);

  /*
   * Calculate the final deadline based on weighted average runtime.
   */
  return tctx->avg_runtime * 100 / lat_weight;
}

/*
 * Return task's evaluated deadline applied to its vruntime.
 */
static __always_inline u64
task_vtime(struct task_struct *p, struct task_ctx *tctx)
{
  u64 min_vruntime = vtime_now - task_lag(p, tctx);

  /*
   * Limit the vruntime to to avoid excessively penalizing tasks.
   */
  if (vtime_before(p->scx.dsq_vtime, min_vruntime)) {
    p->scx.dsq_vtime = min_vruntime;
    tctx->deadline = p->scx.dsq_vtime + task_deadline(p, tctx);
  }

  return tctx->deadline;
}

static __always_inline void
task_refill_slice(struct task_struct *p)
{
  p->scx.slice = CLAMP(slice_max / nr_tasks_waiting(), slice_max / 2, slice_max);
}

static __always_inline int
init_cpumask(struct bpf_cpumask **cpumask)
{
  struct bpf_cpumask *mask;
  int err = 0;

  /*
   * Do nothing if the mask is already initialized.
   */
  mask = *cpumask;
  if (mask)
    return 0;
  /*
   * Create the CPU mask.
   */
  err = calloc_cpumask(cpumask);
  if (!err)
    mask = *cpumask;
  if (!mask)
    err = -ENOMEM;

  return err;
}

static __always_inline void
task_set_domain(struct task_struct *p, __s32 cpu, const struct cpumask *cpumask)
{
  __s32 err;

  const struct cpumask *l2_domain, *llc_domain;
  struct bpf_cpumask *l2_mask, *llc_mask;
  struct task_ctx *tctx;
  struct cpu_ctx *cctx;

  tctx = try_lookup_task_ctx(p);
  if (!tctx)
    return;

  cctx = try_lookup_cpu_ctx(cpu);
  if (!cctx)
    return;

  if (init_cpumask(&l2_mask)) {
    scx_bpf_error("failed to init L2 cpumask");
    return;
  }

  if (init_cpumask(&llc_mask)) {
    scx_bpf_error("failed to init LLC cpumask");
    return;
  }

  l2_domain = cast_mask(cctx->l2_cpumask);
  if (!l2_domain)
    l2_domain = p->cpus_ptr;

  llc_domain = cast_mask(cctx->llc_cpumask);
  if (!llc_domain)
    llc_domain = p->cpus_ptr;

  l2_mask = tctx->l2_cpumask;
  if (!l2_mask) {
    scx_bpf_error("L2 cpumask not initialized");
    return;
  }
  llc_mask = tctx->llc_cpumask;
  if (!llc_mask) {
    scx_bpf_error("LLC cpumask not initialized");
    return;
  }

  /*
   * Narrow down the task's CPU mask to CPUs within the same L2 cache domain.
   * This ensures the task is scheduled on CPUs sharing the same L2 cache,
   * optimizing intermediate-level cache locality.
   */
  bpf_cpumask_and(tctx->l2_cpumask, cpumask, l2_domain);

  /*
   * Further narrow down the task's CPU mask to CPUs within the same LLC (Last Level Cache) domain.
   * This ensures the task remains within a broader cache-sharing scope
   * while still respecting the L2 domain constraints.
   */
  bpf_cpumask_and(tctx->llc_cpumask, cast_mask(l2_mask), llc_domain);

  /*
   * Finalize the task's CPU mask by intersecting the LLC domain mask with the original task's CPU
   * mask. This guarantees the task's CPU affinity adheres to both LLC locality and the original CPU
   * constraints.
   */
  bpf_cpumask_and(tctx->cpumask, cast_mask(llc_mask), cpumask);
}

static bool
is_wake_sync(const struct task_struct *p,
             const struct task_struct *current,
             __s32 prev_cpu,
             __s32 cpu,
             __u64 wake_flags)
{
  if (wake_flags & SCX_WAKE_SYNC)
    return true;

  /*
   * If the current task is a per-CPU kthread running on the wakee's
   * previous CPU, treat it as a synchronous wakeup.
   *
   * The assumption is that the wakee had queued work for the per-CPU
   * kthread, which has now finished, making the wakeup effectively
   * synchronous. An example of this behavior is seen in IO completions.
   */
  if (is_kthread(current) && (p->nr_cpus_allowed == 1) && (prev_cpu == cpu))
    return true;

  return false;
}

/*
 * Find an idle CPU in the system.
 */
static __s32
pick_idle_cpu(struct task_struct *p, __s32 prev_cpu, __u64 wake_flags, bool *is_idle)
{
  const struct cpumask *idle_smtmask, *idle_cpumask;
  const struct cpumask *p_mask, *l2_mask, *l3_mask;
  struct task_ctx *tctx;
  struct cpu_ctx *cctx;
  struct task_struct *current = (void *)bpf_get_current_task_btf();
  int i;
  __s32 cpu = -1;
  __s32 least_loaded_cpu = -1;
  __u64 min_queue_len = 0xffffffff;
  __u64 queue_len;

  *is_idle = false;

  // Fetch task and CPU contexts
  tctx = try_lookup_task_ctx(p);
  if (!tctx)
    return -ENOENT;

  cctx = try_lookup_cpu_ctx(bpf_get_smp_processor_id());
  if (!cctx)
    return -EINVAL;

  // Fetch idle CPU masks
  idle_smtmask = scx_bpf_get_idle_smtmask();
  idle_cpumask = scx_bpf_get_idle_cpumask();

  p_mask = cast_mask(tctx->cpumask);
  l2_mask = cast_mask(tctx->l2_cpumask);
  l3_mask = cast_mask(tctx->llc_cpumask);

  if (!p_mask || !l2_mask || !l3_mask) {
    scx_bpf_error("CPU masks not properly initialized");
    cpu = -EINVAL;
    goto out_put_cpumask;
  }

  /*
   * Step 1: WAKE_SYNC - Prioritize CPU used by the waker task.
   */
  if (is_wake_sync(p, current, bpf_get_smp_processor_id(), prev_cpu, wake_flags)) {
    if (bpf_cpumask_test_cpu(prev_cpu, l3_mask) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
      cpu = prev_cpu;
      *is_idle = true;
      goto out_put_cpumask;
    }
  }

  /*
   * Step 2: Prioritize idle CPUs in L2 cache domain.
   */
  cpu = scx_bpf_pick_idle_cpu(l2_mask, SCX_PICK_IDLE_CORE);
  if (cpu >= 0) {
    *is_idle = true;
    goto out_put_cpumask;
  }

  /*
   * Step 3: Prioritize idle CPUs in L3 cache domain.
   */
  cpu = scx_bpf_pick_idle_cpu(l3_mask, SCX_PICK_IDLE_CORE);
  if (cpu >= 0) {
    *is_idle = true;
    goto out_put_cpumask;
  }

  /*
   * Step 4: SMT - Pick any SMT idle thread.
   */
  if (smt_enabled) {
    cpu = scx_bpf_pick_idle_cpu(p_mask, SCX_PICK_IDLE_CORE);
    if (cpu >= 0) {
      *is_idle = true;
      goto out_put_cpumask;
    }
  }

  bpf_for(i, 0, get_nr_online_cpus())
  {
    if (!bpf_cpumask_test_cpu(i, l3_mask))
      continue;

    queue_len = scx_bpf_dsq_nr_queued(cpu_to_dsq(i));
    if (queue_len < min_queue_len) {
      min_queue_len = queue_len;
      least_loaded_cpu = i;
    }
  }

  if (least_loaded_cpu >= 0) {
    cpu = least_loaded_cpu;
    goto out_put_cpumask;
  }

  /*
   * Step 5: Fallback to previously used CPU.
   */
  if (bpf_cpumask_test_cpu(prev_cpu, l3_mask) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
    cpu = prev_cpu;
    *is_idle = true;
    goto out_put_cpumask;
  }

  /*
   * Step 6: Pick any idle CPU in L2/L3 domain or globally.
   */
  cpu = scx_bpf_pick_idle_cpu(l2_mask, 0);
  if (cpu >= 0) {
    *is_idle = true;
    goto out_put_cpumask;
  }

  cpu = scx_bpf_pick_idle_cpu(l3_mask, 0);
  if (cpu >= 0) {
    *is_idle = true;
    goto out_put_cpumask;
  }

  /*
   * Step 7: Fallback - Pick any CPU in primary domain.
   */
  cpu = scx_bpf_pick_any_cpu(p_mask, 0);

out_put_cpumask:
  scx_bpf_put_cpumask(idle_cpumask);
  scx_bpf_put_cpumask(idle_smtmask);

  if (cpu < 0)
    cpu = prev_cpu;

  return cpu;
}

static __always_inline void
kick_task_cpu(struct task_struct *p, struct task_ctx *tctx)
{
  const struct cpumask *idle_cpumask, *llc_mask;
  s32 cpu;

  /*
   * If the task can only run on a single CPU, it's pointless to wake
   * up any other CPU, so do nothing in this case.
   */
  if (p->nr_cpus_allowed == 1 || p->migration_disabled)
    return;

  /*
   * Look for an idle CPU in the task's LLC domain that can
   * immediately execute the task.
   *
   * Note that we do not want to mark the CPU as busy, since we don't
   * know at this stage if we will actually dispatch any task on it.
   */
  llc_mask = cast_mask(tctx->llc_cpumask);
  if (!llc_mask) {
    scx_bpf_error("l3 cpumask not initialized");
    return;
  }

  idle_cpumask = scx_bpf_get_idle_cpumask();
  cpu = bpf_cpumask_any_and_distribute(llc_mask, idle_cpumask);
  scx_bpf_put_cpumask(idle_cpumask);

  if (cpu < get_nr_online_cpus())
    scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Scale target CPU frequency based on the performance level selected
 * from user-space and the CPU utilization.
 */
static void
update_cpuperf_target(struct task_struct *p, struct task_ctx *tctx)
{
  u64 now = bpf_ktime_get_ns();
  s32 cpu = scx_bpf_task_cpu(p);
  u64 perf_lvl, delta_runtime, delta_t, utilization;
  struct cpu_ctx *cctx;

  if (cpufreq_perf_lvl >= 0) {
    /*
     * Apply fixed cpuperf scaling factor determined by user-space.
     */
    perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
    scx_bpf_cpuperf_set(cpu, perf_lvl);
    return;
  }

  // For interactive tasks, prioritize performance but limit maximum frequency.
  if (tctx->is_interactive) {
    scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
    return;
  }

  /*
   * For non-interactive tasks determine their cpufreq scaling factor as
   * a function of their CPU utilization.
   */
  cctx = try_lookup_cpu_ctx(cpu);
  if (!cctx)
    return;

  delta_t = now - cctx->last_running;
  delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
  perf_lvl = delta_runtime * SCX_CPUPERF_ONE / delta_t;

  /* Ensure baseline is at least 50% to prevent underperformance */
  perf_lvl = MIN(perf_lvl, SCX_CPUPERF_ONE);
  // Apply the dynamic cpuperf scaling factor.
  scx_bpf_cpuperf_set(cpu, perf_lvl);

  cctx->last_running = now;
  cctx->prev_runtime = cctx->tot_runtime;
}

SEC("syscall")
int
enable_sibling_cpu(struct domain_arg *input)
{
  struct cpu_ctx *cctx;
  struct bpf_cpumask *mask, **pmask;
  int err = 0;

  cctx = try_lookup_cpu_ctx(input->cpu_id);
  if (!cctx)
    return -ENOENT;

  /* Make sure the target CPU mask is initialized */
  switch (input->lvl_id) {
  case 2:
    pmask = &cctx->l2_cpumask;
    break;
  case 3:
    pmask = &cctx->llc_cpumask;
    break;
  default:
    return -EINVAL;
  }
  err = init_cpumask(pmask);
  if (err)
    return err;

  bpf_rcu_read_lock();
  mask = *pmask;
  if (mask)
    bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
  bpf_rcu_read_unlock();

  return err;
}

__s32
BPF_STRUCT_OPS(hoge_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
  bool is_idle = false;
  s32 cpu;

  cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
  if (is_idle) {
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    __sync_fetch_and_add(&nr_direct_dispatches, 1);
  }

  return cpu;
}

void
BPF_STRUCT_OPS(hoge_enqueue, struct task_struct *p, __u64 enq_flags)
{
  struct task_ctx *tctx;
  struct cpu_ctx *cctx;
  const struct cpumask *l2_domain, *llc_domain;
  __s32 cpu;

  // prioritize kthreads. dispatch them immediately to the local DSQ
  if (is_kthread(p) && (local_kthreads || p->nr_cpus_allowed == 1)) {
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags | SCX_ENQ_PREEMPT);
    __sync_fetch_and_add(&nr_kthread_dispatches, 1);
    return;
  }

  // Handle task restricted to a specific CPU or migration disabled tasks
  if ((p->nr_cpus_allowed == 1) || p->migration_disabled) {
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) {
      scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
      __sync_fetch_and_add(&nr_direct_dispatches, 1);
      return;
    }
  }

  tctx = try_lookup_task_ctx(p);
  if (!tctx)
    return;

  l2_domain = cast_mask(tctx->l2_cpumask);
  if (!l2_domain)
    l2_domain = p->cpus_ptr;

  llc_domain = cast_mask(tctx->llc_cpumask);
  if (!llc_domain)
    llc_domain = p->cpus_ptr;

  // dispatch interactive task immediately
  if (tctx->is_interactive) {
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags | SCX_ENQ_PREEMPT);
    return;
  }

  // dispatch the task considering L2/LLC cache locality
  if (bpf_cpumask_weight(l2_domain) > 0) {
    cpu = scx_bpf_pick_idle_cpu(l2_domain, SCX_PICK_IDLE_CORE);
    if (cpu >= 0) {
      scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
      return;
    }
  }

  if (bpf_cpumask_weight(llc_domain) > 0) {
    cpu = scx_bpf_pick_idle_cpu(llc_domain, SCX_PICK_IDLE_CORE);
    if (cpu >= 0) {
      scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
      return;
    }
  }

  // Insert the task into the shared DSQ using its virtual runtime (vtime)
  // while considering cache locality.
  scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, task_vtime(p, tctx), enq_flags);

  kick_task_cpu(p, tctx);
}

void
BPF_STRUCT_OPS(hoge_dispatch, __s32 cpu, struct task_struct *prev)
{
  /*
   * Attempt to consume a task from the shared queue.
   */
  if (scx_bpf_consume(SHARED_DSQ)) {
    return;
  }

  if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
    task_refill_slice(prev);
  }
}

void
BPF_STRUCT_OPS(hoge_stopping, struct task_struct *p, bool runnable)
{
  __u64 now = bpf_ktime_get_ns(), slice;
  __s64 delta_t;

  struct cpu_ctx *cctx;
  struct task_ctx *tctx;

  cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
  if (!cctx)
    return;

  __sync_fetch_and_sub(&nr_running, 1);

  tctx = try_lookup_task_ctx(p);
  if (!tctx)
    return;

  if (tctx->is_interactive)
    __sync_fetch_and_sub(&nr_interactive, 1);

  slice = now - tctx->last_run_at;
  tctx->sum_runtime += slice;
  tctx->avg_runtime = calc_avg(tctx->avg_runtime, tctx->sum_runtime);
  p->scx.dsq_vtime += scale_inverse_fair(p, tctx, slice);
  tctx->deadline = p->scx.dsq_vtime + task_deadline(p, tctx);

  if (!nvcsw_max_thresh)
    return;

  if (p->scx.slice > 0)
    tctx->nvcsw++;

  delta_t = now - tctx->nvcsw_ts;
  if (delta_t > NSEC_PER_SEC) {
    __u64 avg_nvcsw = tctx->nvcsw * NSEC_PER_SEC / delta_t;
    tctx->nvcsw = 0;
    tctx->nvcsw_ts = now;
    tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, avg_nvcsw, 0, nvcsw_max_thresh);
    tctx->is_interactive = tctx->avg_nvcsw >= nvcsw_max_thresh;
  }
}

void
BPF_STRUCT_OPS(hoge_running, struct task_struct *p)
{
  struct task_ctx *tctx;

  task_refill_slice(p);

  tctx = try_lookup_task_ctx(p);
  if (!tctx)
    return;
  tctx->last_run_at = bpf_ktime_get_ns();

  update_cpuperf_target(p, tctx);

  if (tctx->is_interactive)
    __sync_fetch_and_add(&nr_interactive, 1);

  if (vtime_before(vtime_now, p->scx.dsq_vtime))
    vtime_now = p->scx.dsq_vtime;
}

void
BPF_STRUCT_OPS(hoge_quiescent, struct task_struct *p, u64 deq_flags)
{
  u64 now = bpf_ktime_get_ns(), delta;
  struct task_ctx *tctx;

  tctx = try_lookup_task_ctx(p);
  if (!tctx)
    return;

  delta = MAX(now - tctx->last_blocked_at, 1);
  tctx->blocked_freq = update_freq(tctx->blocked_freq, delta);
  tctx->last_blocked_at = now;
}

void
BPF_STRUCT_OPS(hoge_runnable, struct task_struct *p, __u64 enq_flags)
{
  __u64 now = bpf_ktime_get_ns(), delta;
  struct task_struct *waker;
  struct task_ctx *tctx;

  tctx = try_lookup_task_ctx(p);
  if (!tctx) {
    scx_bpf_error("incorrectly initialized task: %d (%s)", p->pid, p->comm);
    return;
  }
  tctx->sum_runtime = 0;

  waker = bpf_get_current_task_btf();
  tctx = try_lookup_task_ctx(waker);
  if (!tctx)
    return;

  delta = MAX(now - tctx->last_woke_at, 1);
  tctx->waker_freq = update_freq(tctx->waker_freq, delta);
  tctx->last_woke_at = now;
}

void
BPF_STRUCT_OPS(hoge_enable, struct task_struct *p)
{
  __u64 now = bpf_ktime_get_ns();
  struct task_ctx *tctx;

  p->scx.dsq_vtime = vtime_now;

  tctx = try_lookup_task_ctx(p);
  if (!tctx) {
    scx_bpf_error("incorrectly initialized task: %d (%s)", p->pid, p->comm);
    return;
  }

  // assume new task will use the minimum allowed time slice.
  tctx->avg_runtime = SLICE_MIN;
  tctx->nvcsw = 0;
  tctx->nvcsw_ts = now;
  tctx->deadline = p->scx.dsq_vtime + task_deadline(p, tctx);
}

void
BPF_STRUCT_OPS(hoge_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
  __s32 cpu = bpf_get_smp_processor_id();
  task_set_domain(p, cpu, cpumask);
}

__s32
BPF_STRUCT_OPS(hoge_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
  __s32 cpu = bpf_get_smp_processor_id();
  struct task_ctx *tctx;
  struct bpf_cpumask *cpumask;

  tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!tctx) {
    return -ENOMEM;
  }

  // create task's primary cpumask
  INIT_TASK_CPUMASK(tctx, cpumask, cpumask);
  // create task's L2 cache cpumask
  INIT_TASK_CPUMASK(tctx, cpumask, l2_cpumask);
  // create task's LLC cpumask
  INIT_TASK_CPUMASK(tctx, cpumask, llc_cpumask);

  task_set_domain(p, cpu, p->cpus_ptr);

  return 0;
}

__s32
BPF_STRUCT_OPS_SLEEPABLE(hoge_init)
{
  __s32 err;

  // initialize amount of online CPUs
  nr_online_cpus = get_nr_online_cpus();

  /*
   * Create the shared DSQ.
   *
   * Allocate the new DSQ id to not clash with any valid CPU id.
   */
  err = scx_bpf_create_dsq(SHARED_DSQ, -1);
  if (err) {
    scx_bpf_error("failed to create shared DSQ: %d", err);
    return err;
  }

  return 0;
};

SEC(".struct_ops.link")
struct sched_ext_ops scx_hoge = {
    .init = (void *)hoge_init,
    .init_task = (void *)hoge_init_task,
    .set_cpumask = (void *)hoge_set_cpumask,
    .enable = (void *)hoge_enable,
    .runnable = (void *)hoge_runnable,
    .running = (void *)hoge_running,
    .quiescent = (void *)hoge_quiescent,
    .stopping = (void *)hoge_stopping,
    .dispatch = (void *)hoge_dispatch,
    .enqueue = (void *)hoge_enqueue,
    .select_cpu = (void *)hoge_select_cpu,
    .flags = SCX_OPS_ENQ_EXITING,
    .timeout_ms = 10000U,
    .name = "hoge",
};
