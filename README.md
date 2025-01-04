
# scx_hoge

An eBPF-based scheduler focused on optimizing cache locality, inspired by scx_flash and scx_bpfland.

## Overview

scx_hoge is an eBPF-based scheduler designed to improve L2 and LLC (Last Level Cache) locality while considering SMT (Simultaneous Multi-Threading) efficiency. Inspired by the designs of scx_flash and scx_bpfland, this scheduler doesn't target a specific workload but aims to improve cache hit rates systematically.

## Design Goals

1. Maximize Cache Locality

Tasks are scheduled to CPUs sharing the same L2 and LLC cache domains.

2. Optimize SMT Utilization

Idle SMT siblings are prioritized for task dispatch.

3. Fair Task Scheduling

EWMA (Exponential Weighted Moving Average) ensures fair runtime distribution.

4. Interactive Task Awareness

Tasks exhibiting high voluntary context switch rates are prioritized.

## How It Works

1. **Task Initialization:**
   - Each task is assigned a **`task_ctx`** structure for local storage.
   - CPU masks (`l2_cpumask`, `llc_cpumask`) are dynamically initialized.

2. **Task Queuing:**
   - **Interactive Tasks:** Dispatched immediately to local DSQ.  
   - **Non-Interactive Tasks:** Scheduled across L2, LLC, and Shared DSQ hierarchies.

3. **CPU Selection:**
   - Idle CPUs are prioritized: **L2 → LLC → Global Queues**.  
   - SMT-aware scheduling ensures efficient sibling thread utilization.

4. **Task Execution:**
   - Time slices are dynamically refilled using `task_refill_slice()`.

5. **Task Termination:**
   - Runtime and voluntary context switch statistics are updated for future scheduling adjustments.


## Production Ready?

**No.** Not optimized for specific workloads. In heavy task migration scenarios, **scheduling overhead** may be noticeable.

