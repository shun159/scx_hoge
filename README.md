# scx_hoge

An **eBPF-based scheduler** focused on optimizing **cache locality** and **I/O-bound task performance**, inspired by **scx_flash** and **scx_bpfland**.

---

## Overview

`scx_hoge` is an **eBPF-based scheduler** designed to:  
- Improve **L2 and LLC (Last Level Cache) locality**  
- Optimize **SMT (Simultaneous Multi-Threading) efficiency**  
- Prioritize **I/O-bound tasks** for reduced latency  

---

## Design Goals

1. **Maximize Cache Locality**  
   - Tasks are scheduled to CPUs within the same **L2 and LLC cache domains** to reduce cache misses.  

2. **Optimize SMT Utilization**  
   - Idle SMT siblings are prioritized for task dispatch, leveraging CPU resources effectively.  

3. **Fair Task Scheduling**  
   - **EWMA (Exponential Weighted Moving Average)** ensures fair runtime distribution, preventing task starvation.  

4. **Interactive and I/O Task Awareness**  
   - **Interactive Tasks:** Prioritized based on **voluntary context switch rates (avg_nvcsw)**.  
   - **I/O Tasks:** Identified by tracking **I/O frequency (io_freq)** and **latency**, given shorter **deadlines** for faster dispatch.  

5. **Kernel Thread Prioritization**  
   - Kernel threads (`kthreads`) are dispatched immediately to **local DSQ**, ensuring critical kernel-level tasks remain responsive.  

6. **Dynamic CPU Frequency Scaling**  
   - CPU frequency dynamically scales based on **task utilization** and **user-defined performance levels**.  

---

## How It Works

### Task Initialization  
- Each task gets a **`task_ctx` structure** containing:  
   - Context switch metrics (`nvcsw`, `avg_nvcsw`)  
   - Runtime statistics (`avg_runtime`, `sum_runtime`)  
   - Cache affinity (`cpumask`, `l2_cpumask`, `llc_cpumask`)  
   - **I/O-specific fields:** `is_io_task`, `io_freq`, `avg_io_latency`  

---

### Task Queuing  
Tasks are dispatched based on their characteristics:

- **Kernel Threads:** Dispatched immediately to the **local DSQ**.  
- **High I/O Frequency Tasks:** Prioritized if `io_freq` exceeds `IO_FREQ_THRESHOLD`.  
- **Interactive Tasks:** Immediately dispatched for reduced latency.  
- **Non-Interactive Tasks:** Scheduled across **L2**, **LLC**, and **Shared DSQ** with `vruntime` fairness.  
- **CPU-Restricted Tasks:** Dispatched locally without migration.  

---

### CPU Selection  
The scheduler selects CPUs in the following order:  
1. **L2 Cache Domain** (high priority)  
2. **LLC Cache Domain**  
3. **Idle SMT Threads**  
4. **Least Loaded CPU** (if no idle CPU is found)  

- **Synchronous Wakeups:** Prioritize the **waker's CPU** to reduce migration latency.  

---

### Task Execution  
- **Dynamic Time Slices:** Adjusted via `task_refill_slice()` based on task load.  
- **Task Deadline:** Calculated using `task_deadline()` with I/O-bound tasks receiving **shorter deadlines**.  
- **CPU Frequency Scaling:** Adjusted based on **task utilization** and **performance levels**.  

---

### Task Termination/Blocking  
- Runtime and voluntary context switch metrics are updated.  
- I/O-specific metrics (`io_start_time`, `avg_io_latency`, `io_freq`) are refined.  
- **System Call Monitoring:**  
   - `read`, `recvfrom`, `sendto`, `accept`, `poll` are hooked via **fentry/fexit** to track I/O operations accurately.  

---

### vruntime-Based Fairness  
- Each task's **vruntime** is adjusted based on:  
   - Execution time  
   - Task weight  
   - Task type (I/O-bound, interactive)  
- Fair distribution ensures no task dominates the CPU.  

---

## System Call Monitoring

`scx_hoge` actively hooks critical **I/O-related system calls**:

- `read` / `recvfrom` / `sendto`  
- `accept` / `poll`  

These hooks allow the scheduler to:  
- Identify **I/O-bound tasks** in real-time  
- Estimate **I/O completion time**  
- Adjust task priority dynamically  

---

