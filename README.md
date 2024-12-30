
# scx_hoge

This is a user-defined scheduler built for use with sched_ext,
a Linux kernel feature enabling the implementation of kernel thread schedulers using BPF, which can be dynamically loaded into the kernel.

## Overview

`scx_hoge` is a scheduler designed to optimize **CPU cache locality** and **fairness**.
It dynamically manages task scheduling with a focus on minimizing cache misses, improving interactivity, and ensuring tasks make efficient use of the CPU resources.

## Typical Use Case

### **Latency-Sensitive Workloads**
- Video and audio playback (e.g., 4K video streaming at 60fps without stuttering).  
- UI/UX rendering tasks requiring minimal latency.  

## Production Ready?

**No.**

While `scx_hoge` shows promising results in benchmarks and specific scenarios, it is still under active development. It may not yet meet the reliability and stability requirements for production use in critical environments.  

