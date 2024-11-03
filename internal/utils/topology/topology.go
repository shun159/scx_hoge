package topology

import (
	"fmt"
	"os"
	"scx_core_dispatch/internal/utils/cpumask"
	"strconv"
	"strings"
)

type CoreType int

const (
	CoreTypeBigTurbo CoreType = iota
	CoreTypeBig
	CoreTypeLittle
)

type Cpu struct {
	ID         int
	MinFreq    int
	MaxFreq    int
	BaseFreq   int
	TransLatNs int
	L2ID       int
	L3ID       int
	CoreType   CoreType
	CoreID     int
	LLCID      int
	NodeID     int
}

type Core struct {
	ID       int
	KernelID int
	Cpus     map[int]*Cpu
	Span     *cpumask.Cpumask
	CoreType CoreType
	LLCID    int
	NodeID   int
}

// Llc struct
type Llc struct {
	ID       int
	KernelID int
	Cores    map[int]*Core
	Span     *cpumask.Cpumask
	NodeID   int
	AllCpus  map[int]*Cpu
}

// Node struct
type Node struct {
	ID       int
	Llcs     map[int]*Llc
	Span     *cpumask.Cpumask
	AllCores map[int]*Core
	AllCpus  map[int]*Cpu
}

// Topology struct
type Topology struct {
	Nodes    map[int]*Node
	Span     *cpumask.Cpumask
	AllLlcs  map[int]*Llc
	AllCores map[int]*Core
	AllCpus  map[int]*Cpu
}

type NodeKernelKey struct {
	NodeID   int
	KernelID int
}

type TopoCtx struct {
	// (node_id, core_kernel_id) → core_id
	nodeCoreKernelIDs map[NodeKernelKey]int

	// (node_id, llc_kernel_id) → llc_id
	nodeLLCKernelIDs map[NodeKernelKey]int

	l2IDs map[string]int
	l3IDs map[string]int
}

func NewTopoCtx() *TopoCtx {
	return &TopoCtx{
		nodeCoreKernelIDs: make(map[NodeKernelKey]int),
		nodeLLCKernelIDs:  make(map[NodeKernelKey]int),
		l2IDs:             make(map[string]int),
		l3IDs:             make(map[string]int),
	}
}

func (t *TopoCtx) SetNodeCoreKernelID(nodeID, kernelID, coreID int) {
	t.nodeCoreKernelIDs[NodeKernelKey{NodeID: nodeID, KernelID: kernelID}] = coreID
}

func (t *TopoCtx) GetNodeCoreKernelID(nodeID, kernelID int) (int, bool) {
	v, ok := t.nodeCoreKernelIDs[NodeKernelKey{NodeID: nodeID, KernelID: kernelID}]
	return v, ok
}

func (t *TopoCtx) SetNodeLLCKernelID(nodeID, kernelID, llcID int) {
	t.nodeLLCKernelIDs[NodeKernelKey{NodeID: nodeID, KernelID: kernelID}] = llcID
}

func (t *TopoCtx) GetNodeLLCKernelID(nodeID, kernelID int) (int, bool) {
	v, ok := t.nodeLLCKernelIDs[NodeKernelKey{NodeID: nodeID, KernelID: kernelID}]
	return v, ok
}

func (t *TopoCtx) SetL2ID(key string, id int) {
	t.l2IDs[key] = id
}

func (t *TopoCtx) GetL2ID(key string) (int, bool) {
	v, ok := t.l2IDs[key]
	return v, ok
}

func (t *TopoCtx) SetL3ID(key string, id int) {
	t.l3IDs[key] = id
}

func (t *TopoCtx) GetL3ID(key string) (int, bool) {
	v, ok := t.l3IDs[key]
	return v, ok
}

func cpusOnline() (*cpumask.Cpumask, error) {
	path := "/sys/devices/system/cpu/online"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	onlineStr := string(data)
	span := cpumask.NewCpumask()
	for _, group := range strings.Split(onlineStr, ",") {
		min, max, err := parseCpuRange(group)
		if err != nil {
			return nil, err
		}
		for i := min; i <= max; i++ {
			span.SetCPU(i)
		}
	}
	return span, nil
}

func parseCpuRange(s string) (int, int, error) {
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid range format: %s", s)
		}

		min, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse min value: %s", parts[0])
		}

		max, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse max value: %s", parts[1])
		}

		if min > max {
			return 0, 0, fmt.Errorf("min value is greater than max value")
		}

		return min, max, nil
	}

	value, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse single value: %s", s)
	}

	return value, value, nil
}
