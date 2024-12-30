package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	scx_utils "github.com/shun159/scx_go_utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target amd64 bpf bpf/sched_ext.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__

// Specify a sibling CPU relationship for a specific scheduling domain.
type DomainArg struct {
	CacheLevel   int32
	CpuID        int32
	SiblingCpuID int32
	_            int32
}

func enableSiblingCpu(objs *bpfObjects, cacheLvl, cpuID, sibID int) error {
	buf := new(bytes.Buffer)
	arg := DomainArg{CacheLevel: int32(cacheLvl), CpuID: int32(cpuID), SiblingCpuID: int32(sibID)}
	if err := binary.Write(buf, binary.LittleEndian, arg); err != nil {
		return fmt.Errorf("Failed to encode DomainArg: %v", err)
	}

	_, err := objs.EnableSiblingCpu.Run(&ebpf.RunOptions{Context: buf.Bytes()})
	if err != nil {
		return fmt.Errorf("test_run enable_sibling_cpu: %v", err)
	}

	return nil
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", errors.WithStack(err))
	}
	defer objs.Close()

	topology, err := scx_utils.NewTopology()
	if err != nil {
		log.Fatalf("reading CPU topology: %s", err)
	}

	for _, cpu := range topology.AllCPUs {
		for _, sib := range topology.AllCPUs {
			if cpu.L2ID != sib.L2ID {
				continue
			}
			if err := enableSiblingCpu(&objs, cpu.L2ID, cpu.ID, sib.ID); err != nil {
				log.Fatalf("enable_sibling_cpu L2: %s", err)
			}
		}

		for _, sib := range topology.AllCPUs {
			if cpu.LLCID != sib.LLCID {
				continue
			}
			if err := enableSiblingCpu(&objs, cpu.L3ID, cpu.ID, sib.ID); err != nil {
				log.Fatalf("enable_sibling_cpu L3: %s", err)
			}
		}

	}

	m := objs.ScxHoge
	l, err := link.AttachRawLink(link.RawLinkOptions{
		ProgramFd: m.FD(),
		Attach:    ebpf.AttachStructOps,
	})

	if err != nil {
		log.Fatalf("failed to attach sched_ext: %s", err)
	}
	defer l.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper

	log.Print("quit sched_ext")
}
