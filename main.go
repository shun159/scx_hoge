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
		fmt.Printf("enable sibling cpu: %d (SMT primary: %v)--->", cpu.ID, cpu.IsPrimary)
		for _, sib := range cpu.SiblingIDs {
			if cpu.ID == sib {
				continue
			}
			fmt.Printf(" %d\n", sib)

			buf := new(bytes.Buffer)
			arg := DomainArg{CacheLevel: int32(cpu.L2ID), CpuID: int32(cpu.ID), SiblingCpuID: int32(sib)}
			if err := binary.Write(buf, binary.LittleEndian, arg); err != nil {
				log.Fatalf("Failed to encode DomainArg: %v", err)
			}

			_, err := objs.EnableSiblingCpu.Run(&ebpf.RunOptions{Context: buf.Bytes()})
			if err != nil {
				log.Printf("Error: %v", err)
			}

			buf = new(bytes.Buffer)
			arg = DomainArg{CacheLevel: int32(cpu.L3ID), CpuID: int32(cpu.ID), SiblingCpuID: int32(sib)}
			if err := binary.Write(buf, binary.LittleEndian, arg); err != nil {
				log.Fatalf("Failed to encode DomainArg: %v", err)
			}

			_, err = objs.EnableSiblingCpu.Run(&ebpf.RunOptions{Context: buf.Bytes()})
			if err != nil {
				log.Printf("Error: %v", err)
			}

		}
		fmt.Println()
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
