package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	scx_utils "github.com/shun159/scx_go_utils"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target amd64 bpf bpf/sched_ext.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__

// DomainArg defines the sibling CPU relationship for scheduling domains.
type DomainArg struct {
	CacheLevel   int32
	CpuID        int32
	SiblingCpuID int32
	_            int32
}

// Logger settings
var log = logrus.New()

func initLogger() {
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(logrus.InfoLevel)
}

// enableSiblingCpu enables sibling CPU mapping.
func enableSiblingCpu(objs *bpfObjects, cacheLvl, cpuID, sibID int) error {
	buf := new(bytes.Buffer)
	arg := DomainArg{CacheLevel: int32(cacheLvl), CpuID: int32(cpuID), SiblingCpuID: int32(sibID)}
	if err := binary.Write(buf, binary.LittleEndian, arg); err != nil {
		return errors.Wrap(err, "Failed to encode DomainArg")
	}

	_, err := objs.EnableSiblingCpu.Run(&ebpf.RunOptions{Context: buf.Bytes()})
	if err != nil {
		return errors.Wrap(err, "Failed to run enable_sibling_cpu")
	}

	log.Infof("Enabled sibling CPU: CacheLevel=%d, CpuID=%d, SiblingCpuID=%d", cacheLvl, cpuID, sibID)
	return nil
}

// configureCPUTopology configures CPU sibling relationships.
func configureCPUTopology(objs *bpfObjects) {
	topology, err := scx_utils.NewTopology()
	if err != nil {
		log.Fatalf("Failed to read CPU topology: %s", err)
	}

	for _, cpu := range topology.AllCPUs {
		for _, sib := range topology.AllCPUs {
			if cpu.ID == sib.ID {
				continue
			}

			if cpu.L2ID == sib.L2ID {
				if err := enableSiblingCpu(objs, 2, cpu.ID, sib.ID); err != nil {
					log.Errorf("Failed to enable L2 sibling: %s", err)
				}
			}
			if cpu.L3ID == sib.L3ID {
				if err := enableSiblingCpu(objs, 3, cpu.ID, sib.ID); err != nil {
					log.Errorf("Failed to enable L3 sibling: %s", err)
				}
			}
		}
	}
}

// attachStructOps attaches sched_ext struct operations.
func attachStructOps(objs *bpfObjects) link.Link {
	m := objs.ScxHoge
	l, err := link.AttachRawLink(link.RawLinkOptions{
		ProgramFd: m.FD(),
		Attach:    ebpf.AttachStructOps,
	})
	if err != nil {
		log.Fatalf("Failed to attach sched_ext: %s", err)
	}
	log.Info("Successfully attached sched_ext struct operations")
	return l
}

func main() {
	initLogger()

	// Remove memlock limits
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Configure CPU topology
	configureCPUTopology(&objs)

	// Attach sched_ext struct ops
	l := attachStructOps(&objs)
	defer l.Close()

	// Graceful shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	log.Info("Press Ctrl+C to stop...")
	<-stopper

	log.Info("Shutting down sched_ext")
}
