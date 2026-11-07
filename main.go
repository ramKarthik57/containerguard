package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	mobyclient "github.com/moby/moby/client"
)

type ExecEvent struct {
	TimestampNS uint64
	CgroupID    uint64

	TID  uint32
	TGID uint32
	UID  uint32
	GID  uint32

	Comm     [16]byte
	Filename [256]byte
}

func cString(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock limit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("execve_events.o")
	if err != nil {
		log.Fatalf("Loading BPF specification: %v", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Loading BPF collection: %v", err)
	}
	defer collection.Close()

	program := collection.Programs["cg_execve_events"]
	if program == nil {
		log.Fatal("BPF program not found")
	}

	eventsMap := collection.Maps["events"]
	if eventsMap == nil {
		log.Fatal("Ring buffer map not found")
	}

	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		program,
		nil,
	)
	if err != nil {
		log.Fatalf("Attaching tracepoint: %v", err)
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("Creating ring buffer reader: %v", err)
	}
	defer reader.Close()

	dockerClient, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		log.Fatalf("Connecting to Docker Engine: %v", err)
	}
	defer dockerClient.Close()

	resolver := NewContainerResolver(dockerClient)
	resolver.Start(ctx)

	log.Println("ContainerGuard collector started")
	log.Println("eBPF: sys_enter_execve")
	log.Println("Transport: BPF Ring Buffer")
	log.Println("Container resolution: Docker + cgroup v2")

	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				log.Println("Collector shutting down")
				return
			}

			log.Fatalf("Reading Ring Buffer: %v", err)
		}

		var event ExecEvent

		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			log.Printf("Decoding event: %v", err)
			continue
		}

		info, found := resolver.Lookup(event.CgroupID)

		containerName := "HOST_OR_UNMAPPED"
		containerID := "-"
		image := "-"
		cgroupPath := "-"

		if found {
			containerName = info.Name
			containerID = info.ID
			image = info.Image
			cgroupPath = info.CgroupPath
		}

		fmt.Printf(
			"TIME=%s | CONTAINER=%s | CONTAINER_ID=%s | IMAGE=%s | CGROUP=%d | CGROUP_PATH=%s | TGID=%d | TID=%d | UID=%d | GID=%d | COMM=%s | EXEC=%s\n",
			time.Now().Format(time.RFC3339Nano),
			containerName,
			containerID,
			image,
			event.CgroupID,
			cgroupPath,
			event.TGID,
			event.TID,
			event.UID,
			event.GID,
			cString(event.Comm[:]),
			cString(event.Filename[:]),
		)
	}
}
