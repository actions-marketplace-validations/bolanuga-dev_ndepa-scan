package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ConnectEvent struct {
	Pid      uint32
	DestIP   uint32
	DestPort uint16
	Comm     [16]byte
}

func RunTracer() error {
	// Allow current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load pre-compiled eBPF objects
	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	fmt.Println("NDPA Runtime Monitor Active. Press Ctrl+C to exit...")

	var event ConnectEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		// Parse binary payload from eBPF ringbuf
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, event.DestIP)
		ip := net.IP(ipBytes)
		comm := string(bytes.Trim(event.Comm[:], "\x00"))

		// Log egress activity
		fmt.Printf("[Egress Detected] PID: %d | Process: %-10s | Dest: %s:%d\n",
			event.Pid, comm, ip, event.DestPort)
	}
}
