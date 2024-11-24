package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Padding  [3]byte // Alignment
}

const (
	ALLOW = 1
	BLOCK = 0
)

func ipToString(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("xdp_program.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	flowMap := coll.Maps["flow_verdict_map"]
	if flowMap == nil {
		log.Fatalf("Failed to find flow_verdict_map")
	}

	reader, err := perf.NewReader(coll.Maps["perf_event_map"], os.Getpagesize()*8)
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %v", err)
	}
	defer reader.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("Exiting...")
		reader.Close()
		os.Exit(0)
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			log.Printf("Error reading from perf event: %v", err)
			continue
		}

		var key FlowKey
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &key); err != nil {
			log.Printf("Failed to decode flow key: %v", err)
			continue
		}

		srcIP := ipToString(key.SrcIP)
		dstIP := ipToString(key.DstIP)
		fmt.Printf("Flow: %s:%d -> %s:%d (Protocol: %d)\n", srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol)

		// Example logic: Allow all traffic for demonstration
		verdict := ALLOW
		if err := flowMap.Put(key, verdict); err != nil {
			log.Printf("Failed to write verdict to map: %v", err)
		}
	}
}
