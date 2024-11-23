//go:build windows

package windivertinterceptor

import (
	"context"
	"fmt"
	"log"

	windivert "github.com/sbilly/go-windivert2" //"github.com/paulgmiller/go-windivert2"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

type windivertinterceptor struct {
}

func (wd *windivertinterceptor) Run(ctx context.Context, evaluate func(networkpolicy.Packet) networkpolicy.Verdict) error {

	// Open a WinDivert handle with a filter to capture all traffic
	handle, err := windivert.Open("true", windivert.LayerNetwork, 0, 0)
	if err != nil {
		fmt.Println("Error opening WinDivert handle:", err)
		return err
	}
	//move to shutdown
	defer handle.Close()

	go func() {
		packet := make([]byte, 65535)
		addr := new(windivert.Address)

		for {
			recvLen, err := handle.Recv(packet, addr)
			if err != nil {
				log.Println("Error receiving packet:", err)
				continue
			}
			p, err := networkpolicy.ParsePacket(packet[:recvLen])
			if err != nil {
				log.Println("Error parsing packet:", err)
				continue
			}

			// Inspect or modify the packet here
			// For example, print the packet length
			log.Printf("Captured packet of length %d bytes\n", recvLen)

			//should parallizer this but need to have a pool of packet buffers
			verdict := evaluate(p)
			if verdict == networkpolicy.Drop {
				// Drop the packet
				continue
			}

			// Send the packet back into the network stack
			_, err = handle.Send(packet[:recvLen], addr)
			if err != nil {
				log.Println("Error sending packet:", err)
			}
		}
	}()
	return nil
}
