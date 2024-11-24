//go:build windows

// Windivert https://reqrypt.org/windivert is a nice helper over top of windows filter platform but it has a couple of issues
//  1. It may be abandoned.
//  2. it downloads a driver  and dll from github which is really convenient but radically insecure.
//  3. Lacks ability to do the following
//     a) copy just packet headers
//     b) filter only on first packet of a udp flow. (
//     c) reload a handle when we get a new ip to filter (could we just create a handle for every pod ip then close them when they go away or we shut down?)
//
// If this is actually valuable we could probably for it or just create our own packet capture c library.
package windivertinterceptor

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	windivert "github.com/sbilly/go-windivert2" //"github.com/paulgmiller/go-windivert2"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

func New() *windivertinterceptor {
	return &windivertinterceptor{}
}

type windivertinterceptor struct {
	captureUDP bool
}

func (wd *windivertinterceptor) Run(ctx context.Context, renderVerdict func(context.Context, networkpolicy.Packet) networkpolicy.Verdict) error {
	// Open a WinDivert handle with a filter to capture all traffic
	/// maybe forward for pods?
	// or udp? https://reqrypt.org/windivert-doc.html#filter_language
	filter := "tcp.Syn"
	if wd.captureUDP {
		filter += " or udp"
	}
	handle, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		fmt.Println("Error opening WinDivert handle:", err)
		return err
	}

	packet := make([]byte, 65535)
	addr := new(windivert.Address)
	defer func() {
		log.Println("Cleaning up windivert")
		handle.Close()
	}()
	var packetid uint32
	go func() {
		for ctx.Err() == nil {
			atomic.AddUint32(&packetid, 1)

			//consider RecvEx for better perf.
			//will we block here? after context is cancelled? Might we not close the handle at termination time becaus eof this?
			// Do we need a select statement?
			recvLen, err := handle.Recv(packet, addr)
			if err != nil {
				if ctx.Err() != nil {
					break
				}
				log.Println("Error receiving packet:", err)
				continue
			}

			//can WINDIVERT_IPHDR do this for us?
			// or WinDivertHelperParsePacket
			p, err := networkpolicy.ParsePacket(packet[:recvLen])
			if err != nil {
				log.Println("Error parsing packet:", err)
				continue
			}
			p.Id = packetid

			//should parallizer this but need to have a pool of packet buffers
			verdict := renderVerdict(ctx, p)
			if verdict == networkpolicy.Drop {
				// Drop the packet
				continue
			}

			// Send the packet back into the network stack
			_, err = handle.Send(packet[:recvLen], addr)
			if err != nil && ctx.Err() == nil {
				log.Println("Error sending packet:", err)
			}
		}
	}()
	<-ctx.Done()

	return nil
}

func (_ *windivertinterceptor) Sync(ctx context.Context, podV4IPs sets.Set[string], podV6IPs sets.Set[string]) error {
	//could update hanldes filter or add new handles but we're not really sure of thead safety there.
	return nil
}
