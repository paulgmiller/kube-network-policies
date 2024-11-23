//go:build windows

package windivertinterceptor

import (
	"context"
	"fmt"
	"log"

	windivert "github.com/sbilly/go-windivert2" //"github.com/paulgmiller/go-windivert2"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

func New() windivertinterceptor {
	return windivertinterceptor{}
}

type windivertinterceptor struct {
}

func (wd *windivertinterceptor) Run(ctx context.Context, evaluate func(networkpolicy.Packet) networkpolicy.Verdict) error {

	// Open a WinDivert handle with a filter to capture all traffic
	/// maybe forward for pods?
	// or udp? https://reqrypt.org/windivert-doc.html#filter_language
	handle, err := windivert.Open("tcp.Syn or udp", windivert.LayerNetwork, 0, 0)
	if err != nil {
		fmt.Println("Error opening WinDivert handle:", err)
		return err
	}

	go func() {
		packet := make([]byte, 65535)
		addr := new(windivert.Address)
		defer handle.Close()
		for ctx.Err() == nil {
			//consider RecvEx for better perf.
			recvLen, err := handle.Recv(packet, addr)
			if err != nil {
				log.Println("Error receiving packet:", err)
				continue
			}
			///windivert.
			//can WINDIVERT_IPHDR do this for us?
			// or WinDivertHelperParsePacket
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

func (_ *windivertinterceptor) Sync(ctx context.Context, podV4IPs sets.Set[string], podV6IPs sets.Set[string]) error {
	//could update hanldes filter or add new handles but we're not really sure of thead safety there.
	return nil
}

func (wd *windivertinterceptor) Stop(ctx context.Context) {
	//wpf.session.DeleteRule()
	//windivert.Shutdown()
}
