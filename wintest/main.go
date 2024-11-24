package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	_ "k8s.io/component-base/logs/json/register"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/windivertinterceptor"
)

func containsAny(candidate string, tests []string) bool {
	for _, t := range tests {
		if strings.Contains(candidate, t) {
			return true
		}
	}
	return false
}

// This is a pattern to ensure that deferred functions executes before os.Exit
func main() {

	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt, os.Kill)
	defer cancel()
	log.Println("Started")
	hosts, err := net.LookupHost("httpbin.org")
	if err != nil {
		log.Fatalf("couldn't look up httpbin.org,%s", err)
	}
	log.Printf("Blocking %v", hosts)

	windivertinterceptor := windivertinterceptor.New()
	err = windivertinterceptor.Run(ctx, func(_ context.Context, p networkpolicy.Packet) networkpolicy.Verdict {
		log.Println(p.ShortString())
		if containsAny(p.ShortString(), hosts) {
			log.Println("BLOCKED")
			return networkpolicy.Drop
		}

		return networkpolicy.Accept
	})

	if err != nil {
		log.Fatalf("Failed to run windivertinterceptor: %v", err)
	}
	log.Printf("Exiting")

}
