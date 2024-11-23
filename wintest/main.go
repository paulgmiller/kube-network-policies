package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	_ "k8s.io/component-base/logs/json/register"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/windivertinterceptor"
)

// This is a pattern to ensure that deferred functions executes before os.Exit
func main() {

	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	windivertinterceptor := windivertinterceptor.New()
	err := windivertinterceptor.Run(ctx, func(p networkpolicy.Packet) networkpolicy.Verdict {
		log.Println("Packet:", p)
		return networkpolicy.Accept
	})

	if err != nil {
		log.Fatalf("Failed to run windivertinterceptor: %v", err)
	}

	<-ctx.Done()

}
