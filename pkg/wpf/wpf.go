package wpf

import (
	"context"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

type wpfinterceptor struct{}

func (wpf *wpfinterceptor) Run(_ context.Context, _ func(networkpolicy.Packet) networkpolicy.Verdict) error {
	panic("not implemented") // TODO: Implement
}

func (wpf *wpfinterceptor) Sync(ctx context.Context, podV4IPs sets.Set[string], podV6IPs sets.Set[string]) error {
	panic("not implemented") // TODO: Implement
}

func (wpf *wpfinterceptor) Stop(ctx context.Context) {
	panic("not implemented") // TODO: Implement
}
