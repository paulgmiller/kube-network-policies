package main

import (
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/nfqinterceptor"
)

func getInterceptor(cfg networkpolicy.Config) (interceptor, error) {
	return nfqinterceptor.New(cfg)
}
