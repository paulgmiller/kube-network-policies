package main

import (
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/windivertinterceptor"
)

func getInterceptor(_ networkpolicy.Config) (interceptor, error) {
	return windivertinterceptor.New(), nil
}
