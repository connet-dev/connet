package model

type LoadBalancer struct{ string }

var (
	NoLB           = LoadBalancer{}
	LeastLatencyLB = LoadBalancer{"least-latency"}
	LeastConnsLB   = LoadBalancer{"least-conns"}
	RoundRobinLB   = LoadBalancer{"round-robin"}
	RandomLB       = LoadBalancer{"random"}
)

type LoadBalancerRetry struct{ string }

var (
	NeverRetry = LoadBalancerRetry{""}
	CountRetry = LoadBalancerRetry{"count"}
	TimedRetry = LoadBalancerRetry{"timed"}
	AllRetry   = LoadBalancerRetry{"all"}
)
