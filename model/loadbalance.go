package model

type LoadBalancerStrategy struct{ string }

var (
	UnknownStrategy      = LoadBalancerStrategy{}
	LeastLatencyStrategy = LoadBalancerStrategy{"least-latency"}
	LeastConnsBalancer   = LoadBalancerStrategy{"least-conns"}
	RoundRobinBalancer   = LoadBalancerStrategy{"round-robin"}
	RandomBalancer       = LoadBalancerStrategy{"random"}
)

type LoadBalancerRetry struct{ string }

var (
	UnknownRetry = LoadBalancerRetry{}
	NeverRetry   = LoadBalancerRetry{"never"}
	CountRetry   = LoadBalancerRetry{"count"}
	TimedRetry   = LoadBalancerRetry{"timed"}
	AllRetry     = LoadBalancerRetry{"all"}
)
