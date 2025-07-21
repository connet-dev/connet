package model

type LoadBalancerOrder struct{ string }

var (
	UnknownOrder      = LoadBalancerOrder{}
	LeastLatencyOrder = LoadBalancerOrder{"least-latency"}
	LeastConnsOrder   = LoadBalancerOrder{"least-conns"}
	RoundRobinOrder   = LoadBalancerOrder{"round-robin"}
	RandomOrder       = LoadBalancerOrder{"random"}
)

type LoadBalancerRetry struct{ string }

var (
	UnknownRetry = LoadBalancerRetry{}
	NeverRetry   = LoadBalancerRetry{"never"}
	CountRetry   = LoadBalancerRetry{"count"}
	TimedRetry   = LoadBalancerRetry{"timed"}
	AllRetry     = LoadBalancerRetry{"all"}
)
