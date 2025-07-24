package model

import "fmt"

type LoadBalancePolicy struct{ string }

var (
	NoPolicy           = LoadBalancePolicy{}
	LeastLatencyPolicy = LoadBalancePolicy{"least-latency"}
	LeastConnsPolicy   = LoadBalancePolicy{"least-conns"}
	RoundRobinPolicy   = LoadBalancePolicy{"round-robin"}
	RandomPolicy       = LoadBalancePolicy{"random"}
)

func ParseLBPolicy(s string) (LoadBalancePolicy, error) {
	switch s {
	case NoPolicy.string:
		return NoPolicy, nil
	case LeastLatencyPolicy.string:
		return LeastLatencyPolicy, nil
	case LeastConnsPolicy.string:
		return LeastConnsPolicy, nil
	case RoundRobinPolicy.string:
		return RoundRobinPolicy, nil
	case RandomPolicy.string:
		return RandomPolicy, nil
	}
	return NoPolicy, fmt.Errorf("invalid load balance policy '%s'", s)
}

type LoadBalanceRetry struct{ string }

var (
	NeverRetry = LoadBalanceRetry{}
	CountRetry = LoadBalanceRetry{"count"}
	TimedRetry = LoadBalanceRetry{"timed"}
	AllRetry   = LoadBalanceRetry{"all"}
)

func ParseLBRetry(s string) (LoadBalanceRetry, error) {
	switch s {
	case NeverRetry.string:
		return NeverRetry, nil
	case CountRetry.string:
		return CountRetry, nil
	case TimedRetry.string:
		return TimedRetry, nil
	case AllRetry.string:
		return AllRetry, nil
	}
	return NeverRetry, fmt.Errorf("invalid load balance retry '%s'", s)
}
