package model

type LoadBalancer struct{ string }

var (
	UnknownLoadBalancer = LoadBalancer{}
	FindFastestBalancer = LoadBalancer{"find-fastest"}
	RoundRobinBalancer  = LoadBalancer{"round-robin"}
	RandomBalancer      = LoadBalancer{"random"}
	LeastConnsBalancer  = LoadBalancer{"least-conns"}
)
