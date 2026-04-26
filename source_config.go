package connet

import (
	"fmt"
	"time"

	"github.com/connet-dev/connet/model"
)

// SourceConfig structure represents source configuration.
type SourceConfig struct {
	Endpoint         Endpoint
	Route            RouteOption
	RelayEncryptions []model.EncryptionScheme
	DialTimeout      time.Duration

	DestinationPolicy   LoadBalancePolicy
	DestinationRetry    LoadBalanceRetry
	DestinationRetryMax int
}

// NewSourceConfig creates a source config for a given name.
func NewSourceConfig(name string) SourceConfig {
	return SourceConfig{
		Endpoint:          NewEndpoint(name),
		Route:             RouteAny,
		RelayEncryptions:  []model.EncryptionScheme{model.NoEncryption},
		DestinationPolicy: NoPolicy,
		DestinationRetry:  NeverRetry,
	}
}

// WithRoute sets the route option for this configuration.
func (cfg SourceConfig) WithRoute(route RouteOption) SourceConfig {
	cfg.Route = route
	return cfg
}

// WithRelayEncryptions sets the relay encryptions option for this configuration.
func (cfg SourceConfig) WithRelayEncryptions(schemes ...model.EncryptionScheme) SourceConfig {
	cfg.RelayEncryptions = schemes
	return cfg
}

// WithDialTimeout sets the dial timeout
func (cfg SourceConfig) WithDialTimeout(timeout time.Duration) SourceConfig {
	cfg.DialTimeout = timeout
	return cfg
}

// WithLoadBalance sets the load balancing behavior for this source
func (cfg SourceConfig) WithLoadBalance(policy LoadBalancePolicy, retry LoadBalanceRetry, max int) SourceConfig {
	cfg.DestinationPolicy = policy
	cfg.DestinationRetry = retry
	cfg.DestinationRetryMax = max

	switch {
	case cfg.DestinationRetry == CountRetry && cfg.DestinationRetryMax == 0:
		cfg.DestinationRetryMax = 2
	case cfg.DestinationRetry == TimedRetry && cfg.DestinationRetryMax == 0:
		cfg.DestinationRetryMax = 1000
	}

	return cfg
}

func (cfg SourceConfig) endpointConfig() endpointConfig {
	return endpointConfig{
		endpoint: cfg.Endpoint,
		role:     RoleSource,
		route:    cfg.Route,
	}
}

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
