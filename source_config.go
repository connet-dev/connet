package connet

import (
	"time"

	"github.com/connet-dev/connet/model"
)

// SourceConfig structure represents source configuration.
type SourceConfig struct {
	Endpoint         model.Endpoint
	Route            model.RouteOption
	RelayEncryptions []model.EncryptionScheme
	DialTimeout      time.Duration

	DestinationPolicy   model.LoadBalancePolicy
	DestinationRetry    model.LoadBalanceRetry
	DestinationRetryMax int
}

// NewSourceConfig creates a source config for a given name.
func NewSourceConfig(name string) SourceConfig {
	return SourceConfig{
		Endpoint:          model.NewEndpoint(name),
		Route:             model.RouteAny,
		RelayEncryptions:  []model.EncryptionScheme{model.NoEncryption},
		DestinationPolicy: model.NoPolicy,
		DestinationRetry:  model.NeverRetry,
	}
}

// WithRoute sets the route option for this configuration.
func (cfg SourceConfig) WithRoute(route model.RouteOption) SourceConfig {
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
func (cfg SourceConfig) WithLoadBalance(policy model.LoadBalancePolicy, retry model.LoadBalanceRetry, max int) SourceConfig {
	cfg.DestinationPolicy = policy
	cfg.DestinationRetry = retry
	cfg.DestinationRetryMax = max

	switch {
	case cfg.DestinationRetry == model.CountRetry && cfg.DestinationRetryMax == 0:
		cfg.DestinationRetryMax = 2
	case cfg.DestinationRetry == model.TimedRetry && cfg.DestinationRetryMax == 0:
		cfg.DestinationRetryMax = 1000
	}

	return cfg
}

func (cfg SourceConfig) endpointConfig() endpointConfig {
	return endpointConfig{
		endpoint: cfg.Endpoint,
		role:     model.Source,
		route:    cfg.Route,
	}
}
