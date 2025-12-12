package connet

import (
	"time"

	"github.com/connet-dev/connet/model"
)

// DestinationConfig structure represents destination configuration.
type DestinationConfig struct {
	Endpoint         model.Endpoint
	Route            model.RouteOption
	Proxy            model.ProxyVersion
	RelayEncryptions []model.EncryptionScheme
	DialTimeout      time.Duration
}

// NewDestinationConfig creates a destination config for a given name
func NewDestinationConfig(name string) DestinationConfig {
	return DestinationConfig{
		Endpoint:         model.NewEndpoint(name),
		Route:            model.RouteAny,
		Proxy:            model.ProxyNone,
		RelayEncryptions: []model.EncryptionScheme{model.NoEncryption},
	}
}

// WithRoute sets the route option for this configuration.
func (cfg DestinationConfig) WithRoute(route model.RouteOption) DestinationConfig {
	cfg.Route = route
	return cfg
}

// WithProxy sets the proxy version option for this configuration.
func (cfg DestinationConfig) WithProxy(proxy model.ProxyVersion) DestinationConfig {
	cfg.Proxy = proxy
	return cfg
}

// WithRelayEncryptions sets the relay encryptions option for this configuration.
func (cfg DestinationConfig) WithRelayEncryptions(schemes ...model.EncryptionScheme) DestinationConfig {
	cfg.RelayEncryptions = schemes
	return cfg
}

// WithDialTimeout sets the dial timeout
func (cfg DestinationConfig) WithDialTimeout(timeout time.Duration) DestinationConfig {
	cfg.DialTimeout = timeout
	return cfg
}

func (cfg DestinationConfig) endpointConfig() endpointConfig {
	return endpointConfig{
		endpoint: cfg.Endpoint,
		role:     model.Destination,
		route:    cfg.Route,
	}
}
