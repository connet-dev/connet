package connet

import "github.com/connet-dev/connet/client"

type Client = client.Client

// Connect main entry point
var Connect = client.Connect

type ClientOption = client.Option

// Options
var (
	ClientToken                       = client.ClientToken
	ClientControlAddress              = client.ClientControlAddress
	ClientControlCAsFile              = client.ClientControlCAsFile
	ClientControlCAs                  = client.ClientControlCAs
	ClientDirectAddress               = client.ClientDirectAddress
	ClientDirectStatelessResetKey     = client.ClientDirectStatelessResetKey
	ClientDirectStatelessResetKeyFile = client.ClientDirectStatelessResetKeyFile
	ClientNatPMPConfig                = client.ClientNatPMPConfig
	ClientLogger                      = client.ClientLogger
)

// DestinationConfig structure represents destination configuration. See [Client.DestinationConfig]
type DestinationConfig = client.DestinationConfig

// NewDestinationConfig creates a destination config for a given name. See [client.NewDestinationConfig]
var NewDestinationConfig = client.NewDestinationConfig

type Destination = client.Destination

var (
	ErrNoActiveDestinations = client.ErrNoActiveDestinations
	ErrNoDialedDestinations = client.ErrNoDialedDestinations
)

// Destinations
var NewTCPDestination = client.NewTCPDestination
var NewTLSDestination = client.NewTLSDestination
var NewHTTPProxyDestination = client.NewHTTPProxyDestination
var NewHTTPFileDestination = client.NewHTTPFileDestination

// SourceConfig structure represents source configuration. See [Client.SourceConfig]
type SourceConfig = client.SourceConfig

// NewSourceConfig creates a destination config for a given name. See [client.NewSourceConfig]
var NewSourceConfig = client.NewSourceConfig

type Source = client.Source

// Sources
var NewTCPSource = client.NewTCPSource
var NewTLSSource = client.NewTLSSource
var NewHTTPSource = client.NewHTTPSource
var NewWSSource = client.NewWSSource
