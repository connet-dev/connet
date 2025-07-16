package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"

	"github.com/connet-dev/connet"
	"github.com/connet-dev/connet/model"
	"golang.org/x/sync/errgroup"
)

type destinationsConfig struct {
	destinations        map[string]connet.DestinationConfig
	destinationHandlers map[string]newrunnable[connet.Destination]
}

func parseDestinations(destinationsCfg map[string]DestinationConfig, logger *slog.Logger, defaultRelayEncryptions []model.EncryptionScheme) (*destinationsConfig, error) {
	destinations := map[string]connet.DestinationConfig{}
	destinationHandlers := map[string]newrunnable[connet.Destination]{}

	for name, fc := range destinationsCfg {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return nil, fmt.Errorf("[destination %s] parse route option: %w", name, err)
		}
		proxy, err := parseProxyVersion(fc.ProxyProtoVersion)
		if err != nil {
			return nil, fmt.Errorf("[destination %s] parse proxy proto version: %w", name, err)
		}
		relayEncryptions := defaultRelayEncryptions
		if len(fc.RelayEncryptions) > 0 {
			res, err := parseEncryptionSchemes(fc.RelayEncryptions)
			if err != nil {
				return nil, fmt.Errorf("[destination %s] parse relay encryptions: %w", name, err)
			}
			relayEncryptions = res
		}
		destinations[name] = connet.NewDestinationConfig(name).
			WithRoute(route).
			WithProxy(proxy).
			WithRelayEncryptions(relayEncryptions...)

		targetURL, err := url.Parse(fc.URL)
		if err != nil {
			return nil, fmt.Errorf("[destination %s] parse url: %w", name, err)
		}

		if !slices.Contains([]string{"tcp", "tls", "http", "https", "file"}, targetURL.Scheme) {
			return nil, fmt.Errorf("[destination %s] unsupported scheme '%s'", name, targetURL.Scheme)
		}

		if targetURL.Scheme == "tcp" || targetURL.Scheme == "tls" {
			if targetURL.Port() == "" {
				return nil, fmt.Errorf("[destination %s] missing port for tcp/tls", name)
			}
			if targetURL.Path != "" {
				return nil, fmt.Errorf("[destination %s] url path not supported for tcp/tls", name)
			}
		}

		var destCAs *x509.CertPool
		var destInsecureSkipVerify bool
		var destCerts []tls.Certificate
		if targetURL.Scheme == "tls" || targetURL.Scheme == "https" {
			if fc.CAsFile == "insecure-skip-verify" {
				destInsecureSkipVerify = true
			} else if fc.CAsFile != "" {
				casData, err := os.ReadFile(fc.CAsFile)
				if err != nil {
					return nil, fmt.Errorf("[destination %s] read CAs file: %w", name, err)
				}

				cas := x509.NewCertPool()
				if !cas.AppendCertsFromPEM(casData) {
					return nil, fmt.Errorf("[destination %s] missing CA certificate in %s", name, fc.CAsFile)
				}
				destCAs = cas
			}

			if fc.CertFile != "" {
				cert, err := tls.LoadX509KeyPair(fc.CertFile, fc.KeyFile)
				if err != nil {
					return nil, fmt.Errorf("[destination %s] load cert/key pair: %w", name, err)
				}
				destCerts = append(destCerts, cert)
			}
		}

		destinationHandlers[name] = func(dst connet.Destination) runnable {
			switch targetURL.Scheme {
			case "tcp":
				return connet.NewTCPDestination(dst, targetURL.Host, logger)
			case "tls":
				return connet.NewTLSDestination(dst, targetURL.Host, &tls.Config{
					RootCAs:            destCAs,
					Certificates:       destCerts,
					InsecureSkipVerify: destInsecureSkipVerify,
				}, logger)
			case "http":
				return connet.NewHTTPProxyDestination(dst, targetURL, nil)
			case "https":
				return connet.NewHTTPProxyDestination(dst, targetURL, &tls.Config{
					RootCAs:            destCAs,
					Certificates:       destCerts,
					InsecureSkipVerify: destInsecureSkipVerify,
				})
			case "file":
				path := targetURL.Path
				if path == "" {
					path = targetURL.Opaque
				}
				return connet.NewHTTPFileDestination(dst, path)
			default:
				panic(fmt.Sprintf("unexpected destination scheme: %s", targetURL.Scheme))
			}
		}
	}

	return &destinationsConfig{destinations, destinationHandlers}, nil
}

func (dcfg *destinationsConfig) schedule(ctx context.Context, cl *connet.Client, g *errgroup.Group) {
	for name, cfg := range dcfg.destinations {
		g.Go(func() error {
			dst, err := cl.Destination(ctx, cfg)
			if err != nil {
				return err
			}

			if dstrun := dcfg.destinationHandlers[name]; dstrun != nil {
				g.Go(func() error { return dstrun(dst).Run(ctx) })
			}

			<-dst.Context().Done()
			return fmt.Errorf("[destination %s] unexpected error: %w", name, context.Cause(dst.Context()))
		})
	}
}

type sourcesConfig struct {
	sources        map[string]connet.SourceConfig
	sourceHandlers map[string]newrunnable[connet.Source]
}

func parseSources(sourcesCfg map[string]SourceConfig, logger *slog.Logger, defaultRelayEncryptions []model.EncryptionScheme) (*sourcesConfig, error) {
	sources := map[string]connet.SourceConfig{}
	sourceHandlers := map[string]newrunnable[connet.Source]{}
	for name, fc := range sourcesCfg {
		route, err := parseRouteOption(fc.Route)
		if err != nil {
			return nil, fmt.Errorf("[source %s] parse route option: %w", name, err)
		}
		relayEncryptions := defaultRelayEncryptions
		if len(fc.RelayEncryptions) > 0 {
			res, err := parseEncryptionSchemes(fc.RelayEncryptions)
			if err != nil {
				return nil, fmt.Errorf("[source %s] parse relay encryptions: %w", name, err)
			}
			relayEncryptions = res
		}
		sources[name] = connet.NewSourceConfig(name).
			WithRoute(route).
			WithRelayEncryptions(relayEncryptions...)

		targetURL, err := url.Parse(fc.URL)
		if err != nil {
			return nil, fmt.Errorf("[source %s] parse url: %w", name, err)
		}

		if !slices.Contains([]string{"tcp", "tls", "http", "https", "ws", "wss"}, targetURL.Scheme) {
			return nil, fmt.Errorf("[source %s] unsupported scheme '%s'", name, targetURL.Scheme)
		}

		if targetURL.Scheme == "tcp" || targetURL.Scheme == "tls" {
			if targetURL.Port() == "" {
				return nil, fmt.Errorf("[source %s] missing port for tcp/tls", name)
			}
			if targetURL.Path != "" {
				return nil, fmt.Errorf("[source %s] url path not supported for tcp/tls", name)
			}
		}

		var srcCerts []tls.Certificate
		var srcClientCAs *x509.CertPool
		var srcClientAuth tls.ClientAuthType
		if targetURL.Scheme == "tls" || targetURL.Scheme == "https" || targetURL.Scheme == "wss" {
			cert, err := tls.LoadX509KeyPair(fc.CertFile, fc.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("[source %s] load server cert: %w", name, err)
			}
			srcCerts = append(srcCerts, cert)

			if fc.CAsFile != "" {
				casData, err := os.ReadFile(fc.CAsFile)
				if err != nil {
					return nil, fmt.Errorf("[source %s] read CAs file: %w", name, err)
				}

				cas := x509.NewCertPool()
				if !cas.AppendCertsFromPEM(casData) {
					return nil, fmt.Errorf("[source %s] missing CA certificate in %s", name, fc.CAsFile)
				}
				srcClientCAs = cas
				srcClientAuth = tls.RequireAndVerifyClientCert
			}
		}

		sourceHandlers[name] = func(src connet.Source) runnable {
			switch targetURL.Scheme {
			case "tcp":
				return connet.NewTCPSource(src, targetURL.Host, logger)
			case "tls":
				return connet.NewTLSSource(src, targetURL.Host, &tls.Config{
					Certificates: srcCerts,
					ClientCAs:    srcClientCAs,
					ClientAuth:   srcClientAuth,
				}, logger)
			case "http":
				return connet.NewHTTPSource(src, targetURL, nil)
			case "https":
				return connet.NewHTTPSource(src, targetURL, &tls.Config{
					Certificates: srcCerts,
					ClientCAs:    srcClientCAs,
					ClientAuth:   srcClientAuth,
				})
			case "ws":
				return connet.NewWSSource(src, targetURL, nil, logger)
			case "wss":
				return connet.NewWSSource(src, targetURL, &tls.Config{
					Certificates: srcCerts,
					ClientCAs:    srcClientCAs,
					ClientAuth:   srcClientAuth,
				}, logger)
			default:
				panic(fmt.Sprintf("unexpected source scheme: %s", targetURL.Scheme))
			}
		}
	}

	return &sourcesConfig{sources, sourceHandlers}, nil
}

func (scfg *sourcesConfig) schedule(ctx context.Context, cl *connet.Client, g *errgroup.Group) {
	for name, cfg := range scfg.sources {
		g.Go(func() error {
			src, err := cl.Source(ctx, cfg)
			if err != nil {
				return err
			}

			if srcrun := scfg.sourceHandlers[name]; srcrun != nil {
				g.Go(func() error { return srcrun(src).Run(ctx) })
			}

			<-src.Context().Done()
			return fmt.Errorf("[source %s] unexpected error: %w", name, context.Cause(src.Context()))
		})
	}
}
