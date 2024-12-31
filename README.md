# Connet

`connet` is a reverse proxy for NAT traversal. It is inspired by ngrok, frp, rathole and others.

`connet` helps expose a service running on a device to another device on the internet. Unlike the others, 
`connet` needs to run on both the device that exposes the service (called `destination` in connet's terms)
and the device that wants to access the service (called `source`). This means that the communication is
never public and visible to the rest of the internet, and in many cases the devices can communicate directly.

## Features

 - **Direct communication** Because you run the `connet` client on both the `destination` and the `source`, the server is
is only needed for sharing configuration. In many cases clients can communicate directly, which increases privacy and 
performance, while reducing cost.
 - **Relay support** There are cases when clients are unable to find a path to communicate directly. In such cases, they
can use a relay to maintain connectivity. 
 - **Security** Everything is private, encrypted with TLS. Public server and client certificates are shared between peers
and are required and verified to establish connectivity. Clients and relays need to present a mandatory token when communicating
with the control server, allowing tight control over who can use `connet`.
 - **Embeddable** In case you want `connet` running as part of another (golang) program (as opposed to a separate executable), 
`connet` has a well defined api for running both the client and the server.

## Architecture

```mermaid
flowchart Architecture;
  A[Client Destination] -->|Exchange Direct and Relay Info| C(ControlServer);
  B[Client Source] -->|Exchange Direct and Relay Info| C(ControlServer);
  A[Client Destination] -->|Direct Connection| B;
  R[Relay] -->|Reserve| C(ControlServer);
  A[Client Destination] -->|Relay Connection| R;
  R -->|Relay Connection| B;
```

## Quickstart

Latest builds of `connet` can be acquired from our [releases](https://github.com/connet-dev/connet/releases) page. 
If you are using [NixOS](https://nixos.org), check also the [NixOS](#NixOS) section.

To get started with `connet`, you'll need 3 devices:

 - Server which your clients can communicate with. In most cases, this server will have a public IP and be directly 
accessible by clients. A VPS instance at one of the many cloud providers goes a long way here.
 - Device `A` that has the `destination` service you want to connect to, running at port `3000`.
 - Device `B` (aka `source`) which you want to connect to the service, at port `8000`. 

In the setup above, start `connet server` with the following `server.toml`:
```toml
[server]
tokens = ["client-a-token", "client-b-token"]
cert-file = "cert.pem"
key-file = "key.pem"
```

> **_NOTE_** To run `connet` you'll need a TLS certificate. When hosting it yourself you could either provision one
> via ACME/Let's encrypt (in which case clients don't need a separate `server-cas`) or use openssl to generate a self-signed one.
> 
> This example uses a self-signed one, and we use [minica](https://github.com/jsha/minica) to generate certificates.

Then, on device `A` run `connet` with the following `client-a.toml`:
```toml
[client]
token = "client-a-token"
server-addr = "SERVER_IP:19190"
server-cas = "cert.pem"

[client.destinations.serviceA]
addr = ":3000"
```

On device `B` run `connet` with the following `client-b.toml`:
```toml
[client]
token = "client-b-token"
server-addr = "SERVER_IP:19190"
server-cas = "cert.pem"

[client.sources.serviceA]
addr = ":8000"
```

## Configuration

You can use both a toml config file as well as command line when running `connet`. If you use both a config file and 
command line options, the latter takes precence, overriding any config file options. For simplicity, command line options 
only support a single `destination` or `source` configuration. 

### Client

Here is the full client `client-config.toml` configuration:
```toml
[client]
token = "client-token-1" # the token which the client uses to authenticate against the control server
token_file = "path/to/relay/token" # a file that contains the token, one of token or token_file is required

server-addr = "localhost:19190" # the control server address to connect to
server-cas = "path/to/cert.pem" # the control server certificate
direct-addr = ":19192" # at what address this client listens for direct connections

[client.destinations.serviceX]
addr = "localhost:3000" # where this destination connects to, required
route = "any" # what kind of routes to use, `any` will use both `direct` and `relay`

[client.destinations.serviceY]
addr = "192.168.1.100:8000" # multiple destinations can be defined, they are matched by name at the server
route = "direct" # force only direct communication between clients

[client.sources.serviceX] # matches destinations.serviceX
addr = ":8000" # the address at which to listen for incoming connections to be forwarded
route = "relay" # the kind of route to use

[client.sources.serviceY]
addr = ":8001" # again, mulitple sources can be defined
route = "direct" # force only direct communication between clients, even if other end allows any
```

### Server

Here is the full server `server-config.toml` configuration:
```toml
[server]
tokens = ["client-token-1", "client-token-n"] # set of recognized client tokens
tokens-file = "path/to/client/tokens" # a file that contains a list of client tokens
# one of tokens or tokens-file is required

addr = ":19190" # the address at which the control server will listen for connections, default to :19190
cert-file = "path/to/cert.pem" # the server certificate file, in pem format
key-file = "path/to/key.pem" # the server certificate private key file

relay-addr = ":19191" # the address at which the relay will listen for connectsion, defaults to :19191
relay-hostname = "localhost" # the public hostname (e.g. domain, ip address) which will be advertised to clients, defaults to localhost

store-dir = "path/to/server-store" # where does this server persist runtime information, defaults to a /tmp subdirectory
```

#### Control server

Here is the full control server `control-config.toml` configuration:
```toml
[control]
client-tokens = ["client-token-1", "client-token-n"] # set of recognized client tokens
client-tokens-file = "path/to/client/tokens" # a file that contains a list of client tokens
# one of client-tokens or client-tokens-file is required

relay-tokens = ["relay-token-1", "relay-token-n"] # set of recognized relay tokens
relay-tokens-file = "path/to/relay/token" # a file that contains a list of relay tokens
# one of relay-tokens or relay-tokens-file is necessary when connecting relays

addr = ":19190" # the address at which the control server will listen for connections, default to :19190
cert-file = "path/to/cert.pem" # the server certificate file, in pem format
key-file = "path/to/key.pem" # the server certificate private key file

store-dir = "path/to/control-store" # where does this control server persist runtime information, defaults to a /tmp subdirectory
```

#### Relay server

Here is the full relay server `relay-config.toml` configuration:
```toml
[relay]
token = "relay-token-1" # the token which the relay server uses to authenticate against the control server
token_file = "path/to/relay/token" # a file that contains the token, one of token or token_file is required

addr = ":19191" # the address at which the relay will listen for connectsion, defaults to :19191
hostname = "localhost" # the public hostname (e.g. domain, ip address) which will be advertised to clients, defaults to localhost

control-addr = "localhost:19190" # the control server address to connect to, defaults to localhost:19191
control-cas = "path/to/ca/file.pem" # the public certificate root of the control server, no default, required when using self-signed certs

store-dir = "path/to/relay-store" # where does this relay persist runtime information, defaults to a /tmp subdirectory
```

### Logging

At the root of the config file, you can configure logging (`connet` uses slog internally):
```toml
log-level = "info" # supports debug, info, warn, error, defaults to info
log-format = "text" # supports text and json, defaults to text
```

### Tunning

On some systems, if you might see the following line in the logs:
```
failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB). See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.
```

In which case, we recommend visiting the [wiki page](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes) and applying the recommended changes.

### NisOS

## Examples

TBD

## Hosting

If you want to use `connet`, but you don't wanna run the server yourself, we also have a hosted service 
at [connet.dev](https://connet.dev). It is free when clients connect directly, builds upon the open source components 
by adding account management and it is one of the easiest way to start. 

## Future

 - [ ] UDP support
