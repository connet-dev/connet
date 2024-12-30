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

Then, on device `A` run `connet` with the following `client-a.toml`:
```toml
[client]
token = "client-a-token"
server-cas = "cert.pem"

[client.destinations.serviceA]
addr = ":3000"
```

On device `B` run `connet` with the following `client-b.toml`:
```toml
[client]
token = "client-b-token"
server-cas = "cert.pem"

[client.sources.serviceA]
addr = ":8000"
```

## Configuration

### Server

#### Control server

#### Relay server

### Client

### Logging

### Tunning

### NisOS

## Examples

## Hosting

If you want to use `connet`, but you don't wanna run the server yourself, we also have a hosted service 
at [connet.dev](https://connet.dev). It is free for direct connections, builds upon the open source components 
by adding account management and it is one of the easiest way to start. 

## Future
