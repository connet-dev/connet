# Connet

`connet` is a reverse proxy for NAT traversal. It is inspired by ngrok, frp, rathole and others.

`connet` helps expose a service running on a device to another device on the internet. Unlike the others, 
`connet` needs to run on both the device that exposes the service (called `destination` in connet's terms)
and the device that wants to access the service (called `source`). This means that the communication is
never public and visible to the rest of the internet, and in many cases the devices can communicate directly.

## Features

 - ** Direct communication ** Because you run the `connet` client on both the `destination` and the `source`, the server is
is only needed for sharing configuration. In many cases clients can communicate directly, which increases privacy and 
performance, while reducing cost.
 - ** Relay support ** There are cases when clients are unable to find a path to communicate directly. In such cases, they
can use a relay to maintain connectivity. 
 - ** Security ** Everything is private, encrypted with TLS. Public server and client certificates are shared between peers
and are required and verified to establish connectivity. Clients and relays need to present a mandatory token when communicating
with the control server, allowing tight control over who can use `connet`.

## Quickstart

Latest builds of `connet` can be acquired from our [releases](https://github.com/connet-dev/connet/releases) page. 
If you are using [NixOS](https://nixos.org), check also the [NixOS](#NixOS) section.

To get started with `connet`, you'll need 3 devices:

 - Server which your clients can communicate with. In most cases, this server will have a public IP and be directly 
accessible by clients. A VPS instance at one of the many cloud providers goes a long way here.
 - Device `A` that has the `destination` service you want to connect to.
 - Device `B` (aka `source`) which you want to connect to the service. 

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

## Future
