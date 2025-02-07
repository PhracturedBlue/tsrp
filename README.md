# TSRP - A Tailscale Reverse Proxy

This utility can be use to expose multiple services, each running in ther own goroutine as tailscale services.
It will expose services directly on port 80, and also can optionally expose them on port 443 with SSL termination.

This project is heavily based on [tailscale-reverse-proxy](https://github.com/carsoncall/tailscale-reverse-proxy)

## Features

*  A service can be configured a transparent proxy where the socket is directly forwarded (either on port 80 or port 443)
*  A service can be forwarded to http, https, or a unix-domain socket
*  Multiple way to configure services, any or all of which can be used together:
  * Configure a service via the cmdline
  * Configure a service via a yaml file
  * Autodetect services based on presence (only when forwarding to unix domain sockets)

## Getting Started

You must first get an Auth key from tailscale.  After logging in, go to the 'Settings' tab, and on the left,
under 'Personal Settings', select 'Keys'.  Then select 'Generate Auth Key'.  Create a file named '.env' in the current
directory and store the key as `TS_AUTH_KEY=<put key here>`.  This can alternatively be set as an environment variable.

NOTE: The auth key is only needed when creating a new service (or the 1st time a service is used by `tsrp`.  After that
it may not be needed again (I am unsure if TS_AUTH is needed to renew TLS certificates, but I don't think it should be)

To start the proxy:

```
./tsrp -tsname service1 -origin http://localhost:8080 [-https] [-transparent]
```

Note that persistent state information is stored in $HOME/.config/tsrp (or wherever your system configuration is stored).
This can be overridden via the `-statedir` switch.

## Using a config file

Multiple proxies can be configured via a yaml file.

Create a new proxy.yaml (or whatever name you prefer) with the following syntax:

```
- hostname: service1  # simple port forwarding
  origin: http://localhost:8080
- hostname: service2  # port forwarding to UDS with TLS termination (also forwards port 80)
  origin: unix:/path/to/unix/domain/socket
  https: true
- hostname: service3  # Transparent proxy to a secured service
  origin: https://localhost:8443
  transparent: true
  https: true
```

Note that specifying `-https` on the cmdline is equivalent to specifying `https: true` on all services.  To explicitly not
expose a service over https, use `https: false`.

## Using Unix Domain Socket Auto-Detection

`tsrp` is designed to be used alongside [socket-get](https://github.com/PhracturedBlue/socket-gen) to manage systemd
socket-activated podman containers via unix domain sockets.  The benefit of running services this way is that the service
containers can be run without any networking stack, thus improving security.

In this mode, `tsrp` will look for socket files recrsively from a specified directory, and will automatically enable and
disable services it finds as they appear/disappear.

```
./tsrp -socketdir $XDG_RUNTIME_DIR/sockets [-socketperm 0o666]
```

It may be necessary to changethe socket permissions with the `-socketperm` flag in cases where the socket file is not
managed by SystemD and the creating application does not/cannot give it suitable permissions.

## About TLS termination

Before using the `-https` switch (or coresponding config parameter), make sure to understand the consequences of using 
[Tailscale's HTTPS certificates](https://tailscale.com/kb/1153/enabling-https).  Web browsers will require you to use
a FQDN to access your services (i.e. https://service.friendly_name.ts.net), and your service name will be part of a
public ledger (although not accessible to anyone not on your tailnet of course).  There is no need to manage certififcates
as Tailscale will automatcally register and renew them as needed

## Building

A normal `go build` is generally sufficient to build `tsrp`.  However, if building to run in an Alpine Linux container,
use `CGO_ENABLED=0 go build -ldflags "-s -w"` instead.
