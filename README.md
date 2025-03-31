# ofutun

- **Non-privileged** Wireguard Server
- (Optional) Convert HTTP/HTTPS proxy to **transparent proxy**

> On mobile devices, Proxy is available only when connected to Wi-Fi.  
> With this tool, you can use proxies regardless of Wi-Fi/mobile connection.

## Feature

- No Privilege Required
  - Everything works in user space and no root privileges are required.
  - Built-in TCP/IP stack by [gvisor](https://gvisor.dev/)
  - Terminate tcp/udp connections in the ofutun, and Convert to tcp/udp stream from ofutun.
- http/https proxy conversion by SNI/Hosts header

## Pattern

### Pettern1: As a Non-privileged Wireguard Server

```sh
$ ./ofutun --print
```

![arch](./arch.drawio.svg)

### Pettern2: Convert HTTP/HTTPS Proxy to Transparent Proxy

```sh
$ ./ofutun --print --proxy http://proxy:1080
```

![arch](./arch-proxy.drawio.svg)

### Pattern3: Blocks non-Proxy traffic

```sh
$ ./ofutun --print --proxy http://proxy:1080 --only-proxy
```

![arch](./arch-only-proxy.drawio.svg)

## Usage

```sh
$ ./ofutun --help
Usage:
  ofutun [OPTIONS]

Application Options:
  -p, --print           Print the configuration for the peers
      --private-key=    Base64-encoded private key for the server
      --peer=           List of peer public keys and IP addresses in the format <public-key>,<ip1>,<ip2>,...
      --priv-peer=      List of peer private keys and IP addresses in the format <private-key>,<ip1>,<ip2>,...
      --local-ip=       Local IP address to assign to the tunnel interface (default: 192.168.0.1, fc00::1)
  -l, --listen-port=    Port to listen on for incoming connections (default: 51820)
      --dns-forwarder=  DNS servers to forward queries to (default: 8.8.8.8, 1.1.1.1)
      --proxy=          Proxy address to use for tunneling
      --proxy-insecure  Ignore TLS certificate errors for the proxy
      --proxy-only      Only allow traffic to the proxy
      --http-ports=     List of HTTP ports to allow (default: 80)
      --https-ports=    List of HTTPS ports to allow (default: 443)

Help Options:
  -h, --help            Show this help message
```
