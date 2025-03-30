package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/hrntknr/ofutun/pkg/ofutun"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	Proxy          string   `long:"proxy" required:"true" description:"Proxy address to use for tunneling"`
	AutoGen        bool     `long:"autogen" short:"a" description:"Automatically generate a private key and public key for the server"`
	Print          bool     `long:"print" short:"p" description:"Print the configuration for the peers"`
	ProxyInsecure  bool     `long:"proxy-insecure" description:"Ignore TLS certificate errors for the proxy"`
	PrivateKey     string   `long:"private-key" description:"Base64-encoded private key for the server"`
	Peer           []string `long:"peer" description:"List of peer public keys and IP addresses in the format <public-key>,<ip>"`
	PrivPeer       []string `long:"priv-peer" description:"List of peer private keys and IP addresses in the format <private-key>,<ip>"`
	LocalIP        string   `long:"local-ip" description:"Local IP address to assign to the tunnel interface" default:"192.168.0.1"`
	ListenPort     uint16   `long:"listen-port" short:"l" description:"Port to listen on for incoming connections" default:"51820"`
	DNSForwarder   []string `long:"dns-forwarder" description:"DNS servers to forward queries to" default:"8.8.8.8" default:"1.1.1.1"`
	HTTPPorts      []uint16 `long:"http-ports" description:"List of HTTP ports to allow" default:"80"`
	HTTPSPorts     []uint16 `long:"https-ports" description:"List of HTTPS ports to allow" default:"443"`
	DisableNonHTTP bool     `long:"disable-non-http" description:"Disable non-HTTP/HTTPS traffic"`
}

func main() {
	if _, err := flags.Parse(&opts); err != nil {
		os.Exit(1)
	}

	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	var privateKey []byte
	if opts.PrivateKey != "" {
		_privateKey, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}
		privateKey = _privateKey
	} else if opts.AutoGen {
		_privateKey, err := ofutun.NewPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		privateKey = _privateKey
	} else {
		return fmt.Errorf("either --private-key or --autogen must be specified")
	}
	if len(privateKey) != 32 {
		return fmt.Errorf("invalid private key length: %d, expected 32", len(privateKey))
	}
	peers := make([]ofutun.Peer, len(opts.Peer)+len(opts.PrivPeer))
	for i, peer := range opts.Peer {
		parts := strings.Split(peer, ",")
		if len(parts) != 2 {
			return fmt.Errorf("invalid peer format: %s, expected <public-key>,<ip>", peer)
		}
		publicKey, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return fmt.Errorf("failed to decode public key: %w", err)
		}
		if len(publicKey) != 32 {
			return fmt.Errorf("invalid public key length: %d, expected 32", len(publicKey))
		}
		ip, err := netip.ParseAddr(parts[1])
		if err != nil {
			return fmt.Errorf("failed to parse IP address: %w", err)
		}
		peers[i] = ofutun.Peer{
			PublicKey: publicKey,
			IP:        ip,
		}
	}
	for i, peer := range opts.PrivPeer {
		parts := strings.Split(peer, ",")
		if len(parts) != 2 {
			return fmt.Errorf("invalid private peer format: %s, expected <private-key>,<ip>", peer)
		}
		privateKey, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}
		if len(privateKey) != 32 {
			return fmt.Errorf("invalid private key length: %d, expected 32", len(privateKey))
		}
		ip, err := netip.ParseAddr(parts[1])
		if err != nil {
			return fmt.Errorf("failed to parse IP address: %w", err)
		}
		peers[i+len(opts.Peer)] = ofutun.Peer{
			PrivateKey: privateKey,
			PublicKey:  ofutun.PublicKey(privateKey),
			IP:         ip,
		}
	}
	if len(peers) == 0 {
		if opts.AutoGen {
			privateKey, err := ofutun.NewPrivateKey()
			if err != nil {
				return fmt.Errorf("failed to generate private key: %w", err)
			}
			peers = append(peers, ofutun.Peer{
				PrivateKey: privateKey,
				PublicKey:  ofutun.PublicKey(privateKey),
				IP:         netip.MustParseAddr("192.168.0.2"),
			})
		} else {
			return fmt.Errorf("at least one peer must be specified")
		}
	}
	proxy, err := url.Parse(opts.Proxy)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %w", err)
	}
	localIP, err := netip.ParseAddr(opts.LocalIP)
	if err != nil {
		return fmt.Errorf("failed to parse local IP address: %w", err)
	}
	dnsForwarders := make([]netip.Addr, len(opts.DNSForwarder))
	for i, dns := range opts.DNSForwarder {
		ip, err := netip.ParseAddr(dns)
		if err != nil {
			return fmt.Errorf("failed to parse DNS forwarder IP address: %w", err)
		}
		dnsForwarders[i] = ip
	}

	if opts.Print {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		addrs, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("failed to lookup IP address: %w", err)
		}
		slices.SortFunc(addrs, func(a, b net.IP) int {
			ais4 := a.To4()
			bis4 := b.To4()
			if ais4 != nil && bis4 != nil {
				return bytes.Compare(ais4, bis4)
			}
			if ais4 != nil {
				return -1
			}
			if bis4 != nil {
				return 1
			}
			return bytes.Compare(a, b)
		})
		addr, ok := netip.AddrFromSlice(addrs[0])
		if !ok {
			return fmt.Errorf("failed to convert IP address to netip.Addr: %w", err)
		}
		addrPort := netip.AddrPortFrom(addr, opts.ListenPort)
		if err := ofutun.PrintPeerConfigs(addrPort, localIP, ofutun.PublicKey(privateKey), peers); err != nil {
			return fmt.Errorf("failed to print peer configs: %w", err)
		}
	}

	if err := ofutun.Run(
		proxy,
		opts.ProxyInsecure,
		localIP,
		privateKey,
		opts.ListenPort,
		peers,
		dnsForwarders,
		opts.HTTPPorts,
		opts.HTTPSPorts,
		opts.DisableNonHTTP,
	); err != nil {
		return fmt.Errorf("failed to run ofutun: %w", err)
	}
	return nil
}
