package main

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"os"
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
	Peer           []string `long:"peer" description:"List of peer public keys and IP addresses in the format <public-key>,<ip1>,<ip2>,..."`
	PrivPeer       []string `long:"priv-peer" description:"List of peer private keys and IP addresses in the format <private-key>,<ip1>,<ip2>,..."`
	LocalIP        []string `long:"local-ip" description:"Local IP address to assign to the tunnel interface" default:"192.168.0.1" default:"fc00::1"`
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
		if len(parts) < 2 {
			return fmt.Errorf("invalid peer format: %s, <public-key>,<ip1>,<ip2>,... expected", peer)
		}
		publicKey, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return fmt.Errorf("failed to decode public key: %w", err)
		}
		if len(publicKey) != 32 {
			return fmt.Errorf("invalid public key length: %d, expected 32", len(publicKey))
		}
		ips := make([]netip.Addr, len(parts)-1)
		for j, ipStr := range parts[1:] {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return fmt.Errorf("failed to parse IP address: %w", err)
			}
			ips[j] = ip
		}
		peers[i] = ofutun.Peer{
			PublicKey: publicKey,
			IP:        ips,
		}
	}
	for i, peer := range opts.PrivPeer {
		parts := strings.Split(peer, ",")
		if len(parts) < 2 {
			return fmt.Errorf("invalid private peer format: %s, <private-key>,<ip1>,<ip2>,... expected", peer)
		}
		privateKey, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}
		if len(privateKey) != 32 {
			return fmt.Errorf("invalid private key length: %d, expected 32", len(privateKey))
		}
		ips := make([]netip.Addr, len(parts)-1)
		for j, ipStr := range parts[1:] {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return fmt.Errorf("failed to parse IP address: %w", err)
			}
			ips[j] = ip
		}
		peers[i+len(opts.Peer)] = ofutun.Peer{
			PrivateKey: privateKey,
			PublicKey:  ofutun.PublicKey(privateKey),
			IP:         ips,
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
				IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2"), netip.MustParseAddr("fc00::2")},
			})
		} else {
			return fmt.Errorf("at least one peer must be specified")
		}
	}
	proxy, err := url.Parse(opts.Proxy)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %w", err)
	}
	localIP := make([]netip.Addr, len(opts.LocalIP))
	for i, ipStr := range opts.LocalIP {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("failed to parse local IP address: %w", err)
		}
		localIP[i] = ip
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
		addr, err := ofutun.GetAddr()
		if err != nil {
			return fmt.Errorf("failed to get local address: %w", err)
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
