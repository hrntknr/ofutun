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
	"go.uber.org/zap"
)

func init() {
	var err error
	log, err = zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
}

var log *zap.Logger

var opts struct {
	Print         bool     `long:"print" short:"p" description:"Print the configuration for the peers"`
	PrivateKey    string   `long:"private-key" description:"Base64-encoded private key for the server"`
	Peer          []string `long:"peer" description:"List of peer public keys and IP addresses in the format <public-key>,<ip1>,<ip2>,..."`
	PrivPeer      []string `long:"priv-peer" description:"List of peer private keys and IP addresses in the format <private-key>,<ip1>,<ip2>,..."`
	LocalIP       []string `long:"local-ip" description:"Local IP address to assign to the tunnel interface" default:"192.168.0.1" default:"fc00::1"`
	ListenPort    uint16   `long:"listen-port" short:"l" description:"Port to listen on for incoming connections" default:"51820"`
	DNSForwarder  []string `long:"dns-forwarder" description:"DNS servers to forward queries to" default:"8.8.8.8" default:"1.1.1.1"`
	Proxy         *string  `long:"proxy" description:"Proxy address to use for tunneling"`
	ProxyInsecure bool     `long:"proxy-insecure" description:"Ignore TLS certificate errors for the proxy"`
	ProxyOnly     bool     `long:"proxy-only" description:"Only allow traffic to the proxy"`
	HTTPPorts     []uint16 `long:"http-ports" description:"List of HTTP ports to allow" default:"80"`
	HTTPSPorts    []uint16 `long:"https-ports" description:"List of HTTPS ports to allow" default:"443"`
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
	if opts.ProxyOnly && opts.Proxy == nil {
		return fmt.Errorf("proxy must be specified when --only-proxy is set")
	}
	var privateKey []byte
	if opts.PrivateKey != "" {
		_privateKey, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}
		privateKey = _privateKey
	} else {
		_privateKey, err := ofutun.NewPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		log.Info("generated server key", zap.String("public-key", base64.StdEncoding.EncodeToString(ofutun.PublicKey(_privateKey))))
		privateKey = _privateKey
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
		privateKey, err := ofutun.NewPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		peers = append(peers, ofutun.Peer{
			PrivateKey: privateKey,
			PublicKey:  ofutun.PublicKey(privateKey),
			IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2"), netip.MustParseAddr("fc00::2")},
		})
		log.Info("generated peer",
			zap.String("private-key", base64.StdEncoding.EncodeToString(privateKey)),
			zap.Strings("address", []string{"192.168.0.2", "fc00::2"}),
		)
	}
	var proxy *url.URL
	if opts.Proxy != nil {
		_proxy, err := url.Parse(*opts.Proxy)
		if err != nil {
			return fmt.Errorf("failed to parse proxy URL: %w", err)
		}
		proxy = _proxy
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
		if err := ofutun.PrintPeerConfigs(os.Stdout, addrPort, localIP, ofutun.PublicKey(privateKey), peers, true); err != nil {
			return fmt.Errorf("failed to print peer configs: %w", err)
		}
	}

	o, err := ofutun.NewOfutun(
		log,
		proxy,
		opts.ProxyInsecure,
		localIP,
		privateKey,
		opts.ListenPort,
		peers,
		dnsForwarders,
		opts.HTTPPorts,
		opts.HTTPSPorts,
		opts.ProxyOnly,
	)
	if err != nil {
		return fmt.Errorf("failed to create instance: %w", err)
	}
	if err := o.Run(); err != nil {
		return fmt.Errorf("failed to run: %w", err)
	}
	return nil
}
