package ofutun

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/color"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/boombuler/barcode/qr"
	"github.com/hrntknr/ofutun/pkg/flowcache"
	"github.com/inconshreveable/go-vhost"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func init() {
	var err error
	log, err = zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
}

var log *zap.Logger

type Peer struct {
	PublicKey  []byte
	PrivateKey []byte
	IP         []netip.Addr
}

func PrintPeerConfigs(endpoint netip.AddrPort, localIP []netip.Addr, publicKey []byte, peers []Peer) error {
	for n, peer := range peers {
		fmt.Println("----------- Peer", n+1, "-----------")
		var privateKey string
		if len(peer.PrivateKey) > 0 {
			privateKey = base64.StdEncoding.EncodeToString(peer.PrivateKey)
		} else {
			privateKey = "{private_key}"
		}
		addresses := make([]string, len(peer.IP))
		for i, ip := range peer.IP {
			pfx, err := ip.Prefix(ip.BitLen())
			if err != nil {
				return fmt.Errorf("failed to get prefix: %w", err)
			}
			addresses[i] = pfx.String()
		}
		local := make([]string, len(localIP))
		for i, ip := range localIP {
			local[i] = ip.String()
		}
		line := []string{
			"[Interface]",
			"PrivateKey = " + privateKey,
			"Address = " + strings.Join(addresses, ","),
			"DNS = " + strings.Join(local, ","),
			"MTU = 1420",
			"",
			"[Peer]",
			"PublicKey = " + base64.StdEncoding.EncodeToString(publicKey),
			"AllowedIPs = 0.0.0.0/0,::/0",
			"Endpoint = " + endpoint.String(),
			"PersistentKeepalive = 25",
		}
		fmt.Println(strings.Join(line, "\n"))
		fmt.Println()
		if len(peer.PublicKey) == 0 {
			continue
		}
		qrCode, err := qr.Encode(strings.Join(line, "\n"), qr.L, qr.Auto)
		if err != nil {
			return fmt.Errorf("failed to generate QR code: %w", err)
		}
		rect := qrCode.Bounds()
		for y := rect.Min.Y - 2; y < rect.Max.Y+2; y++ {
			for x := rect.Min.X - 2; x < rect.Max.X+2; x++ {
				if rect.Min.X <= x && x < rect.Max.X &&
					rect.Min.Y <= y && y < rect.Max.Y &&
					qrCode.At(x, y) == color.Black {

					fmt.Print("\033[40m  \033[0m")
				} else {
					fmt.Print("\033[47m  \033[0m")
				}
			}
			fmt.Println()
		}
		fmt.Println()
	}
	return nil
}

func PublicKey(privateKey []byte) []byte {
	var pk [32]byte
	sk := [32]byte(privateKey)
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk[:]
}

func NewPrivateKey() ([]byte, error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return sk[:], nil
}

func Run(
	proxy *url.URL,
	proxyInsecureSkipVerify bool,
	localIP []netip.Addr,
	privateKey []byte,
	listenPort uint16,
	peers []Peer,
	dnsForwarders []netip.Addr,
	httpPort []uint16,
	httpsPort []uint16,
	disableNonHTTP bool,
) error {
	cache, err := flowcache.NewFlowCache()
	if err != nil {
		return err
	}
	configs := []string{
		fmt.Sprintf("private_key=%s", hex.EncodeToString(privateKey)),
		fmt.Sprintf("listen_port=%d", listenPort),
	}
	for _, peer := range peers {
		configs = append(configs, fmt.Sprintf("public_key=%s", hex.EncodeToString(peer.PublicKey)))
		for _, ip := range peer.IP {
			pfx, err := ip.Prefix(ip.BitLen())
			if err != nil {
				return fmt.Errorf("failed to get prefix: %w", err)
			}
			configs = append(configs, fmt.Sprintf("allowed_ip=%s", pfx.String()))
		}
	}

	s, err := setupNetStack(localIP, configs, cache, httpPort, httpsPort, disableNonHTTP)
	if err != nil {
		return err
	}

	proxyDialer := NewProxyDialer(proxy, proxyInsecureSkipVerify)
	// todo: gracefully shutdown
	go func() {
		if err := setupDNS(s, dnsForwarders); err != nil {
			panic(err)
		}
	}()
	for _, port := range httpPort {
		go func(p uint16) {
			if err := setupHTTP(s, proxyDialer, p); err != nil {
				panic(err)
			}
		}(port)
	}
	for _, port := range httpsPort {
		go func(p uint16) {
			if err := setupHTTPS(s, proxyDialer, p); err != nil {
				panic(err)
			}
		}(port)
	}
	if !disableNonHTTP {
		go func() {
			if err := setupAnyTCP(s, cache); err != nil {
				panic(err)
			}
		}()
	}

	log.Info("ofutun started", zap.Uint16("listen_port", listenPort))
	select {}
}

func setupHTTP(s *netstack.Net, proxyDialer ProxyDialer, port uint16) error {
	httpListener, err := s.ListenTCP(&net.TCPAddr{Port: int(port)})
	if err != nil {
		return err
	}
	defer httpListener.Close()

	for {
		conn, err := httpListener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				log.Warn("failed to read request", zap.Error(err))
				return
			}
			upstream, header, err := proxyDialer()
			if err != nil {
				log.Warn("failed to dial upstream", zap.Error(err))
				return
			}
			req.URL.Opaque = "http://" + net.JoinHostPort(req.Host, fmt.Sprintf("%d", port)) + req.URL.Path
			for k, v := range header {
				for _, vv := range v {
					req.Header.Add(k, vv)
				}
			}
			if err := req.Write(upstream); err != nil {
				log.Warn("failed to write request", zap.Error(err))
				return
			}
			if err := pipe(upstream, c, c, upstream); err != nil {
				log.Warn("failed to pipe data", zap.Error(err))
				return
			}
		}(conn)
	}
}

func setupHTTPS(s *netstack.Net, proxyDialer ProxyDialer, port uint16) error {
	httpsListener, err := s.ListenTCP(&net.TCPAddr{Port: int(port)})
	if err != nil {
		return err
	}
	defer httpsListener.Close()

	for {
		conn, err := httpsListener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Warn("failed to upgrade to TLS", zap.Error(err))
				return
			}
			upstream, header, err := proxyDialer()
			if err != nil {
				log.Warn("failed to dial upstream", zap.Error(err))
				return
			}
			target := net.JoinHostPort(tlsConn.Host(), fmt.Sprintf("%d", port))
			req, err := http.NewRequest("CONNECT", target, nil)
			if err != nil {
				log.Warn("failed to create request", zap.Error(err))
				return
			}
			req.URL.Opaque = target
			for k, v := range header {
				for _, vv := range v {
					req.Header.Add(k, vv)
				}
			}
			if err := req.Write(upstream); err != nil {
				log.Warn("failed to write request", zap.Error(err))
				return
			}
			res, err := http.ReadResponse(bufio.NewReader(upstream), req)
			if err != nil {
				log.Warn("failed to read response", zap.Error(err))
				return
			}
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				log.Warn("failed to connect", zap.String("status", res.Status))
				return
			}
			if err := pipe(upstream, tlsConn, c, res.Body); err != nil {
				log.Warn("failed to pipe data", zap.Error(err))
				return
			}
		}(conn)
	}
}

func setupAnyTCP(s *netstack.Net, cache *flowcache.FlowCache) error {
	anyTCPListener, err := s.ListenTCP(&net.TCPAddr{Port: 1})
	if err != nil {
		return err
	}
	defer anyTCPListener.Close()

	for {
		conn, err := anyTCPListener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			flow := cache.Get(conn.RemoteAddr())
			upstream, err := net.Dial(flow.Proto, net.JoinHostPort(flow.Daddr.String(), fmt.Sprintf("%d", flow.Dport)))
			if err != nil {
				log.Warn("failed to dial upstream", zap.Error(err))
				return
			}
			defer upstream.Close()
			if err := pipe(upstream, c, c, upstream); err != nil {
				log.Warn("failed to pipe data", zap.Error(err))
				return
			}
		}(conn)
	}
}

func setupDNS(s *netstack.Net, dnsForwarders []netip.Addr) error {
	dnsmux := dns.NewServeMux()
	dnsmux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		for _, forwarder := range dnsForwarders {
			response, err := dns.Exchange(r, net.JoinHostPort(forwarder.String(), "53"))
			if err == nil {
				w.WriteMsg(response)
				return
			}
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
	})

	dnsUDPListener, err := s.ListenUDP(&net.UDPAddr{Port: 53})
	if err != nil {
		return err
	}
	defer dnsUDPListener.Close()

	dnsTCPListener, err := s.ListenTCP(&net.TCPAddr{Port: 53})
	if err != nil {
		return err
	}
	defer dnsTCPListener.Close()

	errCh := make(chan error, 1)
	go func() {
		if err := dns.ActivateAndServe(nil, dnsUDPListener, dnsmux); err != nil {
			errCh <- fmt.Errorf("failed to start DNS server: %w", err)
		}
	}()
	go func() {
		if err := dns.ActivateAndServe(dnsTCPListener, nil, dnsmux); err != nil {
			errCh <- fmt.Errorf("failed to start DNS server: %w", err)
		}
	}()
	return <-errCh
}

func pipe(
	dst1 io.Writer, src1 io.Reader,
	dst2 io.Writer, src2 io.Reader,
) error {
	ch := make(chan error, 1)
	go func() {
		if _, err := io.Copy(dst1, src1); err != nil {
			ch <- err
		}
	}()
	go func() {
		if _, err := io.Copy(dst2, src2); err != nil {
			ch <- err
		}
	}()
	return <-ch
}

func GetAddr() (netip.Addr, error) {
	host, err := os.Hostname()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get hostname: %w", err)
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		_addrs, err := net.InterfaceAddrs()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to get interface addresses: %w", err)
		}
		addrs = make([]net.IP, len(_addrs))
		for i, addr := range _addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				return netip.Addr{}, fmt.Errorf("failed to convert interface address to IPNet: %w", err)
			}
			addrs[i] = ipnet.IP
		}
	}
	var filtered []net.IP
	for _, addr := range addrs {
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		if addr4 := addr.To4(); addr4 != nil {
			filtered = append(filtered, addr4)
		} else if addr6 := addr.To16(); addr6 != nil {
			filtered = append(filtered, addr6)
		}
	}
	slices.SortFunc(filtered, func(a, b net.IP) int {
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
	if len(filtered) == 0 {
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	addr, ok := netip.AddrFromSlice(filtered[0])
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed to convert IP address to netip.Addr: %w", err)
	}
	return addr, nil
}
