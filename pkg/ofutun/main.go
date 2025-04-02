package ofutun

import (
	"bufio"
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
	"strings"
	"time"

	"github.com/boombuler/barcode/qr"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hrntknr/ofutun/pkg/flowcache"
	"github.com/inconshreveable/go-vhost"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Peer struct {
	PublicKey  []byte
	PrivateKey []byte
	IP         []netip.Addr
}

type output interface {
	io.StringWriter
	io.Writer
}

func PrintPeerConfigs(out output, endpoint netip.AddrPort, localIP []netip.Addr, publicKey []byte, peers []Peer, printQR bool) error {
	for n, peer := range peers {
		out.WriteString("----------- Peer " + fmt.Sprint(n+1) + " -----------\n")
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
		out.WriteString(strings.Join(line, "\n") + "\n")
		if !printQR {
			continue
		}
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
					out.Write([]byte("\033[40m  \033[0m"))
				} else {
					out.Write([]byte("\033[47m  \033[0m"))
				}
			}
			out.WriteString("\n")
		}
		out.WriteString("\n")
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

type Ofutun struct {
	log           *zap.Logger
	cache         *flowcache.FlowCache
	stack         *netstack.Net
	dev           *device.Device
	proxyDialer   ProxyDialer
	dnsForwarders []netip.Addr
	httpPort      []uint16
	httpsPort     []uint16
	proxyOnly     bool
	closed        bool
	closers       []io.Closer
}

func NewOfutun(
	log *zap.Logger,
	proxy *url.URL,
	proxyInsecureSkipVerify bool,
	localIP []netip.Addr,
	privateKey []byte,
	listenPort uint16,
	peers []Peer,
	dnsForwarders []netip.Addr,
	httpPort []uint16,
	httpsPort []uint16,
	ProxyOnly bool,
) (*Ofutun, error) {
	cache, err := flowcache.NewFlowCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create flow cache: %w", err)
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
				return nil, fmt.Errorf("failed to get prefix: %w", err)
			}
			configs = append(configs, fmt.Sprintf("allowed_ip=%s", pfx.String()))
		}
	}

	stack, dev, err := setupNetStack(localIP, configs, cache, proxy, httpPort, httpsPort, ProxyOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to setup netstack: %w", err)
	}

	var proxyDialer ProxyDialer
	if proxy != nil {
		proxyDialer = NewProxyDialer(proxy, proxyInsecureSkipVerify)
	}

	return &Ofutun{
		log:           log,
		cache:         cache,
		stack:         stack,
		dev:           dev,
		proxyDialer:   proxyDialer,
		dnsForwarders: dnsForwarders,
		httpPort:      httpPort,
		httpsPort:     httpsPort,
		proxyOnly:     ProxyOnly,
		closed:        false,
		closers:       []io.Closer{},
	}, nil
}

func (o *Ofutun) Run() error {
	go func() {
		for {
			if err := o.setupDNS(o.dnsForwarders); err != nil {
				if o.closed {
					return
				}
				o.log.Warn("failed to setup DNS", zap.Error(err))
				time.Sleep(5 * time.Second)
			}
		}
	}()
	if o.proxyDialer != nil {
		for _, port := range o.httpPort {
			go func(p uint16) {
				for {
					if err := o.setupHTTP(port); err != nil {
						if o.closed {
							return
						}
						o.log.Warn("failed to setup HTTP", zap.Error(err))
						time.Sleep(5 * time.Second)
					}
				}
			}(port)
		}
		for _, port := range o.httpsPort {
			go func(p uint16) {
				for {
					if err := o.setupHTTPS(port); err != nil {
						if o.closed {
							return
						}
						o.log.Warn("failed to setup HTTPS", zap.Error(err))
						time.Sleep(5 * time.Second)
					}
				}
			}(port)
		}
	}
	if !o.proxyOnly {
		go func() {
			for {
				if err := o.setupAnyTCP(); err != nil {
					if o.closed {
						return
					}
					o.log.Warn("failed to setup any TCP", zap.Error(err))
					time.Sleep(5 * time.Second)
				}
			}
		}()
		go func() {
			for {
				if err := o.setupAnyUDP(); err != nil {
					if o.closed {
						return
					}
					o.log.Warn("failed to setup any UDP", zap.Error(err))
					time.Sleep(5 * time.Second)
				}
			}
		}()
	}

	o.log.Info("ofutun started")
	select {}
}

func (o *Ofutun) setupHTTP(port uint16) error {
	httpListener, err := o.stack.ListenTCP(&net.TCPAddr{Port: int(port)})
	if err != nil {
		return err
	}
	o.closers = append(o.closers, httpListener)

	for {
		conn, err := httpListener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			flow := o.cache.Get(conn.RemoteAddr())
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				o.log.Warn("failed to read request", zap.Error(err))
				return
			}
			upstream, header, err := o.proxyDialer()
			if err != nil {
				o.log.Warn("failed to dial upstream", zap.Error(err))
				return
			}
			fmt.Println(flow.Dst())
			req.URL.Host = flow.Dst()
			req.URL.Opaque = "http://" + req.Host + req.URL.Path
			for k, v := range header {
				for _, vv := range v {
					req.Header.Add(k, vv)
				}
			}
			if err := req.Write(upstream); err != nil {
				if checkErr(err) {
					return
				}
				o.log.Warn("failed to write request", zap.Error(err))
				return
			}
			if err := pipe(upstream, c, c, upstream); err != nil {
				o.log.Warn("failed to pipe data", zap.Error(err))
				return
			}
		}(conn)
	}
}

func (o *Ofutun) setupHTTPS(port uint16) error {
	httpsListener, err := o.stack.ListenTCP(&net.TCPAddr{Port: int(port)})
	if err != nil {
		return err
	}
	o.closers = append(o.closers, httpsListener)

	for {
		conn, err := httpsListener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			flow := o.cache.Get(conn.RemoteAddr())
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				o.log.Warn("failed to upgrade to TLS", zap.Error(err))
				return
			}
			upstream, header, err := o.proxyDialer()
			if err != nil {
				o.log.Warn("failed to dial upstream", zap.Error(err))
				return
			}
			req, err := http.NewRequest("CONNECT", "", nil)
			if err != nil {
				o.log.Warn("failed to create request", zap.Error(err))
				return
			}
			fmt.Println(flow.Dst())
			req.URL.Opaque = flow.Dst()
			req.Host = flow.Dst()
			for k, v := range header {
				for _, vv := range v {
					req.Header.Add(k, vv)
				}
			}
			if err := req.Write(upstream); err != nil {
				if checkErr(err) {
					return
				}
				o.log.Warn("failed to write request", zap.Error(err))
				return
			}
			res, err := http.ReadResponse(bufio.NewReader(upstream), req)
			if err != nil {
				o.log.Warn("failed to read response", zap.Error(err))
				return
			}
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				o.log.Warn("failed to connect", zap.String("status", res.Status))
				return
			}
			if err := pipe(upstream, tlsConn, c, res.Body); err != nil {
				o.log.Warn("failed to pipe data", zap.Error(err))
				return
			}
		}(conn)
	}
}

func (o *Ofutun) setupAnyTCP() error {
	anyTCPListener, err := o.stack.ListenTCP(&net.TCPAddr{Port: 1})
	if err != nil {
		return err
	}
	o.closers = append(o.closers, anyTCPListener)

	for {
		conn, err := anyTCPListener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			flow := o.cache.Get(conn.RemoteAddr())
			upstream, err := net.Dial(flow.Proto, net.JoinHostPort(flow.Daddr.String(), fmt.Sprintf("%d", flow.Dport)))
			if err != nil {
				o.log.Warn("failed to dial upstream", zap.Error(err))
				return
			}
			defer upstream.Close()
			if err := pipe(upstream, c, c, upstream); err != nil {
				o.log.Warn("failed to pipe data", zap.Error(err))
				return
			}
		}(conn)
	}
}

const udpBufferSize = 65535
const udpTimeout = 30
const udpEntrySize = 128

func (o *Ofutun) setupAnyUDP() error {
	anyUDPListener, err := o.stack.ListenUDP(&net.UDPAddr{Port: 1})
	if err != nil {
		return err
	}
	o.closers = append(o.closers, anyUDPListener)

	conns := expirable.NewLRU(udpEntrySize, func(_ [18]byte, c net.Conn) { c.Close() }, udpTimeout*time.Second)
	buf := make([]byte, udpBufferSize)
	for {
		n, saddr, err := anyUDPListener.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("failed to read from UDP: %w", err)
		}
		flow := o.cache.Get(saddr)
		saddr16 := flow.Saddr.To16()
		key := [18]byte{
			saddr16[0], saddr16[1], saddr16[2], saddr16[3],
			saddr16[4], saddr16[5], saddr16[6], saddr16[7],
			saddr16[8], saddr16[9], saddr16[10], saddr16[11],
			saddr16[12], saddr16[13], saddr16[14], saddr16[15],
			byte(flow.Sport >> 8), byte(flow.Sport),
		}
		conn, ok := conns.Get(key)
		if !ok {
			target := net.JoinHostPort(flow.Daddr.String(), fmt.Sprintf("%d", flow.Dport))
			conn, err = net.Dial(flow.Proto, target)
			if err != nil {
				o.log.Warn("failed to dial upstream", zap.Error(err))
				continue
			}
			conns.Add(key, conn)
			go func(saddr net.Addr, conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, udpBufferSize)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						if checkErr(err) {
							return
						}
						o.log.Warn("failed to read from upstream", zap.Error(err))
						return
					}
					if _, err := anyUDPListener.WriteTo(buf[:n], saddr); err != nil {
						if checkErr(err) {
							return
						}
						o.log.Warn("failed to write to UDP", zap.Error(err))
						return
					}
				}
			}(saddr, conn)
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			if checkErr(err) {
				continue
			}
			o.log.Warn("failed to write to upstream", zap.Error(err))
			conn.Close()
			conns.Remove(key)
			continue
		}
	}
}

func (o *Ofutun) setupDNS(dnsForwarders []netip.Addr) error {
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

	dnsUDPListener, err := o.stack.ListenUDP(&net.UDPAddr{Port: 53})
	if err != nil {
		return err
	}
	o.closers = append(o.closers, dnsUDPListener)

	dnsTCPListener, err := o.stack.ListenTCP(&net.TCPAddr{Port: 53})
	if err != nil {
		return err
	}
	o.closers = append(o.closers, dnsTCPListener)

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

func (o *Ofutun) Close() error {
	if o.closed {
		return nil
	}
	o.closed = true
	for _, closer := range o.closers {
		if err := closer.Close(); err != nil {
			return fmt.Errorf("failed to close closer: %w", err)
		}
	}
	return nil
}
