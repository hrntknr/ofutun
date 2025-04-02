package ofutun

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
	"github.com/go-playground/assert/v2"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestHTTPWithProxy(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, url, httpPort := setupHTTPServer(false, false)
	defer server.Close()
	proxy, proxyURL, _, log := setupProxy(false, false, false)
	defer proxy.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		proxyURL,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{httpPort},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	req, err := http.NewRequest("GET", url.String(), nil)
	assert.Equal(t, err, nil)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	assert.Equal(t, err, nil)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(b), "pong")
	assert.Equal(t, len(log.http), 1)
	assert.Equal(t, log.http[0], url.String())
}

func TestHTTPSWithProxy(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, url, httpsPort := setupHTTPServer(false, true)
	defer server.Close()
	proxy, proxyURL, _, log := setupProxy(false, false, false)
	defer proxy.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		proxyURL,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{},
		[]uint16{httpsPort},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	req, err := http.NewRequest("GET", url.String(), nil)
	assert.Equal(t, err, nil)
	host, _, err := net.SplitHostPort(url.Host)
	assert.Equal(t, err, nil)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host + ".nip.io",
			},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	assert.Equal(t, err, nil)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(b), "pong")
	assert.Equal(t, len(log.https), 1)
	assert.Equal(t, log.https[0], fmt.Sprintf("%s:%d", host, httpsPort))
}

func TestHTTPWithHTTPSProxy(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, url, httpPort := setupHTTPServer(false, false)
	defer server.Close()
	proxy, proxyURL, _, log := setupProxy(false, true, false)
	defer proxy.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		proxyURL,
		true,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{httpPort},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	req, err := http.NewRequest("GET", url.String(), nil)
	assert.Equal(t, err, nil)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	assert.Equal(t, err, nil)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(b), "pong")
	assert.Equal(t, len(log.http), 1)
	assert.Equal(t, log.http[0], url.String())
}

func TestHTTPWithProxyAuth(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, url, httpPort := setupHTTPServer(false, false)
	defer server.Close()
	proxy, proxyURL, _, log := setupProxy(false, false, true)
	defer proxy.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		proxyURL,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{httpPort},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	req, err := http.NewRequest("GET", url.String(), nil)
	assert.Equal(t, err, nil)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	assert.Equal(t, err, nil)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(b), "pong")
	assert.Equal(t, len(log.http), 1)
	assert.Equal(t, log.http[0], url.String())
}

func TestHTTPNoProxy(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, url, httpPort := setupHTTPServer(false, false)
	defer server.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		nil,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{httpPort},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	req, err := http.NewRequest("GET", url.String(), nil)
	assert.Equal(t, err, nil)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	assert.Equal(t, err, nil)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(b), "pong")
}

func TestHTTPSWithProxyNoSNI(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, url, httpsPort := setupHTTPServer(false, true)
	defer server.Close()
	proxy, proxyURL, _, log := setupProxy(false, false, false)
	defer proxy.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		proxyURL,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{},
		[]uint16{httpsPort},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	req, err := http.NewRequest("GET", url.String(), nil)
	assert.Equal(t, err, nil)
	host, _, err := net.SplitHostPort(url.Host)
	assert.Equal(t, err, nil)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	assert.Equal(t, err, nil)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)
	assert.Equal(t, string(b), "pong")
	assert.Equal(t, len(log.https), 1)
	assert.Equal(t, log.https[0], fmt.Sprintf("%s:%d", host, httpsPort))
}

func TestTCP(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, target, _ := setupTCPDNSServer(false)
	defer server.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		nil,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	queryTestTCPDNS(t, tnet, target)
}

func TestUDP(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("192.168.0.1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("192.168.0.2")},
	}
	server, target, _ := setupUDPDNSServer(false)
	defer server.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		nil,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	queryTestUDPDNS(t, tnet, target)
}

func TestTCPIPv6(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("fc00::1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("fc00::2")},
	}
	server, target, _ := setupTCPDNSServer(true)
	defer server.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		nil,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	queryTestTCPDNS(t, tnet, target)
}

func TestUDPIPv6(t *testing.T) {
	priv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	peerPriv, err := NewPrivateKey()
	assert.Equal(t, err, nil)
	localIP := []netip.Addr{netip.MustParseAddr("fc00::1")}
	peer := Peer{
		PublicKey:  PublicKey(peerPriv),
		PrivateKey: peerPriv,
		IP:         []netip.Addr{netip.MustParseAddr("fc00::2")},
	}
	server, target, _ := setupUDPDNSServer(true)
	defer server.Close()
	o, err := NewOfutun(
		zap.NewNop(),
		nil,
		false,
		localIP,
		priv,
		0,
		[]Peer{peer},
		[]netip.Addr{},
		[]uint16{},
		[]uint16{},
		false,
	)
	assert.Equal(t, err, nil)
	defer o.Close()
	go o.Run()
	port := getPort(o)
	_, tnet := setupClient(port, localIP, PublicKey(priv), peer)
	queryTestUDPDNS(t, tnet, target)
}

func TestPrintPeerConfig(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	endpoint, _ := netip.AddrFromSlice(net.ParseIP("10.0.0.2").To4())
	localIP, _ := netip.AddrFromSlice(net.ParseIP("192.168.0.1").To4())
	publickey, _ := base64.StdEncoding.DecodeString("FXKZLGcK2t341Wd6gID6uFSEmXxgv0I+XOia56yVSW8=")
	peer1IP, _ := netip.AddrFromSlice(net.ParseIP("192.168.0.2").To4())
	peer1Priv, _ := base64.StdEncoding.DecodeString("IBrZ67n4Uc3kP6DDHLcE9zHsOb/YPzo5lFMJoJp9wlE=")
	peer2IP, _ := netip.AddrFromSlice(net.ParseIP("192.168.0.3").To4())
	peer2Priv, _ := base64.StdEncoding.DecodeString("AMPTTU8tLnLWfz+CxCAu2+ZRIPrY2Dp6COIImv2Gfkc=")
	peer := []Peer{{
		PublicKey:  PublicKey(peer1Priv),
		PrivateKey: peer1Priv,
		IP:         []netip.Addr{peer1IP},
	}, {
		PublicKey:  PublicKey(peer2Priv),
		PrivateKey: nil,
		IP:         []netip.Addr{peer2IP},
	}}
	PrintPeerConfigs(buf, netip.AddrPortFrom(endpoint, 51820), []netip.Addr{localIP}, publickey, peer, false)
	assert.Equal(t, buf.String(), strings.Join([]string{
		"----------- Peer 1 -----------",
		"[Interface]",
		"PrivateKey = IBrZ67n4Uc3kP6DDHLcE9zHsOb/YPzo5lFMJoJp9wlE=",
		"Address = 192.168.0.2/32",
		"DNS = 192.168.0.1",
		"MTU = 1420",
		"",
		"[Peer]",
		"PublicKey = FXKZLGcK2t341Wd6gID6uFSEmXxgv0I+XOia56yVSW8=",
		"AllowedIPs = 0.0.0.0/0,::/0",
		"Endpoint = 10.0.0.2:51820",
		"PersistentKeepalive = 25",
		"----------- Peer 2 -----------",
		"[Interface]",
		"PrivateKey = {private_key}",
		"Address = 192.168.0.3/32",
		"DNS = 192.168.0.1",
		"MTU = 1420",
		"",
		"[Peer]",
		"PublicKey = FXKZLGcK2t341Wd6gID6uFSEmXxgv0I+XOia56yVSW8=",
		"AllowedIPs = 0.0.0.0/0,::/0",
		"Endpoint = 10.0.0.2:51820",
		"PersistentKeepalive = 25",
		"",
	}, "\n"))
}

func getPort(o *Ofutun) int {
	c, _ := o.dev.IpcGet()
	clines := strings.Split(c, "\n")
	port := 0
	for _, line := range clines {
		if strings.HasPrefix(line, "listen_port=") {
			_port, err := strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
			if err != nil {
				panic(err)
			}
			port = _port
			break
		}
	}
	return port
}

func setupClient(port int, localIP []netip.Addr, pub []byte, peer Peer) (tun.Device, *netstack.Net) {
	tun, tnet, err := netstack.CreateNetTUN(peer.IP, localIP, 1420)
	if err != nil {
		panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	err = dev.IpcSet(strings.Join([]string{
		"private_key=" + hex.EncodeToString(peer.PrivateKey),
		"public_key=" + hex.EncodeToString(pub),
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"endpoint=127.0.0.1:" + strconv.Itoa(port),
	}, "\n"))
	if err != nil {
		panic(err)
	}
	err = dev.Up()
	if err != nil {
		panic(err)
	}
	return tun, tnet
}

func setupHTTPServer(ipv6 bool, tls bool) (net.Listener, *url.URL, uint16) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "pong")
	})
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	if tls {
		dname, err := os.MkdirTemp("", "certs")
		if err != nil {
			panic(err)
		}
		certFile := dname + "/cert.pem"
		keyFile := dname + "/key.pem"
		err = os.WriteFile(certFile, LocalhostCert, 0644)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(keyFile, LocalhostKey, 0644)
		if err != nil {
			panic(err)
		}
		go http.ServeTLS(listener, mux, certFile, keyFile)
	} else {
		go http.Serve(listener, mux)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	host := net.JoinHostPort(getLocalAddr(ipv6).String(), strconv.Itoa(port))
	prefix := "http://"
	if tls {
		prefix = "https://"
	}
	u, err := url.Parse(prefix + host + "/ping")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := net.Dial("tcp", host)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return listener, u, uint16(port)
}

type proxyLog struct {
	https []string
	http  []string
}

func setupProxy(ipv6 bool, tls bool, authEnabled bool) (net.Listener, *url.URL, uint16, *proxyLog) {
	log := &proxyLog{
		https: []string{},
		http:  []string{},
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		log.https = append(log.https, host)
		return goproxy.OkConnect, host
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.http = append(log.http, req.URL.String())
		return req, nil
	})
	if authEnabled {
		auth.ProxyBasic(proxy, "RELM", func(user, passwd string) bool {
			return user == "user" && passwd == "pass"
		})
	}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	if tls {
		dname, err := os.MkdirTemp("", "certs")
		if err != nil {
			panic(err)
		}
		certFile := dname + "/cert.pem"
		keyFile := dname + "/key.pem"
		err = os.WriteFile(certFile, LocalhostCert, 0644)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(keyFile, LocalhostKey, 0644)
		if err != nil {
			panic(err)
		}
		go http.ServeTLS(listener, proxy, certFile, keyFile)
	} else {
		go http.Serve(listener, proxy)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	host := net.JoinHostPort(getLocalAddr(ipv6).String(), strconv.Itoa(port))
	prefix := "http://"
	if tls {
		prefix = "https://"
	}
	u, err := url.Parse(prefix + host)
	if err != nil {
		panic(err)
	}
	if authEnabled {
		u.User = url.UserPassword("user", "pass")
	}
	for {
		conn, err := net.Dial("tcp", host)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return listener, u, uint16(port), log
}

func setupTCPDNSServer(ipv6 bool) (net.Listener, string, uint16) {
	dnsmux := dns.NewServeMux()
	dnsmux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = false
		m.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: []string{"TCP response"},
			},
		}
		w.WriteMsg(m)
	})

	dnsTCPListener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	if err != nil {
		panic(err)
	}
	go dns.ActivateAndServe(dnsTCPListener, nil, dnsmux)
	port := dnsTCPListener.Addr().(*net.TCPAddr).Port
	host := net.JoinHostPort(getLocalAddr(ipv6).String(), strconv.Itoa(port))
	return dnsTCPListener, host, uint16(port)
}

func setupUDPDNSServer(ipv6 bool) (net.Conn, string, uint16) {
	dnsmux := dns.NewServeMux()
	dnsmux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = false
		m.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: []string{"UDP response"},
			},
		}
		w.WriteMsg(m)
	})

	dnsUDPListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		panic(err)
	}
	go dns.ActivateAndServe(nil, dnsUDPListener, dnsmux)
	port := dnsUDPListener.LocalAddr().(*net.UDPAddr).Port
	host := net.JoinHostPort(getLocalAddr(ipv6).String(), strconv.Itoa(port))
	return dnsUDPListener, host, uint16(port)
}

func queryTestTCPDNS(t *testing.T, tnet *netstack.Net, target string) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	conn := new(dns.Conn)
	var err error
	conn.Conn, err = tnet.Dial("tcp", target)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := conn.WriteMsg(m); err != nil {
		panic(err)
	}
	msg, err := conn.ReadMsg()
	if err != nil {
		panic(err)
	}
	assert.Equal(t, msg.Rcode, dns.RcodeSuccess)
	assert.Equal(t, len(msg.Answer), 1)
	msgTXT := msg.Answer[0].(*dns.TXT)
	assert.Equal(t, msgTXT.Hdr.Rrtype, dns.TypeTXT)
	assert.Equal(t, msgTXT.Txt[0], "TCP response")

}

func queryTestUDPDNS(t *testing.T, tnet *netstack.Net, target string) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	conn := new(dns.Conn)
	var err error
	conn.Conn, err = tnet.Dial("udp", target)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := conn.WriteMsg(m); err != nil {
		panic(err)
	}
	msg, err := conn.ReadMsg()
	if err != nil {
		panic(err)
	}
	assert.Equal(t, msg.Rcode, dns.RcodeSuccess)
	assert.Equal(t, len(msg.Answer), 1)
	msgTXT := msg.Answer[0].(*dns.TXT)
	assert.Equal(t, msgTXT.Hdr.Rrtype, dns.TypeTXT)
	assert.Equal(t, msgTXT.Txt[0], "UDP response")
}

func getLocalAddr(ipv6 bool) net.IP {
	addr, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}

	for _, a := range addr {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.IsPrivate() || ipnet.IP.IsGlobalUnicast() {
				if (ipv6 && ipnet.IP.To4() == nil) || (!ipv6 && ipnet.IP.To4() != nil) {
					return ipnet.IP
				}
			}
		}
	}
	panic("no suitable host found")
}

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 2048 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIQSRJrEpBGFc7tNb1fb5pKFzANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA6Gba5tHV1dAKouAaXO3/ebDUU4rvwCUg/CNaJ2PT5xLD4N1Vcb8r
bFSW2HXKq+MPfVdwIKR/1DczEoAGf/JWQTW7EgzlXrCd3rlajEX2D73faWJekD0U
aUgz5vtrTXZ90BQL7WvRICd7FlEZ6FPOcPlumiyNmzUqtwGhO+9ad1W5BqJaRI6P
YfouNkwR6Na4TzSj5BrqUfP0FwDizKSJ0XXmh8g8G9mtwxOSN3Ru1QFc61Xyeluk
POGKBV/q6RBNklTNe0gI8usUMlYyoC7ytppNMW7X2vodAelSu25jgx2anj9fDVZu
h7AXF5+4nJS4AAt0n1lNY7nGSsdZas8PbQIDAQABo4GIMIGFMA4GA1UdDwEB/wQE
AwICpDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBStsdjh3/JCXXYlQryOrL4Sh7BW5TAuBgNVHREEJzAlggtleGFtcGxlLmNv
bYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQsFAAOCAQEAxWGI
5NhpF3nwwy/4yB4i/CwwSpLrWUa70NyhvprUBC50PxiXav1TeDzwzLx/o5HyNwsv
cxv3HdkLW59i/0SlJSrNnWdfZ19oTcS+6PtLoVyISgtyN6DpkKpdG1cOkW3Cy2P2
+tK/tKHRP1Y/Ra0RiDpOAmqn0gCOFGz8+lqDIor/T7MTpibL3IxqWfPrvfVRHL3B
grw/ZQTTIVjjh4JBSW3WyWgNo/ikC1lrVxzl4iPUGptxT36Cr7Zk2Bsg0XqwbOvK
5d+NTDREkSnUbie4GeutujmX3Dsx88UiV6UY/4lHJa6I5leHUNOHahRbpbWeOfs/
WkBKOclmOV2xlTVuPw==
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for LocalhostCert.
var LocalhostKey = []byte(testingKey(`-----BEGIN RSA TESTING KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDoZtrm0dXV0Aqi
4Bpc7f95sNRTiu/AJSD8I1onY9PnEsPg3VVxvytsVJbYdcqr4w99V3AgpH/UNzMS
gAZ/8lZBNbsSDOVesJ3euVqMRfYPvd9pYl6QPRRpSDPm+2tNdn3QFAvta9EgJ3sW
URnoU85w+W6aLI2bNSq3AaE771p3VbkGolpEjo9h+i42TBHo1rhPNKPkGupR8/QX
AOLMpInRdeaHyDwb2a3DE5I3dG7VAVzrVfJ6W6Q84YoFX+rpEE2SVM17SAjy6xQy
VjKgLvK2mk0xbtfa+h0B6VK7bmODHZqeP18NVm6HsBcXn7iclLgAC3SfWU1jucZK
x1lqzw9tAgMBAAECggEABWzxS1Y2wckblnXY57Z+sl6YdmLV+gxj2r8Qib7g4ZIk
lIlWR1OJNfw7kU4eryib4fc6nOh6O4AWZyYqAK6tqNQSS/eVG0LQTLTTEldHyVJL
dvBe+MsUQOj4nTndZW+QvFzbcm2D8lY5n2nBSxU5ypVoKZ1EqQzytFcLZpTN7d89
EPj0qDyrV4NZlWAwL1AygCwnlwhMQjXEalVF1ylXwU3QzyZ/6MgvF6d3SSUlh+sq
XefuyigXw484cQQgbzopv6niMOmGP3of+yV4JQqUSb3IDmmT68XjGd2Dkxl4iPki
6ZwXf3CCi+c+i/zVEcufgZ3SLf8D99kUGE7v7fZ6AQKBgQD1ZX3RAla9hIhxCf+O
3D+I1j2LMrdjAh0ZKKqwMR4JnHX3mjQI6LwqIctPWTU8wYFECSh9klEclSdCa64s
uI/GNpcqPXejd0cAAdqHEEeG5sHMDt0oFSurL4lyud0GtZvwlzLuwEweuDtvT9cJ
Wfvl86uyO36IW8JdvUprYDctrQKBgQDycZ697qutBieZlGkHpnYWUAeImVA878sJ
w44NuXHvMxBPz+lbJGAg8Cn8fcxNAPqHIraK+kx3po8cZGQywKHUWsxi23ozHoxo
+bGqeQb9U661TnfdDspIXia+xilZt3mm5BPzOUuRqlh4Y9SOBpSWRmEhyw76w4ZP
OPxjWYAgwQKBgA/FehSYxeJgRjSdo+MWnK66tjHgDJE8bYpUZsP0JC4R9DL5oiaA
brd2fI6Y+SbyeNBallObt8LSgzdtnEAbjIH8uDJqyOmknNePRvAvR6mP4xyuR+Bv
m+Lgp0DMWTw5J9CKpydZDItc49T/mJ5tPhdFVd+am0NAQnmr1MCZ6nHxAoGABS3Y
LkaC9FdFUUqSU8+Chkd/YbOkuyiENdkvl6t2e52jo5DVc1T7mLiIrRQi4SI8N9bN
/3oJWCT+uaSLX2ouCtNFunblzWHBrhxnZzTeqVq4SLc8aESAnbslKL4i8/+vYZlN
s8xtiNcSvL+lMsOBORSXzpj/4Ot8WwTkn1qyGgECgYBKNTypzAHeLE6yVadFp3nQ
Ckq9yzvP/ib05rvgbvrne00YeOxqJ9gtTrzgh7koqJyX1L4NwdkEza4ilDWpucn0
xiUZS4SoaJq6ZvcBYS62Yr1t8n09iG47YL8ibgtmH3L+svaotvpVxVK+d7BLevA/
ZboOWVe3icTy64BT3OQhmg==
-----END RSA TESTING KEY-----`))

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
