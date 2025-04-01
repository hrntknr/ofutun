package ofutun

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

func DialProxy(url *url.URL, proxyInsecureSkipVerify bool) (net.Conn, http.Header, error) {
	switch url.Scheme {
	case "http":
		conn, err := net.Dial("tcp", url.Host)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to dial proxy: %w", err)
		}
		return conn, authHeader(url), nil
	case "https":
		conn, err := tls.Dial("tcp", url.Host, &tls.Config{
			InsecureSkipVerify: proxyInsecureSkipVerify,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to dial proxy: %w", err)
		}
		return conn, authHeader(url), nil
	default:
		return nil, nil, fmt.Errorf("unsupported scheme: %s", url.Scheme)
	}
}

func authHeader(url *url.URL) http.Header {
	if url.User == nil {
		return nil
	}
	auth := http.Header{}
	user := url.User.Username()
	pass, _ := url.User.Password()
	auth.Set("Proxy-Authorization", fmt.Sprintf("Basic %s", basicAuth(user, pass)))
	return auth
}

func basicAuth(user, pass string) string {
	auth := fmt.Sprintf("%s:%s", user, pass)
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func NewProxyDialer(url *url.URL, proxyInsecureSkipVerify bool) ProxyDialer {
	return func() (net.Conn, http.Header, error) {
		return DialProxy(url, proxyInsecureSkipVerify)
	}
}

type ProxyDialer func() (net.Conn, http.Header, error)
