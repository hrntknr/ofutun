package ofutun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
)

func pipe(
	dst1 io.Writer, src1 io.Reader,
	dst2 io.Writer, src2 io.Reader,
) error {
	ch := make(chan error, 1)
	go func() {
		if _, err := io.Copy(dst1, src1); err != nil {
			if checkErr(err) {
				ch <- nil
				return
			}
			ch <- err
		}
	}()
	go func() {
		if _, err := io.Copy(dst2, src2); err != nil {
			if checkErr(err) {
				ch <- nil
				return
			}
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

func checkErr(err error) bool {
	if _, ok := err.(*net.OpError); ok {
		return true
	}
	return errors.Is(err, io.EOF)
}
