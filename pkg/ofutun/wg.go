package ofutun

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"unsafe"

	"github.com/hrntknr/ofutun/pkg/flowcache"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func setupNetStack(
	localIP []netip.Addr,
	configs []string,
	cache *flowcache.FlowCache,
	httpPort []uint16,
	httpsPort []uint16,
	proxyOnly bool,
) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		localIP,
		localIP,
		1420,
	)
	if err != nil {
		return nil, err
	}
	localDNS := []netip.AddrPort{}
	for _, ip := range localIP {
		localDNS = append(localDNS, netip.AddrPortFrom(ip, 53))
	}
	s := unsafeGetStack(tnet)
	ipt := s.IPTables()
	rules4 := []stack.Rule{}
	rules6 := []stack.Rule{}
	for _, port := range httpPort {
		rules4 = append(rules4, stack.Rule{
			Matchers: []stack.Matcher{
				&matcher{DPort: []uint16{port}, Cache: cache},
			},
			Target: &stack.RedirectTarget{
				Port:            port,
				NetworkProtocol: header.IPv4ProtocolNumber,
			},
		})
		rules6 = append(rules6, stack.Rule{
			Matchers: []stack.Matcher{
				&matcher{DPort: []uint16{port}, Cache: cache},
			},
			Target: &stack.RedirectTarget{
				Port:            port,
				NetworkProtocol: header.IPv6ProtocolNumber,
			},
		})
	}
	for _, port := range httpsPort {
		rules4 = append(rules4, stack.Rule{
			Matchers: []stack.Matcher{
				&matcher{DPort: []uint16{port}, Cache: cache},
			},
			Target: &stack.RedirectTarget{
				Port:            port,
				NetworkProtocol: header.IPv4ProtocolNumber,
			},
		})
		rules6 = append(rules6, stack.Rule{
			Matchers: []stack.Matcher{
				&matcher{DPort: []uint16{port}, Cache: cache},
			},
			Target: &stack.RedirectTarget{
				Port:            port,
				NetworkProtocol: header.IPv6ProtocolNumber,
			},
		})
	}
	dport := []uint16{}
	dport = append(dport, httpPort...)
	dport = append(dport, httpsPort...)
	if !proxyOnly {
		rules4 = append(rules4, stack.Rule{
			Matchers: []stack.Matcher{
				&matcher{DPort: dport, DAddrPort: localDNS, Not: true, Cache: cache},
			},
			Target: &stack.RedirectTarget{
				Port:            1,
				NetworkProtocol: header.IPv4ProtocolNumber,
			},
		})
		rules6 = append(rules6, stack.Rule{
			Matchers: []stack.Matcher{
				&matcher{DPort: dport, DAddrPort: localDNS, Not: true, Cache: cache},
			},
			Target: &stack.RedirectTarget{
				Port:            1,
				NetworkProtocol: header.IPv6ProtocolNumber,
			},
		})
	}
	ipt.ReplaceTable(stack.NATID, stack.Table{
		Rules: append(rules4, []stack.Rule{
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		}...),
		BuiltinChains: [stack.NumHooks]int{0, len(rules4) + 1, len(rules4) + 2, len(rules4) + 3, len(rules4) + 4},
	}, false)
	ipt.ReplaceTable(stack.NATID, stack.Table{
		Rules: append(rules6, []stack.Rule{
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
			{Target: &stack.ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
		}...),
		BuiltinChains: [stack.NumHooks]int{0, len(rules6) + 1, len(rules6) + 2, len(rules6) + 3, len(rules6) + 4},
	}, true)

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	if err := dev.IpcSet(strings.Join(configs, "\n")); err != nil {
		return nil, err
	}
	if err := dev.Up(); err != nil {
		return nil, err
	}
	return tnet, nil
}

func unsafeGetStack(tnet *netstack.Net) *stack.Stack {
	v := reflect.ValueOf(tnet).Elem()
	p := v.FieldByIndex([]int{1, 0})
	return (*stack.Stack)(unsafe.Pointer(p.UnsafeAddr()))
}

type matcher struct {
	DPort     []uint16
	DAddrPort []netip.AddrPort
	Not       bool
	Cache     *flowcache.FlowCache
}

func (tm *matcher) Match(hook stack.Hook, pkt stack.PacketBufferPtr, _, _ string) (bool, bool) {
	var proto tcpip.TransportProtocolNumber
	var saddr, daddr tcpip.Address
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		netHeader := header.IPv4(pkt.NetworkHeader().Slice())
		proto = netHeader.TransportProtocol()
		if proto != header.TCPProtocolNumber && proto != header.UDPProtocolNumber {
			return false, false
		}
		if frag := netHeader.FragmentOffset(); frag != 0 {
			if frag == 1 {
				return false, true
			}
			return false, false
		}
		saddr = netHeader.SourceAddress()
		daddr = netHeader.DestinationAddress()
	case header.IPv6ProtocolNumber:
		netHeader := header.IPv6(pkt.NetworkHeader().Slice())
		proto = netHeader.TransportProtocol()
		if proto != header.TCPProtocolNumber && proto != header.UDPProtocolNumber {
			return false, false
		}
		saddr = netHeader.SourceAddress()
		daddr = netHeader.DestinationAddress()
	default:
		return false, false
	}
	var sport, dport uint16
	switch proto {
	case header.TCPProtocolNumber:
		tcpHeader := header.TCP(pkt.TransportHeader().Slice())
		if len(tcpHeader) < header.TCPMinimumSize {
			return false, true
		}
		sport = tcpHeader.SourcePort()
		dport = tcpHeader.DestinationPort()
	case header.UDPProtocolNumber:
		udpHeader := header.UDP(pkt.TransportHeader().Slice())
		if len(udpHeader) < header.UDPMinimumSize {
			return false, true
		}
		sport = udpHeader.SourcePort()
		dport = udpHeader.DestinationPort()
	}

	var action bool
	if tm.Not {
		action = !(slices.Contains(tm.DPort, dport) ||
			slices.ContainsFunc(tm.DAddrPort, addrPortEq(daddr, dport)))
	} else {
		action = slices.Contains(tm.DPort, dport) ||
			slices.ContainsFunc(tm.DAddrPort, addrPortEq(daddr, dport))
	}
	if action {
		tm.Cache.Set(proto, saddr, daddr, sport, dport)
	}

	return action, false
}

func addrPortEq(addr tcpip.Address, port uint16) func(netip.AddrPort) bool {
	return func(a netip.AddrPort) bool {
		if a.Port() != port {
			return false
		}
		addrS, _ := netip.AddrFromSlice(addr.AsSlice())
		return a.Addr().Compare(addrS) == 0
	}
}
