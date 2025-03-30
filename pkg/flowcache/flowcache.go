package flowcache

import (
	"net"

	lru "github.com/hashicorp/golang-lru/v2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const v4KeySize = 1 + 4 + 2
const v6KeySize = 1 + 16 + 2
const v4CacheSize = 128
const v6CacheSize = 128

func NewFlowCache() (*FlowCache, error) {
	v4, err := lru.New[[v4KeySize]byte, *Flow](v4CacheSize)
	if err != nil {
		return nil, err
	}
	v6, err := lru.New[[v6KeySize]byte, *Flow](v6CacheSize)
	if err != nil {
		return nil, err
	}
	return &FlowCache{
		v4: v4,
		v6: v6,
	}, nil
}

func (fc *FlowCache) Get(addr net.Addr) *Flow {
	var proto tcpip.TransportProtocolNumber
	switch addr.Network() {
	case "tcp":
		proto = header.TCPProtocolNumber
	case "udp":
		proto = header.UDPProtocolNumber
	default:
		return nil
	}
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return fc.get(proto, tcpip.AddrFromSlice(addr.IP), uint16(addr.Port))
	case *net.TCPAddr:
		return fc.get(proto, tcpip.AddrFromSlice(addr.IP), uint16(addr.Port))
	case *net.IPAddr:
		return fc.get(proto, tcpip.AddrFromSlice(addr.IP), 0)
	}
	return nil
}

func (fc *FlowCache) get(proto tcpip.TransportProtocolNumber, saddr tcpip.Address, sport uint16) *Flow {
	if saddr.Len() != 4 && saddr.Len() != 16 {
		return nil
	}
	if saddr.Len() == 4 {
		if entry, ok := fc.v4.Get(v4key(proto, saddr, sport)); ok {
			return entry
		}
	}
	if saddr.Len() == 16 {
		if entry, ok := fc.v6.Get(v6key(proto, saddr, sport)); ok {
			return entry
		}
	}
	return nil
}

func (fc *FlowCache) Set(proto tcpip.TransportProtocolNumber, saddr, daddr tcpip.Address, sport, dport uint16) {
	if saddr.Len() != 4 && saddr.Len() != 16 {
		return
	}
	var protoStr string
	switch proto {
	case header.TCPProtocolNumber:
		protoStr = "tcp"
	case header.UDPProtocolNumber:
		protoStr = "udp"
	default:
		return
	}
	entry := &Flow{
		Proto: protoStr,
		Saddr: saddr.AsSlice(),
		Daddr: daddr.AsSlice(),
		Sport: sport,
		Dport: dport,
	}
	if saddr.Len() == 4 {
		fc.v4.Add(v4key(proto, saddr, sport), entry)
	}
	if saddr.Len() == 16 {
		fc.v6.Add(v6key(proto, saddr, sport), entry)
	}
}

func v4key(proto tcpip.TransportProtocolNumber, saddr tcpip.Address, sport uint16) [v4KeySize]byte {
	saddrb := saddr.As4()
	return [v4KeySize]byte{
		byte(proto),
		saddrb[0], saddrb[1], saddrb[2], saddrb[3],
		byte(sport >> 8), byte(sport),
	}
}

func v6key(proto tcpip.TransportProtocolNumber, saddr tcpip.Address, sport uint16) [v6KeySize]byte {
	saddrb := saddr.As16()
	return [v6KeySize]byte{
		byte(proto),
		saddrb[0], saddrb[1], saddrb[2], saddrb[3],
		saddrb[4], saddrb[5], saddrb[6], saddrb[7],
		saddrb[8], saddrb[9], saddrb[10], saddrb[11],
		saddrb[12], saddrb[13], saddrb[14], saddrb[15],
		byte(sport >> 8), byte(sport),
	}
}

type FlowCache struct {
	v4 *lru.Cache[[v4KeySize]byte, *Flow]
	v6 *lru.Cache[[v6KeySize]byte, *Flow]
}

type Flow struct {
	Proto string
	Saddr net.IP
	Daddr net.IP
	Sport uint16
	Dport uint16
}
