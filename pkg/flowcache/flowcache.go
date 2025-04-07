package flowcache

import (
	"net"
	"strconv"

	lru "github.com/hashicorp/golang-lru/v2"
)

const KeySize = 1 + 16 + 2
const CacheSize = 128

type FlowCache struct {
	cache *lru.Cache[[KeySize]byte, *Flow]
}

type Flow struct {
	Proto string
	Saddr net.IP
	Daddr net.IP
	Sport uint16
	Dport uint16
}

func NewFlowCache() (*FlowCache, error) {
	cache, err := lru.New[[KeySize]byte, *Flow](CacheSize)
	if err != nil {
		return nil, err
	}
	return &FlowCache{
		cache: cache,
	}, nil
}

func (fc *FlowCache) Get(saddr net.Addr) *Flow {
	if saddr == nil {
		panic("nil address")
	}
	sproto, saddrIP, sport := extractAddr(saddr)
	entry, ok := fc.cache.Get(key(sproto, saddrIP, sport))
	if !ok {
		return nil
	}
	return entry
}

func (fc *FlowCache) Set(saddr net.Addr, daddr net.Addr) {
	if saddr == nil || daddr == nil {
		panic("nil address")
	}
	sproto, saddrIP, sport := extractAddr(saddr)
	dproto, daddrIP, dport := extractAddr(daddr)
	if sproto != dproto {
		panic("protocol mismatch")
	}
	entry := &Flow{
		Proto: protoToStr(sproto),
		Saddr: saddrIP,
		Daddr: daddrIP,
		Sport: sport,
		Dport: dport,
	}
	fc.cache.Add(key(sproto, saddrIP, sport), entry)
}

func (f *Flow) Dst() string {
	if f.Dport == 0 {
		return f.Daddr.String()
	}
	return net.JoinHostPort(f.Daddr.String(), strconv.Itoa(int(f.Dport)))
}

func key(proto uint8, addr net.IP, port uint16) [KeySize]byte {
	addrb := addr.To16()
	ret := [KeySize]byte{}
	ret[0] = proto
	copy(ret[1:17], addrb)
	ret[17] = byte(port >> 8)
	ret[18] = byte(port)
	return ret
}

func extractAddr(addr net.Addr) (proto uint8, ip net.IP, port uint16) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return 17, addr.IP, uint16(addr.Port)
	case *net.TCPAddr:
		return 6, addr.IP, uint16(addr.Port)
	case *net.IPAddr:
		return 0, addr.IP, 0
	default:
		panic("unknown address type")
	}
}

func protoToStr(proto uint8) string {
	switch proto {
	case 0:
		return "ip"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		panic("unknown protocol")
	}
}
