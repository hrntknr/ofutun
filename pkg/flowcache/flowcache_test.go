package flowcache

import (
	"net"
	"testing"

	"github.com/go-playground/assert/v2"
)

func TestFlowCache(t *testing.T) {
	c, err := NewFlowCache()
	if err != nil {
		t.Fatalf("NewFlowCache() failed: %v", err)
	}
	flow1src := &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 1),
		Port: 8080,
	}
	flow2src := &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 2),
		Port: 8080,
	}
	c.Set(flow1src, flow2src)
	g1 := c.Get(flow1src)
	assert.Equal(t, g1.Saddr.String(), flow1src.IP.String())
	assert.Equal(t, g1.Daddr.String(), flow2src.IP.String())
	assert.Equal(t, g1.Sport, uint16(8080))
	assert.Equal(t, g1.Dport, uint16(8080))
	g2 := c.Get(flow2src)
	assert.Equal(t, g2, nil)
}
