package tunnel

import (
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/FashionFarmer/tun2socks/v2/proxy/reject"
	"github.com/FashionFarmer/tun2socks/v2/tunnel/statistic"
)

func TestGlobalTunnelStartsLazily(t *testing.T) {
	if _globalT != nil {
		t.Fatal("global tunnel was initialized during package import")
	}
	first := T()
	if first == nil || T() != first {
		t.Fatal("global tunnel initialization is not stable")
	}
	first.Close()
	statistic.DefaultManager.Close()
}

type testTCPConn struct{ net.Conn }

func (testTCPConn) ID() stack.TransportEndpointID { return stack.TransportEndpointID{} }

func TestHandleAfterCloseDoesNotBlock(t *testing.T) {
	manager := statistic.NewManager()
	defer manager.Close()
	tunnel := New(&reject.Reject{}, manager)
	tunnel.ProcessAsync()
	tunnel.Close()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		tunnel.HandleTCP(testTCPConn{Conn: client})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleTCP blocked after tunnel close")
	}
	if _, err := client.Write([]byte{1}); err == nil {
		t.Fatal("rejected TCP connection remained open")
	}
}
