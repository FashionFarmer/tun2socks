package tunnel

import (
	"runtime/debug"
	"sync"
	"time"

	"go.uber.org/atomic"

	"github.com/FashionFarmer/tun2socks/v2/core/adapter"
	"github.com/FashionFarmer/tun2socks/v2/log"
	"github.com/FashionFarmer/tun2socks/v2/proxy"
	"github.com/FashionFarmer/tun2socks/v2/tunnel/statistic"
)

const (
	// tcpConnectTimeout is the default timeout for TCP handshakes.
	tcpConnectTimeout = 5 * time.Second
	// tcpWaitTimeout implements a TCP half-close timeout.
	tcpWaitTimeout = 60 * time.Second
	// udpSessionTimeout is the default timeout for UDP sessions.
	udpSessionTimeout = 60 * time.Second
)

var _ adapter.TransportHandler = (*Tunnel)(nil)

type Tunnel struct {
	// Unbuffered TCP/UDP queues.
	tcpQueue chan adapter.TCPConn
	udpQueue chan adapter.UDPConn

	// UDP session timeout.
	udpTimeout *atomic.Duration

	// Internal proxy.Proxy for Tunnel.
	proxyMu sync.RWMutex
	proxy   proxy.Proxy

	// Where the Tunnel statistics are sent to.
	manager *statistic.Manager

	procOnce    sync.Once
	closeOnce   sync.Once
	done        chan struct{}
	processDone chan struct{}
}

func New(proxy proxy.Proxy, manager *statistic.Manager) *Tunnel {
	return &Tunnel{
		tcpQueue:    make(chan adapter.TCPConn),
		udpQueue:    make(chan adapter.UDPConn),
		udpTimeout:  atomic.NewDuration(udpSessionTimeout),
		proxy:       proxy,
		manager:     manager,
		done:        make(chan struct{}),
		processDone: make(chan struct{}),
	}
}

// HandleTCP queues a TCP flow unless the tunnel has already closed. Keeping
// the queue private prevents embedders from bypassing the close-aware path and
// blocking forever on a send after Close.
func (t *Tunnel) HandleTCP(conn adapter.TCPConn) {
	select {
	case t.tcpQueue <- conn:
	case <-t.done:
		_ = conn.Close()
	}
}

// HandleUDP has the same close-aware ownership semantics as HandleTCP.
func (t *Tunnel) HandleUDP(conn adapter.UDPConn) {
	select {
	case t.udpQueue <- conn:
	case <-t.done:
		_ = conn.Close()
	}
}

func (t *Tunnel) process() {
	for {
		select {
		case conn := <-t.tcpQueue:
			safeGo("handle TCP", func() { t.handleTCPConn(conn) })
		case conn := <-t.udpQueue:
			safeGo("handle UDP", func() { t.handleUDPConn(conn) })
		case <-t.done:
			return
		}
	}
}

// ProcessAsync can be safely called multiple times, but will only be effective once.
func (t *Tunnel) ProcessAsync() {
	t.procOnce.Do(func() {
		go func() {
			defer close(t.processDone)
			defer recoverPanic("process")
			t.process()
		}()
	})
}

// Close closes the Tunnel and releases its resources.
func (t *Tunnel) Close() {
	t.ProcessAsync()
	t.closeOnce.Do(func() { close(t.done) })
	<-t.processDone
}

func safeGo(name string, fn func()) {
	go func() {
		defer recoverPanic(name)
		fn()
	}()
}

func recoverPanic(name string) {
	if recovered := recover(); recovered != nil {
		log.Errorf("[TUNNEL] panic recovered in %s: %v\n%s", name, recovered, debug.Stack())
	}
}

func (t *Tunnel) Proxy() proxy.Proxy {
	t.proxyMu.RLock()
	p := t.proxy
	t.proxyMu.RUnlock()
	return p
}

func (t *Tunnel) SetProxy(proxy proxy.Proxy) {
	t.proxyMu.Lock()
	t.proxy = proxy
	t.proxyMu.Unlock()
}

func (t *Tunnel) SetUDPTimeout(timeout time.Duration) {
	t.udpTimeout.Store(timeout)
}
