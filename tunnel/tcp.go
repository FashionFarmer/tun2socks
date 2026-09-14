package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/FashionFarmer/tun2socks/v2/buffer"
	"github.com/FashionFarmer/tun2socks/v2/core/adapter"
	"github.com/FashionFarmer/tun2socks/v2/log"
	M "github.com/FashionFarmer/tun2socks/v2/metadata"
	"github.com/FashionFarmer/tun2socks/v2/tunnel/statistic"
)

func (t *Tunnel) handleTCPConn(originConn adapter.TCPConn) {
	defer originConn.Close()

	id := originConn.ID()
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   parseTCPIPAddress(id.RemoteAddress),
		SrcPort: id.RemotePort,
		DstIP:   parseTCPIPAddress(id.LocalAddress),
		DstPort: id.LocalPort,
	}

	// Sniff the client's leading bytes before dialing, so a route can be chosen
	// on the real protocol and host rather than the destination IP alone. The
	// bytes consumed are replayed into the pipe, so sniffing is transparent.
	src := net.Conn(originConn)
	if t.sniffer != nil {
		proto, host, outcome, prefix := sniffTCP(originConn, t.sniffer)
		metadata.Protocol, metadata.Host, metadata.SniffOutcome = proto, host, outcome
		if len(prefix) > 0 {
			src = &cachedConn{TCPConn: originConn, cache: prefix}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	remoteConn, err := t.Proxy().DialContext(ctx, metadata)
	if err != nil {
		log.Warnf("[TCP] dial %s: %v", metadata.DestinationAddress(), err)
		return
	}
	metadata.MidIP, metadata.MidPort = parseNetAddr(remoteConn.LocalAddr())

	remoteConn = statistic.NewTCPTracker(remoteConn, metadata, t.manager)
	defer remoteConn.Close()

	log.Infof("[TCP] %s <-> %s", metadata.SourceAddress(), metadata.DestinationAddress())
	pipe(src, remoteConn)
}

// pipe copies data to & from provided net.Conn(s) bidirectionally.
func pipe(origin, remote net.Conn) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	safeGo("TCP origin->remote", func() { unidirectionalStream(remote, origin, "origin->remote", &wg) })
	safeGo("TCP remote->origin", func() { unidirectionalStream(origin, remote, "remote->origin", &wg) })

	wg.Wait()
}

func unidirectionalStream(dst, src net.Conn, dir string, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := buffer.Get(buffer.RelayBufferSize)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil {
		log.Debugf("[TCP] copy data for %s: %v", dir, err)
	}
	buffer.Put(buf)
	// Do the upload/download side TCP half-close.
	if cr, ok := src.(interface{ CloseRead() error }); ok {
		cr.CloseRead()
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	// Set TCP half-close timeout.
	dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
}
