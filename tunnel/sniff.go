package tunnel

import (
	"net"
	"time"

	"github.com/FashionFarmer/tun2socks/v2/core/adapter"
	"github.com/FashionFarmer/tun2socks/v2/sniff"
)

const sniffReadChunk = 2048

// sniffTCP reads the client's leading bytes up to the Sniffer's byte budget or
// its timeout, returning the identified protocol and host — both empty when
// nothing matched or the flow spoke no bytes (a server-speaks-first protocol) —
// along with every byte read, so the caller can replay them into the pipe.
//
// It fails open by construction: any read error, timeout, exhausted budget, or
// NotApplicable verdict yields empty results and whatever was buffered. The
// decision of what to do with an unidentified flow belongs to the embedder's
// routing and admission policy, not to the stack.
func sniffTCP(conn net.Conn, s sniff.Sniffer) (proto, host string, buffered []byte) {
	maxBytes, timeout := s.Budget()
	if maxBytes <= 0 || timeout <= 0 {
		return "", "", nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 0, sniffReadChunk)
	tmp := make([]byte, sniffReadChunk)
	for len(buf) < maxBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			p, h, status := s.Sniff(buf)
			switch status {
			case sniff.Matched:
				return p, h, buf
			case sniff.NotApplicable:
				return "", "", buf
			}
		}
		if err != nil {
			return "", "", buf
		}
	}
	return "", "", buf
}

// cachedConn replays already-read leading bytes before yielding the live conn,
// making the sniff read transparent to the pipe. Reads drain the cache first;
// every other operation, including the CloseRead/CloseWrite half-close methods
// the tunnel relies on for FIN propagation, forwards to the wrapped conn.
type cachedConn struct {
	adapter.TCPConn
	cache []byte
}

func (c *cachedConn) Read(b []byte) (int, error) {
	if len(c.cache) > 0 {
		n := copy(b, c.cache)
		c.cache = c.cache[n:]
		return n, nil
	}
	return c.TCPConn.Read(b)
}

func (c *cachedConn) CloseRead() error {
	if cr, ok := c.TCPConn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *cachedConn) CloseWrite() error {
	if cw, ok := c.TCPConn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
