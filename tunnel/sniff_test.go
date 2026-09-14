package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/FashionFarmer/tun2socks/v2/sniff"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeSniffer matches once it has at least need bytes; need == 0 means it never
// matches (NotApplicable on first probe).
type fakeSniffer struct {
	proto, host string
	need        int
	max         int
	timeout     time.Duration
}

func (f fakeSniffer) Budget() (int, time.Duration) { return f.max, f.timeout }

func (f fakeSniffer) Sniff(data []byte) (string, string, sniff.Status) {
	if f.need == 0 {
		return "", "", sniff.NotApplicable
	}
	if len(data) < f.need {
		return "", "", sniff.More
	}
	return f.proto, f.host, sniff.Matched
}

func TestSniffTCPMatched(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { client.Write([]byte("hello world")); client.Close() }()

	proto, host, buf := sniffTCP(server, fakeSniffer{proto: "x", host: "h", need: 5, max: 100, timeout: time.Second})
	if proto != "x" || host != "h" {
		t.Fatalf("got (%q,%q), want (x,h)", proto, host)
	}
	if !bytes.Equal(buf, []byte("hello world")) {
		t.Fatalf("buffered %q, want the full leading bytes for replay", buf)
	}
}

func TestSniffTCPNotApplicable(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { client.Write([]byte("data")); client.Close() }()

	proto, host, buf := sniffTCP(server, fakeSniffer{need: 0, max: 100, timeout: time.Second})
	if proto != "" || host != "" {
		t.Fatalf("got (%q,%q), want empty", proto, host)
	}
	if !bytes.Equal(buf, []byte("data")) {
		t.Fatalf("buffered %q, want the read bytes preserved for replay", buf)
	}
}

func TestSniffTCPServerSpeaksFirst(t *testing.T) {
	_, server := net.Pipe() // client never writes
	defer server.Close()

	start := time.Now()
	proto, host, buf := sniffTCP(server, fakeSniffer{need: 5, max: 100, timeout: 50 * time.Millisecond})
	if proto != "" || host != "" || len(buf) != 0 {
		t.Fatalf("got (%q,%q,%d bytes), want empty on timeout", proto, host, len(buf))
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("returned after %v, want it to wait out the sniff timeout", elapsed)
	}
}

type closeRecorder struct {
	net.Conn
	readClosed, writeClosed bool
}

func (c *closeRecorder) ID() stack.TransportEndpointID { return stack.TransportEndpointID{} }
func (c *closeRecorder) CloseRead() error              { c.readClosed = true; return nil }
func (c *closeRecorder) CloseWrite() error             { c.writeClosed = true; return nil }

func TestCachedConnReplaysThenReads(t *testing.T) {
	client, server := net.Pipe()
	rec := &closeRecorder{Conn: server}
	c := &cachedConn{TCPConn: rec, cache: []byte("AB")}
	go func() { client.Write([]byte("CD")); client.Close() }()

	got := make([]byte, 8)
	n, _ := c.Read(got) // drains the cache first
	if string(got[:n]) != "AB" {
		t.Fatalf("first read %q, want the cached prefix AB", got[:n])
	}
	n, _ = c.Read(got) // then the live conn
	if string(got[:n]) != "CD" {
		t.Fatalf("second read %q, want the live bytes CD", got[:n])
	}

	if c.CloseRead(); !rec.readClosed {
		t.Fatal("CloseRead did not forward to the wrapped conn")
	}
	if c.CloseWrite(); !rec.writeClosed {
		t.Fatal("CloseWrite did not forward to the wrapped conn")
	}
}
