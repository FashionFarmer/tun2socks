//go:build unix

package instance

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/FashionFarmer/tun2socks/v2/core/option"
	M "github.com/FashionFarmer/tun2socks/v2/metadata"
)

type rejectProxy struct{}

func (rejectProxy) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (rejectProxy) DialUDP(*M.Metadata) (net.PacketConn, error) { return nil, net.ErrClosed }

func TestStartStackFailureDoesNotTakeFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	fail := option.Option(func(*stack.Stack) error { return errors.New("test failure") })
	if _, err := Start(Options{TUNFD: fds[0], MTU: 1500, Proxy: rejectProxy{}, StackOptions: []option.Option{fail}}); err == nil {
		t.Fatal("stack option failure was ignored")
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("failed start took ownership of fd: %v", err)
	}
}

func TestInstanceOwnsAndClosesTunFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	instance, err := Start(Options{TUNFD: fds[0], MTU: 1500, Proxy: rejectProxy{}})
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("start instance: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("close instance: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatalf("TUN fd is still open: %v", err)
	}
}

func TestStartValidationDoesNotTakeFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if _, err := Start(Options{TUNFD: fds[0]}); err == nil {
		t.Fatal("nil proxy was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("validation took ownership of fd: %v", err)
	}
}
