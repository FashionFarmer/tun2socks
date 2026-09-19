// Package instance provides the embeddable, independently owned tun2socks
// stack. It deliberately excludes the command-line engine, REST API and proxy
// registry.
package instance

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/FashionFarmer/tun2socks/v2/core"
	"github.com/FashionFarmer/tun2socks/v2/core/adapter"
	"github.com/FashionFarmer/tun2socks/v2/core/device"
	"github.com/FashionFarmer/tun2socks/v2/core/device/fdbased"
	"github.com/FashionFarmer/tun2socks/v2/core/device/tun"
	"github.com/FashionFarmer/tun2socks/v2/core/option"
	"github.com/FashionFarmer/tun2socks/v2/proxy"
	"github.com/FashionFarmer/tun2socks/v2/sniff"
	"github.com/FashionFarmer/tun2socks/v2/tunnel"
	"github.com/FashionFarmer/tun2socks/v2/tunnel/statistic"
)

// Options configures one embeddable TUN stack. The instance takes ownership of
// TUNFD after Start succeeds and closes it from Close.
type Options struct {
	TUNFD int
	// TUNName, when set, opens a driver-managed TUN device by name (wintun on
	// Windows, utun/tun elsewhere) instead of adopting TUNFD. Exactly one of
	// TUNName or a valid TUNFD is used; TUNName takes precedence. It is how a
	// host with no file descriptor to hand over (Windows) attaches a TUN.
	TUNName  string
	MTU      uint32
	FDOffset int
	Proxy    proxy.Proxy
	// Sniffer, when non-nil, identifies each TCP flow's protocol and host from
	// the client's leading bytes before it is dialed, recording the result on
	// the flow metadata. nil disables sniffing.
	Sniffer      sniff.Sniffer
	ICMPHandler  adapter.NetworkHandler
	StackOptions []option.Option
}

type Instance struct {
	device     device.Device
	stack      *stack.Stack
	tunnel     *tunnel.Tunnel
	statistics *statistic.Manager
	closeOnce  sync.Once
}

// Start returns errors to its caller and never terminates the hosting process.
func Start(opts Options) (_ *Instance, err error) {
	if opts.Proxy == nil {
		return nil, errors.New("tun2socks: nil proxy")
	}

	// Obtain the link device one of two ways. A name opens a driver-managed TUN
	// (wintun on Windows); otherwise the instance adopts a file descriptor the
	// host already opened (Android's VpnService), duplicating it and taking
	// ownership so the caller's copy can be closed. ownedFD >= 0 marks the fd
	// path, whose original descriptor is closed only after the stack is up.
	var dev device.Device
	ownedFD := -1
	if opts.TUNName != "" {
		dev, err = tun.Open(opts.TUNName, opts.MTU)
		if err != nil {
			return nil, fmt.Errorf("tun2socks: open TUN %q: %w", opts.TUNName, err)
		}
	} else {
		if opts.TUNFD < 0 {
			return nil, errors.New("tun2socks: invalid TUN fd")
		}
		if opts.FDOffset < 0 {
			return nil, errors.New("tun2socks: invalid fd offset")
		}
		instanceFD, derr := duplicateTunFD(opts.TUNFD)
		if derr != nil {
			return nil, fmt.Errorf("tun2socks: duplicate TUN fd: %w", derr)
		}
		dev, err = fdbased.Open(strconv.Itoa(instanceFD), opts.MTU, opts.FDOffset)
		if err != nil {
			_ = closeTunFD(instanceFD)
			return nil, fmt.Errorf("tun2socks: open TUN fd: %w", err)
		}
		ownedFD = opts.TUNFD
	}
	defer func() {
		if err != nil {
			dev.Close()
		}
	}()
	manager := statistic.NewManager()
	handler := tunnel.New(opts.Proxy, manager)
	if opts.Sniffer != nil {
		handler.SetSniffer(opts.Sniffer)
	}
	handler.ProcessAsync()
	netstack, err := core.CreateStack(&core.Config{
		LinkEndpoint: dev, TransportHandler: handler,
		ICMPHandler: opts.ICMPHandler, Options: opts.StackOptions,
	})
	if err != nil {
		handler.Close()
		manager.Close()
		return nil, fmt.Errorf("tun2socks: create stack: %w", err)
	}
	if ownedFD >= 0 {
		if err = closeTunFD(ownedFD); err != nil {
			netstack.Close()
			netstack.Wait()
			handler.Close()
			manager.Close()
			return nil, fmt.Errorf("tun2socks: take ownership of TUN fd: %w", err)
		}
	}
	return &Instance{device: dev, stack: netstack, tunnel: handler, statistics: manager}, nil
}

func (i *Instance) Statistics() *statistic.Manager {
	if i == nil {
		return nil
	}
	return i.statistics
}

func (i *Instance) Close() error {
	if i == nil {
		return nil
	}
	i.closeOnce.Do(func() {
		i.device.Close()
		i.stack.Close()
		i.stack.Wait()
		i.tunnel.Close()
		i.statistics.Close()
	})
	return nil
}
