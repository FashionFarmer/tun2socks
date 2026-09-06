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
	"github.com/FashionFarmer/tun2socks/v2/core/option"
	"github.com/FashionFarmer/tun2socks/v2/proxy"
	"github.com/FashionFarmer/tun2socks/v2/tunnel"
	"github.com/FashionFarmer/tun2socks/v2/tunnel/statistic"
)

// Options configures one embeddable TUN stack. The instance takes ownership of
// TUNFD after Start succeeds and closes it from Close.
type Options struct {
	TUNFD        int
	MTU          uint32
	FDOffset     int
	Proxy        proxy.Proxy
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
	if opts.TUNFD < 0 {
		return nil, errors.New("tun2socks: invalid TUN fd")
	}
	if opts.FDOffset < 0 {
		return nil, errors.New("tun2socks: invalid fd offset")
	}
	if opts.Proxy == nil {
		return nil, errors.New("tun2socks: nil proxy")
	}
	instanceFD, err := duplicateTunFD(opts.TUNFD)
	if err != nil {
		return nil, fmt.Errorf("tun2socks: duplicate TUN fd: %w", err)
	}
	dev, err := fdbased.Open(strconv.Itoa(instanceFD), opts.MTU, opts.FDOffset)
	if err != nil {
		_ = closeTunFD(instanceFD)
		return nil, fmt.Errorf("tun2socks: open TUN fd: %w", err)
	}
	defer func() {
		if err != nil {
			dev.Close()
		}
	}()
	manager := statistic.NewManager()
	handler := tunnel.New(opts.Proxy, manager)
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
	if err := closeTunFD(opts.TUNFD); err != nil {
		netstack.Close()
		netstack.Wait()
		handler.Close()
		manager.Close()
		return nil, fmt.Errorf("tun2socks: take ownership of TUN fd: %w", err)
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
