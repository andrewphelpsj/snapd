package cluster

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/snapcore/snapd/cluster/mdns"
)

const ServiceType = "_snapd._tcp"

type AdvertiseOpts struct {
	Instance  string
	Port      int
	IPs       []net.IP
	Domain    string
	Hostname  string
	Interface *net.Interface
}

func Advertise(opts AdvertiseOpts) (stop func() error, err error) {
	service, err := mdns.NewMDNSService(
		opts.Instance, ServiceType, opts.Domain, opts.Hostname, opts.Port, opts.IPs, nil,
	)
	if err != nil {
		return nil, err
	}

	server, err := mdns.NewServer(&mdns.Config{
		Zone:  service,
		Iface: opts.Interface,
	})
	if err != nil {
		return nil, err
	}

	return server.Shutdown, nil
}

type DiscoverOpts struct {
	Domain    string
	Interface *net.Interface
}

type UntrustedPeer struct {
	IP   net.IP
	Port int
}

func (up *UntrustedPeer) String() string {
	return fmt.Sprintf("%v:%d", up.IP, up.Port)
}

func Discover(ctx context.Context, opts DiscoverOpts) ([]UntrustedPeer, error) {
	// reasonably large buffer, since the mdns library will drop entries if we
	// cannot process them fast enough
	//
	// TODO: we could patch that if we do fork this library
	ch := make(chan *mdns.ServiceEntry, 1024)

	params := mdns.DefaultParams(ServiceType)
	params.Interface = opts.Interface
	params.Entries = ch
	params.Domain = opts.Domain
	params.Logger = log.New(io.Discard, "", 0)

	var peers []UntrustedPeer
	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range ch {
			peers = append(peers, UntrustedPeer{
				IP:   entry.AddrV4,
				Port: entry.Port,
			})
		}
	}()

	if err := mdns.QueryContext(ctx, params); err != nil {
		close(ch)
		<-done
		return nil, err
	}

	close(ch)
	<-done

	return peers, nil
}

type TrustedPeer struct{}

type Discoverer = func(context.Context) ([]UntrustedPeer, error)

type AssembleOpts struct {
	DiscoveryPeriod time.Duration
	Secret          string
	TLSCert         string
	ErrorHandler    func(error)
	ListenPort      int
}

func Assemble(ctx context.Context, discover Discoverer, opts AssembleOpts) ([]TrustedPeer, error) {
	if opts.ErrorHandler == nil {
		opts.ErrorHandler = func(err error) {
			log.Printf("assembly error: %v\n", err)
		}
	}

	if opts.DiscoveryPeriod == 0 {
		opts.DiscoveryPeriod = time.Second * 3
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// assembly deals with a lot of errors that might happen asynchronously. a
	// lot of these aren't fatal, but we still want to do something with them.
	// this channel here is used to aggregate all of them, i'll figure out what
	// to do with them later.
	errors := make(chan error)
	defer close(errors)

	go func() {
		for err := range errors {
			opts.ErrorHandler(err)
		}
	}()

	discovered := peerNotifier(ctx, discover, opts.DiscoveryPeriod, errors)
	gossip := make(chan []UntrustedPeer)

	// this helps us make sure that all of our peer threads are stopped before
	// we return from this function
	var wg sync.WaitGroup

outer:
	for {
		var untrusted []UntrustedPeer
		select {
		case untrusted = <-discovered:
		case untrusted = <-gossip:
		case <-ctx.Done():
			break outer
		}

		for _, up := range untrusted {
			wg.Add(1)
			go func() {
				defer wg.Done()

				trusted, err := establishTrust(ctx, up, opts)
				if err != nil {
					errors <- err
					return
				}
				_ = trusted
			}()
		}
	}

	// this is important, since this means that no one is writing to either
	// "gossip" or "errors" after this returns. thus, the deferred closes on
	// those channels is fine.
	wg.Wait()

	return nil, nil
}

func establishTrust(ctx context.Context, up UntrustedPeer, opts AssembleOpts) (TrustedPeer, error) {
	return TrustedPeer{}, nil
}

func peerNotifier(ctx context.Context, discover Discoverer, period time.Duration, errors chan<- error) <-chan []UntrustedPeer {
	seen := make(map[string]bool)
	filtered := func(ctx context.Context) ([]UntrustedPeer, error) {
		peers, err := discover(ctx)
		if err != nil {
			return nil, err
		}

		var copied []UntrustedPeer
		for _, p := range peers {
			if seen[p.String()] {
				continue
			}

			seen[p.String()] = true
			copied = append(copied, p)
		}

		return copied, nil
	}

	ch := make(chan []UntrustedPeer)
	go func() {
		defer close(ch)

		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			// fail early even if the ticker won the select
			if ctx.Err() != nil {
				return
			}

			peers, err := filtered(ctx)
			if err != nil {
				errors <- err
				continue
			}

			select {
			case ch <- peers:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}
