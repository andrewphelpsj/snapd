package cluster

import (
	"context"
	"io"
	"log"
	"net"

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

func Discover(ctx context.Context, opts DiscoverOpts) ([]net.IP, error) {
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

	var ips []net.IP
	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range ch {
			ips = append(ips, entry.AddrV4)
		}
	}()

	if err := mdns.QueryContext(ctx, params); err != nil {
		close(ch)
		<-done
		return nil, err
	}

	close(ch)
	<-done

	return ips, nil
}
