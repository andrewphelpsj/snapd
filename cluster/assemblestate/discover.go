package assemblestate

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/brutella/dnssd"
	dnssdlog "github.com/brutella/dnssd/log"
	"github.com/snapcore/snapd/logger"
)

func MulticastDiscovery(
	ctx context.Context,
	iface string,
	address net.IP,
	port int,
	rdt DeviceToken,
	domain string,
	verbose bool,
) (<-chan []string, func(), error) {
	if verbose {
		dnssdlog.Debug.Enable()
		dnssdlog.Info.Enable()
	}

	// use provided domain or default to "local"
	if domain == "" {
		domain = "local"
	}

	const service = "_snapd._https"
	sv, err := dnssd.NewService(dnssd.Config{
		Name:   fmt.Sprintf("snapd-%s", rdt),
		Type:   service,
		Domain: domain,
		Port:   port,
		Ifaces: []string{iface},
		IPs:    []net.IP{address},
	})
	if err != nil {
		return nil, nil, err
	}

	rp, err := dnssd.NewResponder()
	if err != nil {
		return nil, nil, err
	}

	_, err = rp.Add(sv)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := rp.Respond(ctx)
		logger.Debugf("mdns responder exited: %v", err)
	}()

	addresses := make(chan []string)

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := dnssd.LookupType(ctx, fmt.Sprintf("%s.%s.", service, domain), func(be dnssd.BrowseEntry) {
			addrs := make([]string, 0, len(be.IPs))
			for _, ip := range be.IPs {
				// drop non ipv4 for now, just for simplicity
				if len(ip) != net.IPv4len {
					continue
				}

				addr := fmt.Sprintf("%s:%d", ip, be.Port)
				addrs = append(addrs, addr)
			}
			addresses <- addrs
		}, func(be dnssd.BrowseEntry) {})
		logger.Debugf("mdns lookup exited: %v", err)
	}()

	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		wg.Wait()
	}

	return addresses, stop, nil
}
