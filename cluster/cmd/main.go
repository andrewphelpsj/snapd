package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/snapcore/snapd/cluster"
)

func run() error {
	name := flag.String("node", "", "name of the node")
	ip := flag.String("ip", "", "ip of the node")
	domain := flag.String("domain", "", "domain of the node")
	hostname := flag.String("hostname", "", "hostname of the node")
	i := flag.String("iface", "", "iface of the node")
	flag.Parse()

	iface, err := net.InterfaceByName(*i)
	if err != nil {
		return err
	}

	addr := net.ParseIP(*ip)
	if addr == nil {
		return fmt.Errorf("invalid ip: %s", *ip)
	}

	stop, err := cluster.Advertise(cluster.AdvertiseOpts{
		Instance:  *name,
		Port:      8080,
		Domain:    *domain,
		Hostname:  *hostname,
		Interface: iface,
		IPs:       []net.IP{addr},
	})
	if err != nil {
		return err
	}

	defer func() {
		if err := stop(); err != nil {
			log.Println("failed to stop advertising:", err)
		} else {
			log.Println("advertising stopped")
		}
	}()
	fmt.Printf("advertising ip: %v\n", addr)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer func() {
		signal.Stop(signals)
		close(signals)
	}()

	// cancel context when we get a signal
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signals
		cancel()
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	opts := cluster.DiscoverOpts{
		Domain:    *domain,
		Interface: iface,
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// looks weird, but we want to fail early if the context is canceled
			// and the ticker happened to win the select
			select {
			case <-ctx.Done():
				return nil
			default:
			}
		}

		ips, err := cluster.Discover(ctx, opts)
		if err != nil {
			return err
		}

		log.Printf("discovered ips: %v\n", ips)
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
