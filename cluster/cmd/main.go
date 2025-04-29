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
	domain := flag.String("domain", "", "domain of the node")
	hostname := flag.String("hostname", "", "hostname of the node")
	ipStr := flag.String("ip", "", "ip of the node")
	ifaceStr := flag.String("iface", "", "iface of the node")
	flag.Parse()

	if *name == "" || *ipStr == "" || *domain == "" || *ifaceStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	iface, err := net.InterfaceByName(*ifaceStr)
	if err != nil {
		return err
	}

	ip := net.ParseIP(*ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", *ipStr)
	}

	stop, err := cluster.Advertise(cluster.AdvertiseOpts{
		Instance:  *name,
		Port:      8080,
		Domain:    *domain,
		Hostname:  *hostname,
		Interface: iface,
		IPs:       []net.IP{ip},
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
	fmt.Printf("advertising ip: %v\n", ip)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

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
		}

		// fail early even if the ticker won the select
		if ctx.Err() != nil {
			return nil
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
