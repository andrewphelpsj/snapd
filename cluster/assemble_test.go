package cluster_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/snapcore/snapd/cluster"
)

func TestAssemble(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	stop, err := cluster.Advertise(cluster.AdvertiseOpts{
		Instance:  "one",
		Port:      8001,
		IPs:       []net.IP{net.ParseIP("127.0.0.1")},
		Interface: lo,
	})
	if err != nil {
		t.Fatalf("advertising one: %v", err)
	}
	defer stop()

	stop, err = cluster.Advertise(cluster.AdvertiseOpts{
		Instance:  "two",
		Port:      8002,
		IPs:       []net.IP{net.ParseIP("127.0.0.1")},
		Interface: lo,
	})
	if err != nil {
		t.Fatalf("advertising two: %v", err)
	}
	defer stop()

	discover := func(ctx context.Context) ([]cluster.UntrustedPeer, error) {
		return cluster.Discover(ctx, cluster.DiscoverOpts{
			Interface: lo,
		})
	}

	const secret = "secret"

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	}))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cluster.Assemble(ctx, discover, cluster.AssembleOpts{
			DiscoveryPeriod: time.Second * 1,
			Secret:          "secret",
			ListenIP:        net.ParseIP("127.0.0.1"),
			ListenPort:      8001,
			Logger:          logger,
			RDTOverride:     "one",
		}); err != nil {
			t.Errorf("assemble failed: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cluster.Assemble(ctx, discover, cluster.AssembleOpts{
			DiscoveryPeriod: time.Second * 1,
			Secret:          "secret",
			ListenIP:        net.ParseIP("127.0.0.1"),
			ListenPort:      8002,
			Logger:          logger,
			RDTOverride:     "two",
		}); err != nil {
			t.Errorf("assemble failed: %v", err)
		}
	}()

	time.Sleep(time.Second * 5)

	stop, err = cluster.Advertise(cluster.AdvertiseOpts{
		Instance:  "three",
		Port:      8003,
		IPs:       []net.IP{net.ParseIP("127.0.0.1")},
		Interface: lo,
	})
	if err != nil {
		t.Fatalf("advertising three: %v", err)
	}
	defer stop()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cluster.Assemble(ctx, discover, cluster.AssembleOpts{
			DiscoveryPeriod: time.Second * 1,
			Secret:          "secret",
			ListenIP:        net.ParseIP("127.0.0.1"),
			ListenPort:      8003,
			Logger:          logger,
			RDTOverride:     "three",
		}); err != nil {
			t.Errorf("assemble failed: %v", err)
		}
	}()

	wg.Wait()
}
