package cluster_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/snapcore/snapd/cluster"
	"github.com/snapcore/snapd/cluster/assemblestate"
)

func TestAssemble(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	const total = 64

	for i := range total {
		stop, err := cluster.Advertise(cluster.AdvertiseOpts{
			Instance:  strconv.Itoa(i),
			Port:      8001 + i,
			IPs:       []net.IP{net.ParseIP("127.0.0.1")},
			Interface: lo,
		})
		if err != nil {
			t.Fatalf("advertising: %v", err)
		}
		defer stop()
	}

	discover := func(ctx context.Context) ([]cluster.UntrustedPeer, error) {
		return cluster.Discover(ctx, cluster.DiscoverOpts{
			Interface: lo,
		})
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	}))

	debug := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	collected := make([]assemblestate.Routes, total)
	var wg sync.WaitGroup
	for i := range total {
		wg.Add(1)

		l := logger
		if i == 0 {
			l = debug
		}

		go func() {
			defer wg.Done()
			routes, err := cluster.Assemble(ctx, discover, cluster.AssembleOpts{
				DiscoveryPeriod: time.Millisecond * 500,
				Secret:          "secret",
				ListenIP:        net.ParseIP("127.0.0.1"),
				ListenPort:      8001 + i,
				RDTOverride:     strconv.Itoa(i),
				Logger:          l,
			})
			if err != nil {
				t.Errorf("assemble failed: %v", err)
			}

			collected[i] = routes
		}()
	}

	wg.Wait()

	// after all nodes exit, each of them should see the same fully connected
	// graph
	g := assemblestate.NewGraph()
	for i := range total {
		for peer := range total {
			if i == peer {
				continue
			}

			from := assemblestate.RDT(strconv.Itoa(i))
			to := assemblestate.RDT(strconv.Itoa(peer))
			via := fmt.Sprintf("127.0.0.1:%d", 8001+peer)
			if _, err := g.Connect(from, to, via); err != nil {
				t.Fatal(err)
			}
		}
	}

	expected, err := g.Export()
	if err != nil {
		t.Fatal(err)
	}

	for i, r := range collected {
		if !reflect.DeepEqual(expected, r) {
			t.Errorf("node %d did not report the expected set of routes: %v", i, r)
		}
	}
}
