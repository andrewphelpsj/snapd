package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/snapcore/snapd/cluster"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/state"
)

func main() {
	rdt := flag.String("rdt", "", "random device token")
	port := flag.Int("port", 0, "listen port")
	ip := flag.String("ip", "", "listen address")
	terminate := flag.Bool("t", false, "terminate once all routes found")
	flag.Parse()

	if *port == 0 || *ip == "" {
		return
	}

	run(*ip, *port, *rdt, *terminate, flag.Args())
}

func run(ip string, port int, rdt string, terminate bool, peers []string) error {
	discover := func(ctx context.Context) ([]string, error) {
		return peers, nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	l := logger.New(os.Stdout, logger.DefaultFlags, &logger.LoggerOptions{
		ForceDebug: true,
	})

	st := state.New(nil)

	expected := 0
	if terminate {
		expected = len(peers) + 1
	}

	opts := cluster.AssembleOpts{
		Secret:       "secret",
		ListenIP:     net.ParseIP(ip),
		ListenPort:   port,
		RDTOverride:  rdt,
		Logger:       l,
		ExpectedSize: expected,
	}

	got, err := cluster.Assemble(st, ctx, discover, opts)
	if err != nil {
		return err
	}

	l.Debug(fmt.Sprintf("assembly exited after finding %d routes", len(got.Routes)/3))

	return nil
}
