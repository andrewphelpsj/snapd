package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"

	"github.com/snapcore/snapd/cluster"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/state"
	"golang.org/x/sync/errgroup"
)

func main() {
	n := flag.Int("n", 0, "number of devices to simulate")
	flag.Parse()

	if *n == 0 {
		return
	}

	run(*n)
}

func run(total int) error {
	peers := make([]string, 0, total)
	for i := range total {
		peers = append(peers, fmt.Sprintf("127.0.0.1:%d", 8001+i))
	}

	discover := func(ctx context.Context) ([]string, error) {
		return peers, nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg errgroup.Group
	for i := range total {
		null := logger.Logger(logger.NullLogger)
		l := logger.New(os.Stdout, logger.DefaultFlags, &logger.LoggerOptions{
			ForceDebug: true,
		})
		use := null
		if i == 0 {
			use = l
		}

		wg.Go(func() error {
			defer cancel()

			rtd := strconv.Itoa(i)
			st := state.New(nil)

			opts := cluster.AssembleOpts{
				Secret:      "secret",
				ListenIP:    net.ParseIP("127.0.0.1"),
				ListenPort:  8001 + i,
				RDTOverride: rtd,
				Logger:      use,
			}
			if i == 0 {
				opts.ExpectedSize = total
			}

			got, err := cluster.Assemble(st, ctx, discover, opts)
			if err != nil {
				return err
			}

			l.Debug(fmt.Sprintf("assembly exited after finding %d routes", len(got.Routes)/3))
			return nil
		})
	}

	return wg.Wait()
}
