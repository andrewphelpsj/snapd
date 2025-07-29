package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/snapcore/snapd/cluster"
	"github.com/snapcore/snapd/cluster/assemblestate"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/state"
)

func main() {
	rdt := flag.String("rdt", "", "random device token")
	port := flag.Int("port", 0, "listen port")
	iface := flag.String("iface", "", "interface to listen on")
	ip := flag.String("ip", "", "listen address")
	count := flag.Int("c", 0, "expected cluster size")
	flag.Parse()

	if *port == 0 || *ip == "" || *iface == "" || *rdt == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*iface, *ip, *port, *rdt, *count); err != nil {
		log.Fatalln(err)
	}
}

func run(iface string, ip string, port int, rdt string, count int) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	l := logger.New(os.Stdout, logger.DefaultFlags, &logger.LoggerOptions{
		ForceDebug: true,
	})

	st := state.New(nil)

	opts := cluster.AssembleOpts{
		Secret:       "secret",
		ListenIP:     net.ParseIP(ip),
		ListenPort:   port,
		RDTOverride:  rdt,
		Logger:       l,
		ExpectedSize: count,
	}

	discoveries, stop, err := assemblestate.MulticastDiscovery(ctx, iface, ip, port, assemblestate.DeviceToken(rdt))
	if err != nil {
		return err
	}

	defer stop()

	got, err := cluster.Assemble(st, ctx, discoveries, opts)
	if err != nil {
		return err
	}

	l.Debug(fmt.Sprintf("assembly exited after finding %d routes", len(got.Routes)/3))

	return nil
}
