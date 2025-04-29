package cluster_test

import (
	"context"
	"net"
	"testing"

	"github.com/snapcore/snapd/cluster"
	"github.com/snapcore/snapd/testutil"
	. "gopkg.in/check.v1"
)

func TestCluster(t *testing.T) { TestingT(t) }

type discoverySuite struct{}

var _ = Suite(&discoverySuite{})

func (s *discoverySuite) TestDiscoverer(c *C) {
	expected := []net.IP{
		[]byte{192, 168, 0, 41},
		[]byte{192, 168, 0, 42},
	}

	one := cluster.AdvertiseOpts{
		Instance: "one",
		Port:     9090,
		IPs:      []net.IP{expected[0]},
	}

	two := cluster.AdvertiseOpts{
		Instance: "two",
		Port:     9091,
		IPs:      []net.IP{expected[1]},
	}

	oneStop, err := cluster.Advertise(one)
	c.Assert(err, IsNil)
	defer func() {
		c.Assert(oneStop(), IsNil)
	}()

	twoStop, err := cluster.Advertise(two)
	c.Assert(err, IsNil)
	defer func() {
		c.Assert(twoStop(), IsNil)
	}()

	// first discover should see both IPs
	ctx := context.Background()
	ips, err := cluster.Discover(ctx, cluster.DiscoverOpts{})
	c.Assert(err, IsNil)

	c.Assert(ips, testutil.DeepUnsortedMatches, expected)

	// stop one, then we should only see two's IP
	err = oneStop()
	c.Assert(err, IsNil)

	ips, err = cluster.Discover(ctx, cluster.DiscoverOpts{})
	c.Assert(err, IsNil)

	c.Assert(ips, testutil.DeepUnsortedMatches, expected[1:])

	// stop two, then we should see nothing
	err = twoStop()
	c.Assert(err, IsNil)

	ips, err = cluster.Discover(ctx, cluster.DiscoverOpts{})
	c.Assert(err, IsNil)

	c.Assert(ips, HasLen, 0)
}
