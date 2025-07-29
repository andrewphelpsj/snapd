package assemblestate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/check.v1"
)

type TransportSuite struct{}

var _ = check.Suite(&TransportSuite{})

func generateTestCert() (tls.Certificate, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, certDER, nil
}

func (s *TransportSuite) TestTrustedSuccess(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, serverCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify request is to correct endpoint
		c.Assert(r.URL.Path, check.Equals, "/assemble/routes")

		// verify method is POST
		c.Assert(r.Method, check.Equals, "POST")

		// verify json payload
		var routes Routes
		err := json.NewDecoder(r.Body).Decode(&routes)
		c.Assert(err, check.IsNil)

		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	routes := Routes{
		Devices:   []DeviceToken{"device1"},
		Addresses: []string{"addr1"},
		Routes:    []int{1},
	}

	err = client.Trusted(context.Background(), server.Listener.Addr().String(), serverCertDER, "routes", routes)
	c.Assert(err, check.IsNil)

	// verify counters were incremented
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(1))
	c.Assert(atomic.LoadInt64(&client.tx) > 0, check.Equals, true)
}

func (s *TransportSuite) TestTrustedCertificateMismatch(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	// generate different cert for mismatch
	_, wrongCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// suppress server error logging for this test since we expect TLS errors
	server.Config.ErrorLog = log.New(io.Discard, "", 0)

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	routes := Routes{
		Devices:   []DeviceToken{"device1"},
		Addresses: []string{"addr1"},
		Routes:    []int{1},
	}

	err = client.Trusted(context.Background(), server.Listener.Addr().String(), wrongCertDER, "routes", routes)
	c.Assert(err, check.NotNil)

	// the error message should contain something about certificate verification
	c.Assert(strings.Contains(err.Error(), "refusing to communicate with unexpected peer certificate"), check.Equals, true)

	// counters should not be incremented on failure
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(0))
}

func (s *TransportSuite) TestTrustedRateLimit(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, serverCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	callCount := int64(0)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	routes := Routes{
		Devices:   []DeviceToken{"device1"},
		Addresses: []string{"addr1"},
		Routes:    []int{1},
	}

	// send first message immediately
	start := time.Now()
	err = client.Trusted(context.Background(), server.Listener.Addr().String(), serverCertDER, "routes", routes)
	c.Assert(err, check.IsNil)

	// send second message - should be rate limited
	err = client.Trusted(context.Background(), server.Listener.Addr().String(), serverCertDER, "routes", routes)
	c.Assert(err, check.IsNil)

	elapsed := time.Since(start)

	// with rate limit of 20/sec, second call should take at least 50ms
	c.Assert(elapsed >= 40*time.Millisecond, check.Equals, true, check.Commentf("expected rate limiting delay, but calls completed in %v", elapsed))

	c.Assert(atomic.LoadInt64(&callCount), check.Equals, int64(2))
}

func (s *TransportSuite) TestTrustedContextCancellation(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, serverCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// delay to allow context cancellation
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	routes := Routes{
		Devices:   []DeviceToken{"device1"},
		Addresses: []string{"addr1"},
		Routes:    []int{1},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = client.Trusted(ctx, server.Listener.Addr().String(), serverCertDER, "routes", routes)
	c.Assert(err, check.NotNil)

	// counters should not be incremented on failure
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(0))
}

func (s *TransportSuite) TestTrustedCountersUpdate(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, serverCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	routes := Routes{
		Devices:   []DeviceToken{"device1", "device2"},
		Addresses: []string{"addr1", "addr2"},
		Routes:    []int{1, 2},
	}

	// send multiple messages and verify counters
	for i := 0; i < 3; i++ {
		err = client.Trusted(context.Background(), server.Listener.Addr().String(), serverCertDER, "routes", routes)
		c.Assert(err, check.IsNil)
	}

	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(3))

	tx := atomic.LoadInt64(&client.tx)
	c.Assert(tx > 0, check.Equals, true)

	// tx should be consistent across calls (same payload size)
	expectedTx := tx / 3
	c.Assert(expectedTx > 0, check.Equals, true)
}

func (s *TransportSuite) TestTrustedNonSuccessStatus(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, serverCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400) // bad request
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	routes := Routes{
		Devices:   []DeviceToken{"device1"},
		Addresses: []string{"addr1"},
		Routes:    []int{1},
	}

	err = client.Trusted(context.Background(), server.Listener.Addr().String(), serverCertDER, "routes", routes)
	c.Assert(err, check.NotNil)

	expectedError := "response to 'routes' message contains status code 400"
	c.Assert(err.Error(), check.Equals, expectedError)

	// counters should not be incremented when send fails due to non-200 status
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(0))
}

func (s *TransportSuite) TestUntrustedSuccess(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, serverCertDER, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify request is to correct endpoint
		c.Assert(r.URL.Path, check.Equals, "/assemble/auth")

		// verify method is POST
		c.Assert(r.Method, check.Equals, "POST")

		// verify json payload
		var auth Auth
		err := json.NewDecoder(r.Body).Decode(&auth)
		c.Assert(err, check.IsNil)

		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	auth := Auth{
		HMAC: []byte("test-hmac"),
		RDT:  DeviceToken("test-device"),
	}

	cert, err := client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
	c.Assert(err, check.IsNil)

	// verify returned certificate matches server certificate
	c.Assert(string(cert), check.Equals, string(serverCertDER))

	// verify counters were incremented
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(1))
	c.Assert(atomic.LoadInt64(&client.tx) > 0, check.Equals, true)
}

func (s *TransportSuite) TestUntrustedRateLimit(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	callCount := int64(0)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	auth := Auth{
		HMAC: []byte("test-hmac"),
		RDT:  DeviceToken("test-device"),
	}

	// send first message immediately
	start := time.Now()
	_, err = client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
	c.Assert(err, check.IsNil)

	// send second message - should be rate limited
	_, err = client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
	c.Assert(err, check.IsNil)

	elapsed := time.Since(start)

	// with rate limit of 20/sec, second call should take at least 50ms
	c.Assert(elapsed >= 40*time.Millisecond, check.Equals, true, check.Commentf("expected rate limiting delay, but calls completed in %v", elapsed))

	c.Assert(atomic.LoadInt64(&callCount), check.Equals, int64(2))
}

func (s *TransportSuite) TestUntrustedContextCancellation(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// delay to allow context cancellation
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	auth := Auth{
		HMAC: []byte("test-hmac"),
		RDT:  DeviceToken("test-device"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = client.Untrusted(ctx, server.Listener.Addr().String(), "auth", auth)
	c.Assert(err, check.NotNil)

	// counters should not be incremented on failure
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(0))
}

func (s *TransportSuite) TestUntrustedCountersUpdate(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	auth := Auth{
		HMAC: []byte("test-hmac-data"),
		RDT:  DeviceToken("test-device-token"),
	}

	// send multiple messages and verify counters
	for i := 0; i < 3; i++ {
		_, err = client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
		c.Assert(err, check.IsNil)
	}

	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(3))

	tx := atomic.LoadInt64(&client.tx)
	c.Assert(tx > 0, check.Equals, true)

	// tx should be consistent across calls (same payload size)
	expectedTx := tx / 3
	c.Assert(expectedTx > 0, check.Equals, true)
}

func (s *TransportSuite) TestUntrustedNonSuccessStatus(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	serverCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403) // forbidden
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(clientCert)

	auth := Auth{
		HMAC: []byte("test-hmac"),
		RDT:  DeviceToken("test-device"),
	}

	_, err = client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
	c.Assert(err, check.NotNil)

	expectedError := "got non-200 status code in response to auth message: 403"
	c.Assert(err.Error(), check.Equals, expectedError)

	// counters should still be incremented as the message was sent
	c.Assert(atomic.LoadInt64(&client.sent), check.Equals, int64(1))
}

func (s *TransportSuite) TestUntrustedNoTLS(c *check.C) {
	clientCert, _, err := generateTestCert()
	c.Assert(err, check.IsNil)

	// create non-TLS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := NewHTTPClient(clientCert)

	auth := Auth{
		HMAC: []byte("test-hmac"),
		RDT:  DeviceToken("test-device"),
	}

	// this test is tricky because the client will try to use TLS but the server doesn't support it
	// the http client will fail before we get to check TLS
	_, err = client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
	c.Assert(err, check.NotNil)

	// we expect a TLS-related error, not our specific error message
	// because the connection fails before we can check res.TLS
}
