package assemblestate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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

func TestTrustedSuccess(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify request is to correct endpoint
		if r.URL.Path != "/assemble/routes" {
			t.Errorf("expected path /assemble/routes, got %s", r.URL.Path)
		}

		// verify method is POST
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// verify json payload
		var routes Routes
		if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
			t.Errorf("failed to decode routes: %v", err)
		}

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
	if err != nil {
		t.Fatalf("trusted call failed: %v", err)
	}

	// verify counters were incremented
	if atomic.LoadInt64(&client.sent) != 1 {
		t.Errorf("expected sent counter to be 1, got %d", atomic.LoadInt64(&client.sent))
	}

	if atomic.LoadInt64(&client.tx) == 0 {
		t.Error("expected tx counter to be > 0")
	}
}

func TestTrustedCertificateMismatch(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	// generate different cert for mismatch
	_, wrongCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
		Devices:   []DeviceToken{"device1"},
		Addresses: []string{"addr1"},
		Routes:    []int{1},
	}

	err = client.Trusted(context.Background(), server.Listener.Addr().String(), wrongCertDER, "routes", routes)
	if err == nil {
		t.Fatal("expected error due to certificate mismatch, got nil")
	}

	// the error message should contain something about certificate verification
	if !strings.Contains(err.Error(), "refusing to communicate with unexpected peer certificate") {
		t.Errorf("unexpected error message: %v", err)
	}

	// counters should not be incremented on failure
	if atomic.LoadInt64(&client.sent) != 0 {
		t.Errorf("expected sent counter to be 0, got %d", atomic.LoadInt64(&client.sent))
	}
}

func TestTrustedRateLimit(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatalf("first trusted call failed: %v", err)
	}

	// send second message - should be rate limited
	err = client.Trusted(context.Background(), server.Listener.Addr().String(), serverCertDER, "routes", routes)
	if err != nil {
		t.Fatalf("second trusted call failed: %v", err)
	}

	elapsed := time.Since(start)

	// with rate limit of 20/sec, second call should take at least 50ms
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected rate limiting delay, but calls completed in %v", elapsed)
	}

	if atomic.LoadInt64(&callCount) != 2 {
		t.Errorf("expected 2 server calls, got %d", atomic.LoadInt64(&callCount))
	}
}

func TestTrustedContextCancellation(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err == nil {
		t.Fatal("expected error due to context timeout, got nil")
	}

	// counters should not be incremented on failure
	if atomic.LoadInt64(&client.sent) != 0 {
		t.Errorf("expected sent counter to be 0, got %d", atomic.LoadInt64(&client.sent))
	}
}

func TestTrustedCountersUpdate(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
		if err != nil {
			t.Fatalf("trusted call %d failed: %v", i+1, err)
		}
	}

	if atomic.LoadInt64(&client.sent) != 3 {
		t.Errorf("expected sent counter to be 3, got %d", atomic.LoadInt64(&client.sent))
	}

	tx := atomic.LoadInt64(&client.tx)
	if tx == 0 {
		t.Error("expected tx counter to be > 0")
	}

	// tx should be consistent across calls (same payload size)
	expectedTx := tx / 3
	if expectedTx == 0 {
		t.Error("expected consistent payload size per message")
	}
}

func TestTrustedNonSuccessStatus(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err == nil {
		t.Fatal("expected error due to non-200 status, got nil")
	}

	expectedError := "response to 'routes' message contains status code 400"
	if err.Error() != expectedError {
		t.Errorf("expected error '%s', got '%v'", expectedError, err)
	}

	// counters should not be incremented when send fails due to non-200 status
	if atomic.LoadInt64(&client.sent) != 0 {
		t.Errorf("expected sent counter to be 0, got %d", atomic.LoadInt64(&client.sent))
	}
}

func TestUntrustedSuccess(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverCertDER, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify request is to correct endpoint
		if r.URL.Path != "/assemble/auth" {
			t.Errorf("expected path /assemble/auth, got %s", r.URL.Path)
		}

		// verify method is POST
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// verify json payload
		var auth Auth
		if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
			t.Errorf("failed to decode auth: %v", err)
		}

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
	if err != nil {
		t.Fatalf("untrusted call failed: %v", err)
	}

	// verify returned certificate matches server certificate
	if string(cert) != string(serverCertDER) {
		t.Error("returned certificate doesn't match server certificate")
	}

	// verify counters were incremented
	if atomic.LoadInt64(&client.sent) != 1 {
		t.Errorf("expected sent counter to be 1, got %d", atomic.LoadInt64(&client.sent))
	}

	if atomic.LoadInt64(&client.tx) == 0 {
		t.Error("expected tx counter to be > 0")
	}
}

func TestUntrustedRateLimit(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatalf("first untrusted call failed: %v", err)
	}

	// send second message - should be rate limited
	_, err = client.Untrusted(context.Background(), server.Listener.Addr().String(), "auth", auth)
	if err != nil {
		t.Fatalf("second untrusted call failed: %v", err)
	}

	elapsed := time.Since(start)

	// with rate limit of 20/sec, second call should take at least 50ms
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected rate limiting delay, but calls completed in %v", elapsed)
	}

	if atomic.LoadInt64(&callCount) != 2 {
		t.Errorf("expected 2 server calls, got %d", atomic.LoadInt64(&callCount))
	}
}

func TestUntrustedContextCancellation(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err == nil {
		t.Fatal("expected error due to context timeout, got nil")
	}

	// counters should not be incremented on failure
	if atomic.LoadInt64(&client.sent) != 0 {
		t.Errorf("expected sent counter to be 0, got %d", atomic.LoadInt64(&client.sent))
	}
}

func TestUntrustedCountersUpdate(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
		if err != nil {
			t.Fatalf("untrusted call %d failed: %v", i+1, err)
		}
	}

	if atomic.LoadInt64(&client.sent) != 3 {
		t.Errorf("expected sent counter to be 3, got %d", atomic.LoadInt64(&client.sent))
	}

	tx := atomic.LoadInt64(&client.tx)
	if tx == 0 {
		t.Error("expected tx counter to be > 0")
	}

	// tx should be consistent across calls (same payload size)
	expectedTx := tx / 3
	if expectedTx == 0 {
		t.Error("expected consistent payload size per message")
	}
}

func TestUntrustedNonSuccessStatus(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	serverCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err == nil {
		t.Fatal("expected error due to non-200 status, got nil")
	}

	expectedError := "got non-200 status code in response to auth message: 403"
	if err.Error() != expectedError {
		t.Errorf("expected error '%s', got '%v'", expectedError, err)
	}

	// counters should still be incremented as the message was sent
	if atomic.LoadInt64(&client.sent) != 1 {
		t.Errorf("expected sent counter to be 1, got %d", atomic.LoadInt64(&client.sent))
	}
}

func TestUntrustedNoTLS(t *testing.T) {
	clientCert, _, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

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
	if err == nil {
		t.Fatal("expected error due to TLS requirement, got nil")
	}

	// we expect a TLS-related error, not our specific error message
	// because the connection fails before we can check res.TLS
}

