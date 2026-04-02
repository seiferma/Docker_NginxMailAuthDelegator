package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-imap/backend/memory"
	"github.com/emersion/go-imap/server"
	"github.com/seiferma/nginxmailauthdelegator/internal/asserts"
)

// generateSelfSignedCert creates a self-signed certificate and returns the cert and key in PEM format
func generateSelfSignedCert(host string) (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
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
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

// startTestIMAPServer starts an embedded IMAP server wrapped in TLS
// Returns the port, the certificate PEM, and a function to stop the server
// The server has a default user "username" with password "password"
func startTestIMAPServer(t *testing.T) (int, []byte, func()) {
	// Generate self-signed certificate
	certPEM, keyPEM, err := generateSelfSignedCert("localhost")
	asserts.AssertNil(t, err)

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	asserts.AssertNil(t, err)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Create memory backend (comes with default user "username"/"password")
	be := memory.New()

	// Create IMAP server
	s := server.New(be)
	s.Addr = "127.0.0.1:0" // Let the system assign a port
	s.TLSConfig = tlsConfig

	// Start listening on TLS
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Get the assigned port
	port := listener.Addr().(*net.TCPAddr).Port

	// Serve in a goroutine
	go func() {
		if err := s.Serve(listener); err != nil {
			log.Printf("IMAP server error: %v", err)
		}
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Return port, cert, and cleanup function
	return port, certPEM, func() {
		s.Close()
		listener.Close()
	}
}

func TestCredentialsValidInImap_ValidCredentials(t *testing.T) {
	port, certPEM, stop := startTestIMAPServer(t)
	defer stop()

	// Create a temporary CA cert file containing our self-signed cert
	tmpFile := t.TempDir() + "/ca.crt"
	err := os.WriteFile(tmpFile, certPEM, 0644)
	asserts.AssertNil(t, err)

	// Test with valid credentials (using the default "username"/"password" from memory backend)
	valid, ok := credentialsValidInImap("127.0.0.1", port, "username", "password", tmpFile)
	asserts.AssertEquals(t, true, ok)
	asserts.AssertEquals(t, true, valid)
}

func TestCredentialsValidInImap_InvalidCredentials(t *testing.T) {
	port, certPEM, stop := startTestIMAPServer(t)
	defer stop()

	// Create a temporary CA cert file containing our self-signed cert
	tmpFile := t.TempDir() + "/ca.crt"
	err := os.WriteFile(tmpFile, certPEM, 0644)
	asserts.AssertNil(t, err)

	// Test with invalid credentials
	valid, ok := credentialsValidInImap("127.0.0.1", port, "username", "wrongpass", tmpFile)
	asserts.AssertEquals(t, true, ok)
	asserts.AssertEquals(t, false, valid)
}

func TestCredentialsValidInImap_InvalidCert(t *testing.T) {
	port, _, stop := startTestIMAPServer(t)
	defer stop()

	// Generate a different self-signed certificate
	otherCertPEM, _, err := generateSelfSignedCert("otherhost")
	asserts.AssertNil(t, err)

	// Create a temporary CA cert file containing the OTHER cert (not the server's)
	tmpFile := t.TempDir() + "/ca.crt"
	err = os.WriteFile(tmpFile, otherCertPEM, 0644)
	asserts.AssertNil(t, err)

	// Test should fail because the certificate is not trusted
	valid, ok := credentialsValidInImap("127.0.0.1", port, "username", "password", tmpFile)
	asserts.AssertEquals(t, false, ok)
	asserts.AssertEquals(t, false, valid)
}

func TestCredentialsValidInImap_ServerUnavailable(t *testing.T) {
	// Find a free port that nothing is listening on
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	// Generate self-signed cert for CA file
	certPEM, _, err := generateSelfSignedCert("localhost")
	asserts.AssertNil(t, err)

	tmpFile := t.TempDir() + "/ca.crt"
	err = os.WriteFile(tmpFile, certPEM, 0644)
	asserts.AssertNil(t, err)

	// Test should fail because no server is listening
	valid, ok := credentialsValidInImap("127.0.0.1", port, "username", "password", tmpFile)
	asserts.AssertEquals(t, false, ok)
	asserts.AssertEquals(t, false, valid)
}
