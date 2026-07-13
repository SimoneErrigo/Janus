package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// buildTLSConfig creates a tls.Config based on the service TLS mode.
func buildTLSConfig(svc *storage.Service) (*tls.Config, error) {
	var (
		cfg *tls.Config
		err error
	)
	switch svc.TLSMode {
	case storage.TLSModeSelfSigned:
		cfg, err = selfSignedTLSConfig(svc.ListenAddr)
	case storage.TLSModeChallenge:
		cfg, err = challengeTLSConfig(svc.CertFile, svc.KeyFile)
	default:
		return nil, fmt.Errorf("unsupported TLS mode: %q", svc.TLSMode)
	}
	if err != nil {
		return nil, err
	}

	// RFC 6455 WebSocket upgrades use HTTP/1.1. Advertising h2 for a WSS-only
	// listener can make a browser negotiate HTTP/2, where the classic Upgrade
	// handshake is unavailable (extended CONNECT is a separate protocol).
	if svc.Protocol == storage.ProtocolWSS {
		cfg.NextProtos = []string{"http/1.1"}
	}
	return cfg, nil
}

// selfSignedTLSConfig generates a self-signed certificate for the given address.
func selfSignedTLSConfig(addr string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Janus Self-Signed"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add the listen address as a SAN
	if ip := net.ParseIP(addr); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{addr}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// challengeTLSConfig loads TLS cert and key from the provided file paths.
func challengeTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading challenge cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
