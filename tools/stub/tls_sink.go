package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func (s *stub) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		CipherSuites: append([]uint16(nil), staticRSASuites...),
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if blockedSNI(hello.ServerName) {
				s.log.Printf("tls event=refused sni=%s", logToken(hello.ServerName))
				return nil, errors.New("sni refused")
			}
			return nil, nil
		},
		GetCertificate: s.certificate,
	}
}

func blockedSNI(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return name == "lan3rd.line.me"
}

func (s *stub) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSuffix(hello.ServerName, ".")
	if blockedSNI(name) || !sniOK(name) {
		s.log.Printf("tls event=refused sni=%s", logToken(name))
		return nil, errors.New("sni refused")
	}
	if name == "" || sameHost(name, s.cfg.host) {
		if s.pinned != nil {
			return s.pinned, nil
		}
		name = s.cfg.host
	}
	return s.certs.get(name, clock())
}

func sniOK(name string) bool {
	if name == "" {
		return true
	}
	if len(name) > 253 || strings.ContainsAny(name, " /\\@") {
		return false
	}
	if ip := net.ParseIP(name); ip != nil {
		return ip.To4() != nil
	}
	return validateDNS(name) == nil
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

type certCache struct {
	mu sync.Mutex
	m  map[string]*tls.Certificate
}

func newCertCache() *certCache {
	return &certCache{m: map[string]*tls.Certificate{}}
}

func (c *certCache) get(name string, now time.Time) (*tls.Certificate, error) {
	key := strings.ToLower(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.m[key]; ok {
		return cert, nil
	}
	if len(c.m) >= 64 {
		return nil, errors.New("cert cache full")
	}
	cert, err := selfSignedRSA(name, now)
	if err != nil {
		return nil, err
	}
	c.m[key] = cert
	return cert, nil
}

func selfSignedRSA(name string, now time.Time) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cn := name
	if len(cn) > 64 {
		cn = cn[:64]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func loadPinnedRSA(certFile, keyFile, host string, now time.Time) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, errors.New("cert unreadable")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.New("key unreadable")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("cert invalid")
	}
	if _, ok := pair.PrivateKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("cert must be RSA")
	}
	if err := validateLeaf(&pair, host, now); err != nil {
		return nil, err
	}
	return &pair, nil
}

func validateLeaf(cert *tls.Certificate, host string, now time.Time) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return errors.New("cert invalid")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return errors.New("cert invalid")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("cert not valid")
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return errors.New("cert name mismatch")
	}
	return nil
}

func pemPair(certDER []byte, key *rsa.PrivateKey) (certPEM, keyPEM []byte) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

const (
	sinkMaxConns = 32
	sinkMaxRead  = 64 << 10
)

func serveSink(ctx context.Context, ln net.Listener, role string, lg *log.Logger) error {
	sem := make(chan struct{}, sinkMaxConns)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			go func(c net.Conn) {
				defer func() {
					<-sem
					_ = c.Close()
				}()
				handleSink(c, role, lg)
			}(c)
		default:
			lg.Printf("sink role=%s event=refused proto=tcp", role)
			_ = c.Close()
		}
	}
}

func handleSink(c net.Conn, role string, lg *log.Logger) {
	peer := c.RemoteAddr().String()
	lg.Printf("sink role=%s event=accept proto=tcp peer=%s", role, peer)
	buf := make([]byte, 1024)
	read := 0
	hard := time.Now().Add(2 * time.Second)
	_ = c.SetDeadline(hard)
	for read < sinkMaxRead && time.Now().Before(hard) {
		short := time.Now().Add(500 * time.Millisecond)
		if short.After(hard) {
			short = hard
		}
		_ = c.SetReadDeadline(short)
		n, err := c.Read(buf)
		read += n
		if err != nil {
			break
		}
	}
	lg.Printf("sink role=%s event=close proto=tcp peer=%s", role, peer)
}
