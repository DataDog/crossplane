/*
Copyright 2026 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/crossplane/crossplane-runtime/v2/pkg/logging"
)

// This catches stale client certificates and CA pools in the TLS config cloned
// by gRPC before an atomic replacement of the certificates-directory symlink.
func TestLoadClientTLSConfigRotation(t *testing.T) {
	oldCA := newTestCA(t, "old")
	newCA := newTestCA(t, "new")
	oldClient := newTestLeaf(t, oldCA, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	newClient := newTestLeaf(t, newCA, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	oldServer := newTestLeaf(t, oldCA, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	newServer := newTestLeaf(t, newCA, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))

	dir := t.TempDir()
	oldDir := filepath.Join(dir, "old")
	newDir := filepath.Join(dir, "new")
	writeTestClientBundle(t, oldDir, oldCA, oldClient)
	writeTestClientBundle(t, newDir, newCA, newClient)
	current := filepath.Join(dir, "current")
	if err := os.Symlink(oldDir, current); err != nil {
		t.Fatal(err)
	}

	config, watcher := newTestClientTLSConfig(t, current)
	cloned := config.Clone()
	cloned.ServerName = "function.example.com"
	assertClientHandshake(t, cloned, oldCA, oldServer, oldClient)
	if err := cloned.VerifyConnection(serverConnectionState(newServer)); err == nil {
		t.Fatal("trusted the new CA before rotation")
	}

	// Rename the replacement symlink over the existing one to publish a
	// complete new bundle rather than updating files in place.
	next := filepath.Join(dir, "next")
	if err := os.Symlink(newDir, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, current); err != nil {
		t.Fatal(err)
	}
	if err := watcher.ReadCertificate(); err != nil {
		t.Fatal(err)
	}

	// ReadCertificate invokes our CA reload callback asynchronously. Wait for
	// observable trust to change, without replacing the production callback.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for err := cloned.VerifyConnection(serverConnectionState(newServer)); err != nil; err = cloned.VerifyConnection(serverConnectionState(newServer)) {
		select {
		case <-deadline.C:
			t.Fatalf("cloned config did not trust the new CA after rotation: %v", err)
		case <-ticker.C:
		}
	}
	assertClientHandshake(t, cloned, newCA, newServer, newClient)
	if err := cloned.VerifyConnection(serverConnectionState(oldServer)); err == nil {
		t.Fatal("cloned config still trusted the old CA after rotation")
	}
}

// This catches accidentally bypassing server identity, chain, or expiry checks
// when InsecureSkipVerify is enabled for dynamic CA verification.
func TestLoadClientTLSConfigVerifyConnection(t *testing.T) {
	ca := newTestCA(t, "trusted")
	untrustedCA := newTestCA(t, "untrusted")
	client := newTestLeaf(t, ca, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	server := newTestLeaf(t, ca, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	untrusted := newTestLeaf(t, untrustedCA, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	expired := newTestLeaf(t, ca, x509.ExtKeyUsageServerAuth, time.Now().Add(-time.Hour))
	intermediate := newTestCertificate(t, &x509.Certificate{
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
		Subject:  pkix.Name{CommonName: "intermediate"},
		NotAfter: time.Now().Add(time.Hour),
	}, &ca)
	chained := newTestLeaf(t, intermediate, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))

	dir := t.TempDir()
	writeTestClientBundle(t, dir, ca, client)
	config, _ := newTestClientTLSConfig(t, dir)
	cloned := config.Clone()
	cases := map[string]struct {
		state   tls.ConnectionState
		wantErr bool
	}{
		"TrustedServer": {state: serverConnectionState(server)},
		"WrongHostname": {
			state:   tls.ConnectionState{ServerName: "other.example.com", PeerCertificates: []*x509.Certificate{server.cert}},
			wantErr: true,
		},
		"UntrustedCA":   {state: serverConnectionState(untrusted), wantErr: true},
		"ExpiredServer": {state: serverConnectionState(expired), wantErr: true},
		"MissingPeers":  {state: tls.ConnectionState{ServerName: "function.example.com"}, wantErr: true},
		"ValidIntermediateChain": {
			state: tls.ConnectionState{ServerName: "function.example.com", PeerCertificates: []*x509.Certificate{chained.cert, intermediate.cert}},
		},
		"MissingIntermediate": {state: serverConnectionState(chained), wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := cloned.VerifyConnection(tc.state)
			if (err != nil) != tc.wantErr {
				t.Fatalf("VerifyConnection() error = %v, want error = %t", err, tc.wantErr)
			}
		})
	}
}

type testCertificate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T, name string) testCertificate {
	t.Helper()
	return newTestCertificate(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: name},
		IsCA:    true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
		NotAfter: time.Now().Add(time.Hour),
	}, nil)
}

func newTestLeaf(t *testing.T, ca testCertificate, usage x509.ExtKeyUsage, notAfter time.Time) testCertificate {
	t.Helper()
	return newTestCertificate(t, &x509.Certificate{
		DNSNames:    []string{"function.example.com"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
		NotAfter:    notAfter,
	}, &ca)
}

func newTestCertificate(t *testing.T, template *x509.Certificate, parent *testCertificate) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template.NotBefore = time.Now().Add(-2 * time.Hour)
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{cert: cert, key: key, der: der}
}

func writeTestClientBundle(t *testing.T, dir string, ca, client testCertificate) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalECPrivateKey(client.key)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"ca.pem":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der}),
		"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client.der}),
		"key.pem":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func newTestClientTLSConfig(t *testing.T, dir string) (*tls.Config, *certwatcher.CertWatcher) {
	t.Helper()
	config, watcher, err := loadClientTLSConfig(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), logging.NewNopLogger())
	if err != nil {
		t.Fatal(err)
	}
	// CertWatcher only exposes resource cleanup through Start. Its initial
	// watch registration runs even with an already-cancelled context, then it
	// closes the watcher immediately. Keep the files until cleanup completes.
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := watcher.Start(ctx); err != nil {
			t.Errorf("close certificate watcher: %v", err)
		}
	})
	if config.VerifyConnection == nil {
		t.Fatal("dynamic server verification callback is missing")
	}
	return config, watcher
}

func serverConnectionState(server testCertificate) tls.ConnectionState {
	return tls.ConnectionState{ServerName: "function.example.com", PeerCertificates: []*x509.Certificate{server.cert}}
}

func assertClientHandshake(t *testing.T, config *tls.Config, ca, server, wantClient testCertificate) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	serverTLS := tls.Server(serverConn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{server.der}, PrivateKey: server.key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.Handshake() }()
	clientErr := tls.Client(clientConn, config).Handshake()
	serverErr := <-serverDone
	if clientErr != nil || serverErr != nil {
		t.Fatalf("TLS handshake failed: client = %v, server = %v", clientErr, serverErr)
	}
	peers := serverTLS.ConnectionState().PeerCertificates
	if len(peers) == 0 || !bytes.Equal(peers[0].Raw, wantClient.der) {
		t.Fatal("server did not receive the expected client certificate")
	}
}
