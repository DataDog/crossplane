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
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync/atomic"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/crossplane/crossplane-runtime/v2/pkg/certificates"
	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
	"github.com/crossplane/crossplane-runtime/v2/pkg/logging"
)

// loadClientTLSConfig loads client certificates and trust, and returns the
// watcher that the caller must add to the manager to reload them on rotation.
func loadClientTLSConfig(caPath, certPath, keyPath string, log logging.Logger) (*tls.Config, *certwatcher.CertWatcher, error) {
	clienttls, err := certificates.LoadMTLSConfig(caPath, certPath, keyPath, false)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot load client TLS certificates")
	}

	clientCertWatcher, err := certwatcher.New(certPath, keyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create client certificate watcher")
	}
	clienttls.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return clientCertWatcher.GetCertificate(nil)
	}

	var clientRootCAs atomic.Pointer[x509.CertPool]

	loadClientRootCAs := func() error {
		ca, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return errors.New("no valid certificates found in CA bundle")
		}
		clientRootCAs.Store(pool)
		return nil
	}
	if err := loadClientRootCAs(); err != nil {
		return nil, nil, errors.Wrap(err, "cannot load client CA certificate")
	}

	// grpc's credentials.NewTLS clones this *tls.Config once when the function
	// runner is constructed, so mutating clienttls.RootCAs afterwards has
	// no effect on future handshakes. Verify manually instead, reading the CA
	// pool from clientRootCAs on every connection, so CA rotation actually
	// takes effect.
	clienttls.InsecureSkipVerify = true
	clienttls.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no peer certificates presented")
		}
		opts := x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Roots:         clientRootCAs.Load(),
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}

	clientCertWatcher.RegisterCallback(func(_ tls.Certificate) {
		if err := loadClientRootCAs(); err != nil {
			log.Info("Cannot reload client CA certificate, keeping previous CA pool", "path", caPath, "error", err)
		}
	})
	return clienttls, clientCertWatcher, nil
}
