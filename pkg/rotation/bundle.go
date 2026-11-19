/*
Copyright 2026 The cert-manager Authors.

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

package rotation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

// Bundle is the certificate material a workload serves.
type Bundle struct {
	Certificate []byte
	PrivateKey  []byte
	CA          []byte

	parsed *x509.Certificate
}

// BundleFromSecret extracts the TLS material from a certificate Secret.
func BundleFromSecret(secret *corev1.Secret) Bundle {
	return Bundle{
		Certificate: secret.Data[corev1.TLSCertKey],
		PrivateKey:  secret.Data[corev1.TLSPrivateKeyKey],
		CA:          secret.Data["ca.crt"],
	}
}

// ValidateBundle rejects a bundle that must never be persisted or served.
//
// The half-coverage failure mode (certificate rotated while the private key is
// not) is caught here: the decoded certificate's public key has to match the
// decoded private key. A bundle that fails this check cannot establish a
// handshake, so callers must abort the rotation and keep the previous bundle
// untouched rather than write the broken one.
func ValidateBundle(bundle Bundle) error {
	if len(bundle.Certificate) == 0 {
		return fmt.Errorf("bundle has no certificate data")
	}
	if len(bundle.PrivateKey) == 0 {
		return fmt.Errorf("bundle has no private key data")
	}

	certificate, err := utilpki.DecodeX509CertificateBytes(bundle.Certificate)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}
	privateKey, err := utilpki.DecodePrivateKeyBytes(bundle.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	matches, err := utilpki.PublicKeyMatchesCertificate(privateKey.Public(), certificate)
	if err != nil {
		return fmt.Errorf("failed to compare certificate and private key: %w", err)
	}
	if !matches {
		return fmt.Errorf("refusing half-covered bundle: certificate public key does not match private key")
	}

	return nil
}

// Parse decodes the leaf certificate. It returns an error if the bundle has
// not previously passed ValidateBundle.
func (b Bundle) Parse() (*x509.Certificate, error) {
	if b.parsed != nil {
		return b.parsed, nil
	}
	certificate, err := utilpki.DecodeX509CertificateBytes(b.Certificate)
	if err != nil {
		return nil, err
	}
	b.parsed = certificate
	return certificate, nil
}

// Fingerprint is a stable identifier of the certificate bytes. Only the
// certificate is hashed: private key material must never be copied into audit
// records or status objects.
func (b Bundle) Fingerprint() string {
	sum := sha256.Sum256(b.Certificate)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NotAfter returns the leaf certificate expiry.
func (b Bundle) NotAfter() (time.Time, error) {
	certificate, err := b.Parse()
	if err != nil {
		return time.Time{}, err
	}
	return certificate.NotAfter, nil
}

// ExpiryRisk reports whether the bundle expires within warningPeriod of now.
func (b Bundle) ExpiryRisk(now time.Time, warningPeriod time.Duration) (bool, time.Duration, error) {
	notAfter, err := b.NotAfter()
	if err != nil {
		return false, 0, err
	}
	remaining := notAfter.Sub(now)
	return remaining <= warningPeriod, remaining, nil
}
