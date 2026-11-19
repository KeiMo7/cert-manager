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
	"testing"
	"time"
)

func TestValidateBundle(t *testing.T) {
	now := time.Now()
	good := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)

	if err := ValidateBundle(good); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}

	other := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)
	halfCovered := halfCoveredBundle(t, good, other)
	err := ValidateBundle(halfCovered)
	if err == nil {
		t.Fatalf("half-covered bundle must be rejected")
	}

	missingKey := Bundle{Certificate: good.Certificate}
	if err := ValidateBundle(missingKey); err == nil {
		t.Fatalf("bundle without private key must be rejected")
	}

	missingCert := Bundle{PrivateKey: good.PrivateKey}
	if err := ValidateBundle(missingCert); err == nil {
		t.Fatalf("bundle without certificate must be rejected")
	}
}

func TestBundleFingerprintStableAndDistinct(t *testing.T) {
	now := time.Now()
	first := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	second := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)

	if first.Fingerprint() == "" || first.Fingerprint() != first.Fingerprint() {
		t.Fatalf("fingerprint must be stable and non-empty")
	}
	if first.Fingerprint() == second.Fingerprint() {
		t.Fatalf("distinct certificates must have distinct fingerprints")
	}
}

func TestBundleExpiryRisk(t *testing.T) {
	now := time.Now()
	bundle := mustGenerateBundle(t, 1, now.Add(-23*time.Hour), 24*time.Hour)

	atRisk, remaining, err := bundle.ExpiryRisk(now, 2*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !atRisk {
		t.Fatalf("bundle expiring in %s must be at risk", remaining)
	}

	atRisk, _, err = bundle.ExpiryRisk(now, 30*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atRisk {
		t.Fatalf("bundle must not be at risk with a shorter warning period")
	}
}
