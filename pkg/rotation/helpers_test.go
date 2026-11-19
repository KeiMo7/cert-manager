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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

func mustGenerateBundle(t *testing.T, serial int64, notBefore time.Time, lifetime time.Duration) Bundle {
	t.Helper()
	key, err := utilpki.GenerateECPrivateKey(utilpki.ECCurve256)
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(lifetime),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certPEM, _, err := utilpki.SignCertificate(template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	keyPEM, err := utilpki.EncodePrivateKey(key, cmv1.PKCS8)
	if err != nil {
		t.Fatalf("encoding private key: %v", err)
	}
	return Bundle{Certificate: certPEM, PrivateKey: keyPEM}
}

func halfCoveredBundle(t *testing.T, certBundle, keyBundle Bundle) Bundle {
	t.Helper()
	return Bundle{Certificate: certBundle.Certificate, PrivateKey: keyBundle.PrivateKey}
}

func testTargets(n int) []Target {
	targets := make([]Target, n)
	for i := range n {
		targets[i] = Target{
			UID:       string(rune('a' + i)),
			Namespace: "shop",
			Name:      "payments-" + string(rune('0'+i)),
			PodIP:     "10.0.0." + string(rune('1'+i)),
		}
	}
	return targets
}

type fakeDiscovery struct {
	targets []Target
	err     error
}

func (f fakeDiscovery) Discover(_ context.Context, _, _ string) ([]Target, error) {
	return f.targets, f.err
}

type memoryStore struct {
	mu        sync.Mutex
	states    map[SecretRef]map[string]TargetState
	previous  map[SecretRef]string
	saveCalls int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		states:   map[SecretRef]map[string]TargetState{},
		previous: map[SecretRef]string{},
	}
}

func (m *memoryStore) Load(_ context.Context, ref SecretRef) (map[string]TargetState, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	states := map[string]TargetState{}
	for uid, state := range m.states[ref] {
		states[uid] = state
	}
	return states, m.previous[ref], nil
}

func (m *memoryStore) Save(_ context.Context, ref SecretRef, states map[string]TargetState, previousFingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveCalls++
	cloned := map[string]TargetState{}
	for uid, state := range states {
		cloned[uid] = state
	}
	m.states[ref] = cloned
	m.previous[ref] = previousFingerprint
	return nil
}

type recordingReloader struct {
	results  map[string]ReloadResult
	calls    []Target
	served   map[string]*CertStore
	mu       sync.Mutex
	failNext bool
}

func newRecordingReloader() *recordingReloader {
	return &recordingReloader{
		results: map[string]ReloadResult{},
		served:  map[string]*CertStore{},
	}
}

func (r *recordingReloader) Reload(_ context.Context, target Target, bundle Bundle) ReloadResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, target)
	if result, ok := r.results[target.UID]; ok {
		return result
	}
	if r.failNext {
		return ReloadResult{Target: target, Outcome: OutcomeFailed, Fingerprint: bundle.Fingerprint(), Err: errBoom, AttemptedAt: time.Now()}
	}
	// Simulate the workload's graceful in-process swap.
	store := r.served[target.UID]
	if store == nil {
		var err error
		store, err = NewCertStore(bundle)
		if err != nil {
			return ReloadResult{Target: target, Outcome: OutcomeFailed, Err: err, AttemptedAt: time.Now()}
		}
		r.served[target.UID] = store
	} else if err := store.Swap(bundle); err != nil {
		return ReloadResult{Target: target, Outcome: OutcomeFailed, Err: err, AttemptedAt: time.Now()}
	}
	return ReloadResult{Target: target, Outcome: OutcomeSuccess, Fingerprint: bundle.Fingerprint(), AttemptedAt: time.Now()}
}

func (r *recordingReloader) servedFingerprint(uid string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.served[uid].Fingerprint()
}

type fakePoller struct {
	calls int
}

func (f *fakePoller) Converge(_ context.Context, _ SecretRef, targets []Target, bundle Bundle) []ReloadResult {
	f.calls++
	results := make([]ReloadResult, 0, len(targets))
	for _, target := range targets {
		results = append(results, ReloadResult{Target: target, Outcome: OutcomeSuccess, Fingerprint: bundle.Fingerprint(), AttemptedAt: time.Now()})
	}
	return results
}

type fakeMetrics struct {
	mu            sync.Mutex
	rotations     int
	pollFallbacks int
	lastOutcomes  map[Outcome]int
	lastAtRisk    bool
	lastRemaining time.Duration
}

func (f *fakeMetrics) ObserveRotation(_ SecretRef, _ time.Duration, outcomes map[Outcome]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotations++
	f.lastOutcomes = outcomes
}

func (f *fakeMetrics) SetExpiryRisk(_ SecretRef, atRisk bool, remaining time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAtRisk = atRisk
	f.lastRemaining = remaining
}

func (f *fakeMetrics) ObservePollFallback(_ SecretRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollFallbacks++
}

type fakeEvents struct {
	mu     sync.Mutex
	events []string
}

func (f *fakeEvents) Event(_ any, _, reason, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, reason+": "+message)
}

func (f *fakeEvents) contains(reason string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, event := range f.events {
		if len(event) >= len(reason) && event[:len(reason)] == reason {
			return true
		}
	}
	return false
}

type fakePush struct{ healthy bool }

func (f fakePush) PushHealthy() bool { return f.healthy }

type boomError struct{}

func (boomError) Error() string { return "boom" }

var errBoom = boomError{}

func secretWithBundleAndExtraFields(bundle Bundle) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop",
			Name:      "payments-tls",
			Annotations: map[string]string{
				"unrelated-annotation": "must-survive",
			},
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       bundle.Certificate,
			corev1.TLSPrivateKeyKey: bundle.PrivateKey,
			"unrelated-field":       []byte("do-not-touch"),
		},
	}
}

func dumpSecret(secret *corev1.Secret) string {
	parts := []string{secret.Name, secret.Namespace}
	for key, value := range secret.Annotations {
		parts = append(parts, "a:"+key+"="+string(value))
	}
	for key, value := range secret.Data {
		parts = append(parts, "d:"+key+"="+string(value))
	}
	slices.Sort(parts)
	return strings.Join(parts, "|")
}
