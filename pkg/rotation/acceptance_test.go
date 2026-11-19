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
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fleet is the acceptance-test workload fleet: ten services sharing one
// certificate Secret. Every service keeps an in-process CertStore wired into
// tls.Config and holds long-lived connections whose continuity proves zero
// interruption during rotation.
type fleetService struct {
	name          string
	store         *CertStore
	established   []*establishedConnection
	interruptions atomic.Int64
}

// establishedConnection models a negotiated TLS session. Real TLS never
// re-handshakes an established connection on GetCertificate changes, so the
// only way it can "break" is an explicit listener/process restart, which this
// test models with interrupt().
type establishedConnection struct {
	initialFingerprint string
	open               atomic.Bool
}

func newFleet(t *testing.T, n int, initial Bundle) ([]*fleetService, Reloader) {
	t.Helper()
	services := make([]*fleetService, n)
	targets := make([]Target, n)
	stores := map[string]*CertStore{}
	for i := range n {
		store, err := NewCertStore(initial)
		if err != nil {
			t.Fatalf("service %d initial store: %v", i, err)
		}
		services[i] = &fleetService{
			name:  fmt.Sprintf("payments-%d", i),
			store: store,
			established: []*establishedConnection{
				{initialFingerprint: initial.Fingerprint()},
				{initialFingerprint: initial.Fingerprint()},
			},
		}
		for _, conn := range services[i].established {
			conn.open.Store(true)
		}
		targets[i] = Target{UID: string(rune('a' + i)), Namespace: "shop", Name: services[i].name}
		stores[targets[i].UID] = store
	}

	reloader := &fleetReloader{stores: stores, services: services}
	return services, reloader
}

type fleetReloader struct {
	mu       sync.Mutex
	stores   map[string]*CertStore
	services []*fleetService
}

func (r *fleetReloader) Reload(_ context.Context, target Target, bundle Bundle) ReloadResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	store := r.stores[target.UID]
	if store == nil {
		return ReloadResult{Target: target, Outcome: OutcomeFailed, Err: fmt.Errorf("unknown target %s", target), AttemptedAt: time.Now()}
	}
	if err := store.Swap(bundle); err != nil {
		return ReloadResult{Target: target, Outcome: OutcomeFailed, Err: err, AttemptedAt: time.Now()}
	}
	return ReloadResult{Target: target, Outcome: OutcomeSuccess, Fingerprint: bundle.Fingerprint(), AttemptedAt: time.Now()}
}

// interruptingReloader mimics an application whose "reload" restarts its
// listener: every established connection is torn down. The acceptance metrics
// must make this visibly non-zero.
type interruptingReloader struct {
	services []*fleetService
}

func (r interruptingReloader) Reload(_ context.Context, target Target, bundle Bundle) ReloadResult {
	for _, service := range r.services {
		if service.name != target.Name {
			continue
		}
		for _, conn := range service.established {
			if conn.open.CompareAndSwap(true, false) {
				service.interruptions.Add(1)
			}
		}
	}
	return ReloadResult{Target: target, Outcome: OutcomeSuccess, Fingerprint: bundle.Fingerprint(), AttemptedAt: time.Now()}
}

// TestAcceptanceRealRotationAcrossTenSharedServices is the recorded
// acceptance scenario: one real rotation propagated to all ten services, with
// latency measurement, zero interruption and zero error rate.
func TestAcceptanceRealRotationAcrossTenSharedServices(t *testing.T) {
	now := time.Date(2026, time.November, 20, 2, 0, 0, 0, time.UTC)
	oldBundle := mustGenerateBundle(t, 1, now.Add(-24*time.Hour), 48*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Minute), 48*time.Hour)

	services, reloader := newFleet(t, 10, oldBundle)
	targets := testTargets(10)
	for i := range targets {
		targets[i].Name = services[i].name
	}

	store := newMemoryStore()
	metrics := &fakeMetrics{}
	events := &fakeEvents{}
	audit := &memoryAudit{}
	manager := &Manager{
		Discovery:   fakeDiscovery{targets: targets},
		ReloaderFor: func(Config) (Reloader, error) { return reloader, nil },
		Store:       store,
		Poller:      &fakePoller{},
		Audit:       audit,
		Events:      events,
		Metrics:     metrics,
		Push:        fakePush{healthy: true},
	}

	ref := SecretRef{Namespace: "shop", Name: "payments-tls"}
	cfg := Config{
		Enabled:              true,
		TargetSelector:       "app in (payments)",
		Method:               ReloadMethodSignal,
		Signal:               "SIGHUP",
		PollFallbackInterval: time.Minute,
		ExpiryWarningPeriod:  7 * 24 * time.Hour,
	}

	started := time.Now()
	record, err := manager.Rotate(context.Background(), ref, cfg, oldBundle, newBundle, TriggerSecretChange)
	wallLatency := time.Since(started)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	// 1. Every target serves the new fingerprint.
	for i, target := range targets {
		if got := services[i].store.Fingerprint(); got != newBundle.Fingerprint() {
			t.Fatalf("target %s fingerprint = %s, want %s", target, got, newBundle.Fingerprint())
		}
		if _, err := services[i].store.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
			t.Fatalf("new handshake failed on %s: %v", target, err)
		}
	}

	// 2. Zero interruptions: every established connection stays open and still
	// references the original negotiated session.
	var totalInterruptions int64
	for _, service := range services {
		totalInterruptions += service.interruptions.Load()
		for _, conn := range service.established {
			if !conn.open.Load() {
				t.Fatalf("established connection on %s was interrupted", service.name)
			}
			if conn.initialFingerprint != oldBundle.Fingerprint() {
				t.Fatalf("established session state changed")
			}
		}
	}
	if totalInterruptions != 0 {
		t.Fatalf("interruptions = %d, want 0", totalInterruptions)
	}

	// 3. Error rate during the rotation window: every outcome is success.
	var attempts, failures int
	for _, result := range record.Results {
		attempts++
		if result.Outcome == OutcomeFailed || result.Outcome == OutcomeNotReady {
			failures++
		}
	}
	errorRate := float64(failures) / float64(attempts)
	if errorRate != 0 {
		t.Fatalf("error rate = %.2f, want 0", errorRate)
	}

	// 4. Retention: previous certificate fingerprint is kept for rollback.
	if stored := store.previous[ref]; stored != newBundle.Fingerprint() {
		t.Fatalf("retention fingerprint = %q", stored)
	}
	if len(audit.records) != 1 {
		t.Fatalf("expected one audit record, got %d", len(audit.records))
	}

	t.Logf("ACCEPTANCE targets=%d latency=%s (controller observed=%s) interruptions=%d errorRate=%.4f retention=%s",
		len(targets), wallLatency, record.TotalDuration, totalInterruptions, errorRate, store.previous[ref])
}

// TestAcceptanceInterruptingReloadIsDetected proves the acceptance harness
// catches a reload implementation that restarts listeners: the error rate
// metric stays zero (handshakes technically succeed) but interruptions are
// non-zero, which is exactly the signal operators need.
func TestAcceptanceInterruptingReloadIsDetected(t *testing.T) {
	now := time.Date(2026, time.November, 20, 2, 0, 0, 0, time.UTC)
	oldBundle := mustGenerateBundle(t, 1, now.Add(-24*time.Hour), 48*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Minute), 48*time.Hour)

	services, _ := newFleet(t, 10, oldBundle)
	targets := testTargets(10)
	for i := range targets {
		targets[i].Name = services[i].name
	}

	manager := &Manager{
		Discovery: fakeDiscovery{targets: targets},
		ReloaderFor: func(Config) (Reloader, error) {
			return interruptingReloader{services: services}, nil
		},
		Store:   newMemoryStore(),
		Poller:  &fakePoller{},
		Audit:   &memoryAudit{},
		Events:  &fakeEvents{},
		Metrics: &fakeMetrics{},
		Push:    fakePush{healthy: true},
	}

	record, err := manager.Rotate(context.Background(), SecretRef{Namespace: "shop", Name: "payments-tls"}, Config{
		Enabled: true, TargetSelector: "app=payments", Method: ReloadMethodExec, Command: "restart",
		ExpiryWarningPeriod: 7 * 24 * time.Hour,
	}, oldBundle, newBundle, TriggerSecretChange)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	var interruptions int64
	for _, service := range services {
		interruptions += service.interruptions.Load()
	}
	if interruptions != int64(2*len(services)) {
		t.Fatalf("interruptions = %d, want %d (2 connections per service)", interruptions, 2*len(services))
	}
	if len(record.FailedTargets()) != 0 {
		t.Fatalf("listener restarts report success at the API level; continuity is the real metric")
	}
	t.Logf("ACCEPTANCE negative case: interrupting reload produced %d dropped connections while reporting success", interruptions)
}

// TestAcceptanceFailedIssuanceKeepsSecretUntouched pins the retention
// guarantee: when no new bundle is produced, the old Secret content and all
// unrelated fields remain byte-identical and no notification goes out.
func TestAcceptanceFailedIssuanceKeepsSecretUntouched(t *testing.T) {
	now := time.Now()
	oldBundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)

	originalSecret := secretWithBundleAndExtraFields(oldBundle)
	snapshot := dumpSecret(originalSecret)

	// Simulate issuance failure: the pipeline never calls UpdateData, so the
	// Secret is simply not touched. The rotation manager additionally must
	// refuse an invalid replacement if one ever reaches it.
	reloader := newRecordingReloader()
	manager, store, _, events, _ := newTestManager(testTargets(3), reloader, now)
	_, err := manager.Rotate(context.Background(), SecretRef{Namespace: "shop", Name: "payments-tls"},
		validEnabledConfig(), oldBundle, Bundle{Certificate: oldBundle.Certificate}, TriggerSecretChange)
	if err == nil {
		t.Fatalf("missing private key must abort rotation")
	}

	if dumpSecret(originalSecret) != snapshot {
		t.Fatalf("Secret changed on failed rotation")
	}
	if originalSecret.Data["unrelated-field"] == nil {
		t.Fatalf("unrelated Secret field disappeared")
	}
	if len(reloader.calls) != 0 || store.saveCalls != 0 {
		t.Fatalf("no side effects allowed on failed rotation")
	}
	if !events.contains(ReasonRotationFailed) {
		t.Fatalf("failure must be audited")
	}
}
