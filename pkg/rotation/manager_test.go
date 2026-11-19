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
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"
)

type memoryAudit struct {
	records []AuditRecord
}

func (m *memoryAudit) Write(_ context.Context, record AuditRecord) error {
	m.records = append(m.records, record)
	return nil
}

func newTestManager(targets []Target, reloader Reloader, now time.Time) (*Manager, *memoryStore, *fakeMetrics, *fakeEvents, *memoryAudit) {
	store := newMemoryStore()
	metrics := &fakeMetrics{}
	events := &fakeEvents{}
	audit := &memoryAudit{}
	manager := &Manager{
		Discovery: fakeDiscovery{targets: targets},
		ReloaderFor: func(Config) (Reloader, error) {
			return reloader, nil
		},
		Store:   store,
		Poller:  &fakePoller{},
		Audit:   audit,
		Events:  events,
		Metrics: metrics,
		Push:    fakePush{healthy: true},
		Clock:   clocktesting.NewFakeClock(now),
	}
	return manager, store, metrics, events, audit
}

func TestRotateFansOutToEveryTarget(t *testing.T) {
	now := time.Now()
	oldBundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)
	targets := testTargets(10)

	reloader := newRecordingReloader()
	manager, store, metrics, events, audit := newTestManager(targets, reloader, now)

	ref := SecretRef{Namespace: "shop", Name: "payments-tls"}
	record, err := manager.Rotate(context.Background(), ref, validEnabledConfig(), oldBundle, newBundle, TriggerSecretChange)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	if len(reloader.calls) != len(targets) {
		t.Fatalf("notified %d targets, want %d", len(reloader.calls), len(targets))
	}
	for _, target := range targets {
		if got := reloader.servedFingerprint(target.UID); got != newBundle.Fingerprint() {
			t.Fatalf("target %s serves %s, want %s", target, got, newBundle.Fingerprint())
		}
	}
	if len(record.Results) != 10 {
		t.Fatalf("record has %d results, want 10", len(record.Results))
	}
	if store.previous[ref] != newBundle.Fingerprint() {
		t.Fatalf("retention fingerprint must be stored, got %q", store.previous[ref])
	}
	if metrics.rotations != 1 {
		t.Fatalf("rotation metric not observed")
	}
	if !events.contains(ReasonRotationSucceeded) {
		t.Fatalf("success event missing: %v", events.events)
	}
	if len(audit.records) != 1 || audit.records[0].Fingerprint != newBundle.Fingerprint() {
		t.Fatalf("audit record missing or wrong: %+v", audit.records)
	}
}

func TestRotateRejectsHalfCoveredBundleAndKeepsOld(t *testing.T) {
	now := time.Now()
	oldBundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	other := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)

	reloader := newRecordingReloader()
	targets := testTargets(3)
	manager, store, _, events, _ := newTestManager(targets, reloader, now)

	ref := SecretRef{Namespace: "shop", Name: "payments-tls"}
	_, err := manager.Rotate(context.Background(), ref, validEnabledConfig(), oldBundle, halfCoveredBundle(t, oldBundle, other), TriggerSecretChange)
	if err == nil {
		t.Fatalf("half-covered bundle must abort the rotation")
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("no target must be touched on validation failure")
	}
	if store.saveCalls != 0 {
		t.Fatalf("state must not change on validation failure")
	}
	if !events.contains(ReasonRotationFailed) {
		t.Fatalf("failure event missing")
	}
}

func TestRotateFallsBackToPollingWhenPushUnhealthy(t *testing.T) {
	now := time.Now()
	oldBundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)
	targets := testTargets(10)

	poller := &fakePoller{}
	store := newMemoryStore()
	metrics := &fakeMetrics{}
	events := &fakeEvents{}
	manager := &Manager{
		Discovery: fakeDiscovery{targets: targets},
		Store:     store,
		Poller:    poller,
		Audit:     &memoryAudit{},
		Events:    events,
		Metrics:   metrics,
		Push:      fakePush{healthy: false},
		Clock:     clocktesting.NewFakeClock(now),
	}

	record, err := manager.Rotate(context.Background(), SecretRef{Namespace: "shop", Name: "payments-tls"}, validEnabledConfig(), oldBundle, newBundle, TriggerSecretChange)
	if err != nil {
		t.Fatalf("polling fallback must converge, got %v", err)
	}
	if poller.calls != 1 {
		t.Fatalf("poller was not invoked")
	}
	if record.NotificationOK {
		t.Fatalf("record must show push notification was unavailable")
	}
	if metrics.pollFallbacks != 1 || !events.contains(ReasonPollFallback) {
		t.Fatalf("fallback telemetry missing")
	}
	for _, result := range record.Results {
		if result.Outcome != OutcomeSuccess {
			t.Fatalf("polling path must converge every target, got %+v", result)
		}
	}
}

func TestRotateFailureKeepsOldBundleAndWarnsBeforeExpiry(t *testing.T) {
	// The old certificate expires in one hour; warning period is a week.
	now := time.Now()
	oldBundle := mustGenerateBundle(t, 1, now.Add(-23*time.Hour), 24*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)
	targets := testTargets(3)

	reloader := newRecordingReloader()
	reloader.failNext = true
	manager, store, metrics, events, _ := newTestManager(targets, reloader, now)

	cfg := validEnabledConfig()
	ref := SecretRef{Namespace: "shop", Name: "payments-tls"}
	record, err := manager.Rotate(context.Background(), ref, cfg, oldBundle, newBundle, TriggerSecretChange)
	if err != nil {
		t.Fatalf("per-target failures are results, not manager errors: %v", err)
	}
	failed := record.FailedTargets()
	if len(failed) != 3 {
		t.Fatalf("want 3 failed targets, got %d", len(failed))
	}
	if !events.contains(ReasonRotationFailed) || !events.contains(ReasonExpiryWarning) {
		t.Fatalf("failure and expiry warning events missing: %v", events.events)
	}
	if !metrics.lastAtRisk {
		t.Fatalf("expiry risk metric must be set")
	}
	// State records the failure so the next reconcile retries rather than
	// assuming success.
	states, _, err := store.Load(context.Background(), ref)
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	for _, target := range targets {
		if states[target.UID].Outcome != OutcomeFailed {
			t.Fatalf("target %s state = %+v, want failed", target, states[target.UID])
		}
	}
}

func TestRotateBlocksNotReadyTarget(t *testing.T) {
	now := time.Now()
	oldBundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)
	targets := testTargets(3)

	reloader := newRecordingReloader()
	manager, store, _, events, _ := newTestManager(targets, reloader, now)
	ref := SecretRef{Namespace: "shop", Name: "payments-tls"}

	err := store.Save(context.Background(), ref, map[string]TargetState{
		targets[2].UID: {Outcome: OutcomeFailed, Err: "connection refused", AttemptedAt: now},
	}, oldBundle.Fingerprint())
	if err != nil {
		t.Fatalf("seeding state: %v", err)
	}

	record, err := manager.Rotate(context.Background(), ref, validEnabledConfig(), oldBundle, newBundle, TriggerRetry)
	if err != nil {
		t.Fatalf("rotation returned error: %v", err)
	}
	if len(reloader.calls) != 2 {
		t.Fatalf("blocked target must not be reloaded, got %d calls", len(reloader.calls))
	}
	var blocked int
	for _, result := range record.Results {
		if result.Outcome == OutcomeNotReady {
			blocked++
		}
	}
	if blocked != 1 || !events.contains(ReasonRotationBlocked) {
		t.Fatalf("expected one blocked target with event, got blocked=%d events=%v", blocked, events.events)
	}
}

func TestRotatePostponedOutsideWindow(t *testing.T) {
	now := time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) // Monday noon
	oldBundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 30*24*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Hour), 30*24*time.Hour)
	targets := testTargets(2)

	window, err := ParseWindow("Mon-Fri 01:00-03:00")
	if err != nil {
		t.Fatalf("parse window: %v", err)
	}
	cfg := validEnabledConfig()
	cfg.Window = window

	reloader := newRecordingReloader()
	manager, _, _, _, _ := newTestManager(targets, reloader, now)
	record, err := manager.Rotate(context.Background(), SecretRef{Namespace: "shop", Name: "payments-tls"}, cfg, oldBundle, newBundle, TriggerSecretChange)
	if err != nil {
		t.Fatalf("postponed rotation is not an error: %v", err)
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("no reload may happen outside the window")
	}
	for _, result := range record.Results {
		if result.Outcome != OutcomeSkipped {
			t.Fatalf("all targets must be skipped, got %+v", result)
		}
	}
}

func TestRotateKeepsPreviousFingerprintOnSecondRotation(t *testing.T) {
	now := time.Now()
	first := mustGenerateBundle(t, 1, now.Add(-2*time.Hour), 24*time.Hour)
	second := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)
	third := mustGenerateBundle(t, 3, now.Add(-time.Minute), 24*time.Hour)
	targets := testTargets(2)

	reloader := newRecordingReloader()
	manager, store, _, _, _ := newTestManager(targets, reloader, now)
	ref := SecretRef{Namespace: "shop", Name: "payments-tls"}
	cfg := validEnabledConfig()

	if _, err := manager.Rotate(context.Background(), ref, cfg, first, second, TriggerSecretChange); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if _, err := manager.Rotate(context.Background(), ref, cfg, second, third, TriggerSecretChange); err != nil {
		t.Fatalf("second rotation: %v", err)
	}

	// The rollback record must point at the bundle served before the latest
	// rotation, i.e. the second certificate, not the newest one.
	if store.previous[ref] != second.Fingerprint() {
		t.Fatalf("retention = %q, want previous fingerprint %q", store.previous[ref], second.Fingerprint())
	}
	states, _, err := store.Load(context.Background(), ref)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	for _, target := range targets {
		if states[target.UID].Fingerprint != third.Fingerprint() {
			t.Fatalf("target %s did not converge on the newest fingerprint", target)
		}
	}
}
