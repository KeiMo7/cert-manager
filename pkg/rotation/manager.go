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
	"fmt"
	"time"

	"k8s.io/utils/clock"
)

// SecretRef identifies a rotated certificate Secret.
type SecretRef struct {
	Namespace string
	Name      string
}

// StateStore persists per-target reload state and the previous certificate
// fingerprint (the retention/rollback record).
type StateStore interface {
	Load(ctx context.Context, ref SecretRef) (states map[string]TargetState, previousFingerprint string, err error)
	Save(ctx context.Context, ref SecretRef, states map[string]TargetState, previousFingerprint string) error
}

// FleetPoller is the degraded polling path: it represents the rotation
// agents watching the mounted files. When push notifications are unhealthy
// the manager delegates convergence to it.
type FleetPoller interface {
	Converge(ctx context.Context, ref SecretRef, targets []Target, bundle Bundle) []ReloadResult
}

// Metrics receives rotation telemetry. The controller provides a Prometheus
// implementation; tests use a fake.
type Metrics interface {
	ObserveRotation(ref SecretRef, duration time.Duration, outcomes map[Outcome]int)
	SetExpiryRisk(ref SecretRef, atRisk bool, remaining time.Duration)
	ObservePollFallback(ref SecretRef)
}

// PushHealth decides whether the push notification channel (pods/exec,
// pod-to-pod HTTP) is available.
type PushHealth interface {
	PushHealthy() bool
}

// Manager orchestrates a rotation across every workload sharing a Secret.
type Manager struct {
	Discovery   TargetDiscovery
	ReloaderFor func(cfg Config) (Reloader, error)
	Store       StateStore
	Poller      FleetPoller
	Audit       AuditSink
	Events      EventRecorder
	Metrics     Metrics
	Push        PushHealth
	Clock       clock.Clock
}

// RetryBackoff returns the wait before the nth retry (n is 1-based).
func RetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// 30s, 1m, 2m, 4m ... capped at 10 minutes.
	if attempt >= 6 {
		return 10 * time.Minute
	}
	backoff := 30 * time.Second * time.Duration(1<<(attempt-1))
	if backoff > 10*time.Minute {
		return 10 * time.Minute
	}
	return backoff
}

// Rotate fans a rotated bundle out to every target of ref. It never mutates
// the Secret: issuance and storage stay with the existing pipeline. The
// previous bundle remains the served bundle on any target whose reload fails.
func (m *Manager) Rotate(ctx context.Context, ref SecretRef, cfg Config, served, next Bundle, trigger AuditTrigger) (*AuditRecord, error) {
	now := m.now()
	record := &AuditRecord{
		Time:       now,
		Trigger:    trigger,
		Namespace:  ref.Namespace,
		SecretName: ref.Name,
		Selector:   cfg.TargetSelector,
	}

	// A bundle that cannot be validated (notably a cert/key half-coverage) is
	// rejected before any target is touched. The old bundle stays in place.
	if err := ValidateBundle(next); err != nil {
		m.recordEvent(ReasonRotationFailed, "Refusing rotated bundle for %s/%s: %v", ref.Namespace, ref.Name, err)
		return record, fmt.Errorf("rotated bundle failed validation: %w", err)
	}
	record.Fingerprint = next.Fingerprint()

	states, previousFingerprint, err := m.Store.Load(ctx, ref)
	if err != nil {
		return record, fmt.Errorf("loading rotation state: %w", err)
	}
	record.PreviousPrint = previousFingerprint

	targets, err := m.Discovery.Discover(ctx, ref.Namespace, cfg.TargetSelector)
	if err != nil {
		return record, fmt.Errorf("discovering rotation targets: %w", err)
	}
	record.Targets = targets

	issues, err := CheckReadiness(cfg, targets, states)
	if err != nil {
		m.recordEvent(ReasonRotationBlocked, "Rotation blocked for %s/%s: %v", ref.Namespace, ref.Name, err)
		return record, err
	}

	reloadNow, _, overridden, err := ShouldReloadNow(cfg, served, now)
	if err != nil {
		return record, fmt.Errorf("evaluating reload window: %w", err)
	}
	record.WindowOverridden = overridden
	if overridden {
		m.recordEvent(ReasonWindowOverride, "Certificate for %s/%s is inside its expiry warning period; proceeding outside the configured window", ref.Namespace, ref.Name)
	}

	m.recordEvent(ReasonRotationStarted, "Rotating %s/%s to %s for %d target(s)", ref.Namespace, ref.Name, record.Fingerprint, len(targets))

	blocked := map[string]ReadinessIssue{}
	for _, issue := range issues {
		blocked[issue.Target.UID] = issue
		m.recordEvent(ReasonRotationBlocked, "Target %s not ready: %s", issue.Target, issue.Reason)
	}

	if !reloadNow {
		// Outside the window with no expiry pressure: nothing is reloaded and
		// the controller requeues for the next window.
		record.Results = m.skippedResults(targets, blocked, next, now)
		m.finish(ctx, ref, cfg, record, states, next, nil)
		return record, nil
	}

	pushHealthy := m.Push == nil || m.Push.PushHealthy()
	if !pushHealthy {
		// Degraded path: let the polling agents converge instead of failing.
		m.Metrics.ObservePollFallback(ref)
		m.recordEvent(ReasonPollFallback, "Push channel unavailable for %s/%s; falling back to file polling", ref.Namespace, ref.Name)
		record.NotificationOK = false
		record.Results = m.Poller.Converge(ctx, ref, targets, next)
	} else {
		reloader, err := m.ReloaderFor(cfg)
		if err != nil {
			return record, fmt.Errorf("building reloader: %w", err)
		}
		record.NotificationOK = true
		record.Results = m.fanOut(ctx, reloader, targets, blocked, next, now)
	}

	m.finish(ctx, ref, cfg, record, states, next, blocked)
	return record, nil
}

func (m *Manager) fanOut(ctx context.Context, reloader Reloader, targets []Target, blocked map[string]ReadinessIssue, bundle Bundle, now time.Time) []ReloadResult {
	results := make([]ReloadResult, 0, len(targets))
	for _, target := range targets {
		if issue, ok := blocked[target.UID]; ok {
			results = append(results, ReloadResult{
				Target:      target,
				Outcome:     OutcomeNotReady,
				Fingerprint: bundle.Fingerprint(),
				Err:         fmt.Errorf("%s", issue.Reason),
				AttemptedAt: now,
			})
			continue
		}
		results = append(results, reloader.Reload(ctx, target, bundle))
	}
	return results
}

func (m *Manager) skippedResults(targets []Target, blocked map[string]ReadinessIssue, bundle Bundle, now time.Time) []ReloadResult {
	results := make([]ReloadResult, 0, len(targets))
	for _, target := range targets {
		outcome := OutcomeSkipped
		var err error
		if issue, ok := blocked[target.UID]; ok {
			outcome = OutcomeNotReady
			err = fmt.Errorf("%s", issue.Reason)
		}
		results = append(results, ReloadResult{
			Target:      target,
			Outcome:     outcome,
			Fingerprint: bundle.Fingerprint(),
			Err:         err,
			AttemptedAt: now,
		})
	}
	return results
}

func (m *Manager) finish(ctx context.Context, ref SecretRef, cfg Config, record *AuditRecord, previous map[string]TargetState, next Bundle, blocked map[string]ReadinessIssue) {
	record.TotalDuration = m.now().Sub(record.Time)

	nextStates := make(map[string]TargetState, len(record.Results))
	outcomes := map[Outcome]int{}
	for _, result := range record.Results {
		outcomes[result.Outcome]++
		errText := ""
		if result.Err != nil {
			errText = result.Err.Error()
		}
		nextStates[result.Target.UID] = TargetState{
			Fingerprint: result.Fingerprint,
			Outcome:     result.Outcome,
			Err:         errText,
			AttemptedAt: result.AttemptedAt,
		}
	}

	// Retention: the previous fingerprint is kept as the rollback record. On
	// failure the target keeps serving its old in-memory bundle, and the state
	// store retains both fingerprints.
	retentionFingerprint := record.PreviousPrint
	if retentionFingerprint == "" {
		retentionFingerprint = record.Fingerprint
	}
	if err := m.Store.Save(ctx, ref, nextStates, retentionFingerprint); err != nil {
		m.recordEvent(ReasonRotationFailed, "Failed persisting rotation state for %s/%s: %v", ref.Namespace, ref.Name, err)
	}

	failed := record.FailedTargets()
	if len(failed) == 0 {
		m.recordEvent(ReasonRotationSucceeded, "Rotation of %s/%s converged on %d target(s) in %s", ref.Namespace, ref.Name, len(record.Results), record.TotalDuration)
	} else {
		m.recordEvent(ReasonRotationFailed, "Rotation of %s/%s incomplete: %d of %d target(s) failed", ref.Namespace, ref.Name, len(failed), len(record.Results))
	}

	if atRisk, remaining, err := next.ExpiryRisk(m.now(), cfg.ExpiryWarningPeriod); err == nil {
		m.Metrics.SetExpiryRisk(ref, atRisk, remaining)
		if atRisk && len(failed) > 0 {
			m.recordEvent(ReasonExpiryWarning, "Certificate %s/%s expires in %s and %d target(s) have not reloaded", ref.Namespace, ref.Name, remaining.Round(time.Second), len(failed))
		}
	}

	m.Metrics.ObserveRotation(ref, record.TotalDuration, outcomes)
	if m.Audit != nil {
		_ = m.Audit.Write(ctx, *record)
	}
}

func (m *Manager) recordEvent(reason, format string, args ...any) {
	if m.Events != nil {
		m.Events.Event(nil, "Warning", reason, fmt.Sprintf(format, args...))
	}
}

func (m *Manager) now() time.Time {
	if m.Clock != nil {
		return m.Clock.Now()
	}
	return time.Now()
}
