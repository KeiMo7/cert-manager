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
	"time"
)

// AuditTrigger identifies what started a rotation attempt.
type AuditTrigger string

const (
	// TriggerSecretChange is a real rotation detected via a Secret watch.
	TriggerSecretChange AuditTrigger = "SecretChange"
	// TriggerPollFallback is a rotation converged by the polling path after
	// push notifications were unavailable.
	TriggerPollFallback AuditTrigger = "PollFallback"
	// TriggerManual is an operator-initiated attempt.
	TriggerManual AuditTrigger = "Manual"
	// TriggerRetry is a scheduled retry of a previous failure.
	TriggerRetry AuditTrigger = "Retry"
)

// AuditRecord is the immutable record of one rotation attempt. It is written
// to the status ConfigMap and to Kubernetes events. Private key material is
// never included: only the certificate fingerprint identifies the bundle.
type AuditRecord struct {
	Time             time.Time
	Trigger          AuditTrigger
	Namespace        string
	SecretName       string
	Fingerprint      string
	PreviousPrint    string
	Selector         string
	Targets          []Target
	Results          []ReloadResult
	TotalDuration    time.Duration
	NotificationOK   bool
	WindowOverridden bool
}

// FailedTargets returns targets whose reload did not succeed. Notification-
// only outcomes are not failures.
func (r AuditRecord) FailedTargets() []ReloadResult {
	var failed []ReloadResult
	for _, result := range r.Results {
		if result.Outcome == OutcomeFailed || result.Outcome == OutcomeNotReady {
			failed = append(failed, result)
		}
	}
	return failed
}

// AuditSink persists audit records. Implementations must not mutate the
// record and must keep append-only history.
type AuditSink interface {
	Write(ctx context.Context, record AuditRecord) error
}

// EventRecorder mirrors record.EventRecorder without importing client-go, so
// the manager stays transport-agnostic.
type EventRecorder interface {
	Event(object any, eventtype, reason, message string)
}

// Audit reasons used on Kubernetes events.
const (
	ReasonRotationStarted   = "RotationStarted"
	ReasonRotationSucceeded = "RotationSucceeded"
	ReasonRotationFailed    = "RotationFailed"
	ReasonRotationBlocked   = "RotationBlocked"
	ReasonWindowOverride    = "RotationWindowOverridden"
	ReasonPollFallback      = "RotationPollFallback"
	ReasonExpiryWarning     = "RotationExpiryWarning"
)
