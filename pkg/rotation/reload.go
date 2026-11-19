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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Target is one workload instance consuming the rotated Secret. Every pod
// matched by the target selector is a distinct Target so that fan-out can be
// verified per instance and the least-frequently-restarted pod cannot be
// silently skipped.
type Target struct {
	UID       string
	Namespace string
	Name      string
	// PodIP is used by transports that reach the pod over the network.
	PodIP string
}

func (t Target) String() string {
	return t.Namespace + "/" + t.Name
}

// Outcome classifies a reload attempt.
type Outcome string

const (
	// OutcomeSuccess means the target now serves the new fingerprint.
	OutcomeSuccess Outcome = "Success"
	// OutcomeSkipped means the target was already serving the new bundle.
	OutcomeSkipped Outcome = "Skipped"
	// OutcomeNotReady means a precondition failed and the attempt was withheld.
	OutcomeNotReady Outcome = "NotReady"
	// OutcomeFailed means the target could not be reloaded; retries follow.
	OutcomeFailed Outcome = "Failed"
	// OutcomeNotificationOnly means no automatic reload was configured; the
	// notification itself is the deliverable.
	OutcomeNotificationOnly Outcome = "NotificationOnly"
)

// ReloadResult is the per-target result of one attempt.
type ReloadResult struct {
	Target      Target
	Outcome     Outcome
	Fingerprint string
	Err         error
	AttemptedAt time.Time
	// Duration is the wall-clock time spent talking to the target.
	Duration time.Duration
}

// Reloader performs the reload of one target. Implementations must not restart
// the workload process or close its listener: the whole point of the feature
// is to swap served certificates while established connections keep running.
type Reloader interface {
	Reload(ctx context.Context, target Target, bundle Bundle) ReloadResult
}

// CertStore is a graceful, in-process certificate store. Wire it into a
// tls.Config via GetCertificate: the TLS stack calls it for every new
// handshake, so Swap takes effect for new connections immediately while
// already-negotiated connections keep their state and run to completion. No
// listener restart is involved, hence zero interrupted connections.
type CertStore struct {
	current     atomic.Pointer[tls.Certificate]
	fingerprint atomic.Pointer[string]
}

// NewCertStore validates the initial bundle and stores it.
func NewCertStore(initial Bundle) (*CertStore, error) {
	if err := ValidateBundle(initial); err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(initial.Certificate, initial.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load initial key pair: %w", err)
	}
	store := &CertStore{}
	fingerprint := initial.Fingerprint()
	store.current.Store(&certificate)
	store.fingerprint.Store(&fingerprint)
	return store, nil
}

// Swap atomically replaces the served bundle. On error the previous bundle
// stays in place: a failed swap is never observable by clients.
func (s *CertStore) Swap(next Bundle) error {
	if err := ValidateBundle(next); err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair(next.Certificate, next.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load replacement key pair: %w", err)
	}
	fingerprint := next.Fingerprint()
	s.current.Store(&certificate)
	s.fingerprint.Store(&fingerprint)
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *CertStore) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := s.current.Load()
	if certificate == nil {
		return nil, fmt.Errorf("certificate store is empty")
	}
	return certificate, nil
}

// Fingerprint returns the fingerprint of the currently served certificate.
func (s *CertStore) Fingerprint() string {
	fingerprint := s.fingerprint.Load()
	if fingerprint == nil {
		return ""
	}
	return *fingerprint
}

// SignalSender delivers a signal to a target process. The Kubernetes
// implementation uses the pods/exec subresource; tests provide a fake.
type SignalSender interface {
	SendSignal(ctx context.Context, target Target, signal string) error
}

// SignalReloader asks the workload to reload by POSIX signal.
type SignalReloader struct {
	Sender SignalSender
	Signal string
	Now    func() time.Time
}

func (r SignalReloader) Reload(ctx context.Context, target Target, bundle Bundle) ReloadResult {
	started := r.now()
	err := r.Sender.SendSignal(ctx, target, r.Signal)
	return ReloadResult{
		Target:      target,
		Outcome:     outcomeOrFailed(err),
		Fingerprint: bundle.Fingerprint(),
		Err:         err,
		AttemptedAt: started,
		Duration:    r.now().Sub(started),
	}
}

func (r SignalReloader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// HTTPDoer is the subset of *http.Client used by HTTPReloader.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPReloader calls a loopback hot-reload endpoint on the target.
type HTTPReloader struct {
	Doer HTTPDoer
	URL  string
	Now  func() time.Time
}

func (r HTTPReloader) Reload(ctx context.Context, target Target, bundle Bundle) ReloadResult {
	started := r.now()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(nil))
	if err != nil {
		return r.result(target, bundle, started, err)
	}
	response, err := r.Doer.Do(request)
	if err == nil {
		defer response.Body.Close()
		defer io.Copy(io.Discard, response.Body)
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			err = fmt.Errorf("reload endpoint returned status %d", response.StatusCode)
		}
	}
	return r.result(target, bundle, started, err)
}

func (r HTTPReloader) result(target Target, bundle Bundle, started time.Time, err error) ReloadResult {
	return ReloadResult{
		Target:      target,
		Outcome:     outcomeOrFailed(err),
		Fingerprint: bundle.Fingerprint(),
		Err:         err,
		AttemptedAt: started,
		Duration:    r.now().Sub(started),
	}
}

func (r HTTPReloader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// CommandRunner executes a reload command inside the target pod. The
// Kubernetes implementation uses the pods/exec subresource; tests provide a
// fake.
type CommandRunner interface {
	Run(ctx context.Context, target Target, command string) error
}

// ExecReloader runs a user-specified reload command inside the target pod.
type ExecReloader struct {
	Runner  CommandRunner
	Command string
	Now     func() time.Time
}

func (r ExecReloader) Reload(ctx context.Context, target Target, bundle Bundle) ReloadResult {
	started := r.now()
	err := r.Runner.Run(ctx, target, r.Command)
	return ReloadResult{
		Target:      target,
		Outcome:     outcomeOrFailed(err),
		Fingerprint: bundle.Fingerprint(),
		Err:         err,
		AttemptedAt: started,
		Duration:    r.now().Sub(started),
	}
}

func (r ExecReloader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// NoopReloader implements reload-method=none: the notification is delivered
// and recorded but no automatic action is taken against the workload.
type NoopReloader struct {
	Now func() time.Time
}

func (r NoopReloader) Reload(_ context.Context, target Target, bundle Bundle) ReloadResult {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	started := now()
	return ReloadResult{
		Target:      target,
		Outcome:     OutcomeNotificationOnly,
		Fingerprint: bundle.Fingerprint(),
		AttemptedAt: started,
	}
}

func outcomeOrFailed(err error) Outcome {
	if err != nil {
		return OutcomeFailed
	}
	return OutcomeSuccess
}
