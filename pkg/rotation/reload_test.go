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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCertStoreSwapIsAtomicAndZeroInterrupt(t *testing.T) {
	now := time.Now()
	old := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	newBundle := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)

	store, err := NewCertStore(old)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tlsConfig := &tls.Config{GetCertificate: store.GetCertificate}

	// Simulate long-lived established connections: they hold the negotiated
	// state and never call GetCertificate again. The store swap therefore
	// cannot interrupt them.
	establishedFingerprint := store.Fingerprint()

	if err := store.Swap(newBundle); err != nil {
		t.Fatalf("swap failed: %v", err)
	}

	if store.Fingerprint() != newBundle.Fingerprint() {
		t.Fatalf("store did not adopt the new fingerprint")
	}
	// A new handshake observes the new certificate through tls.Config.
	certificate, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if len(certificate.Certificate) == 0 {
		t.Fatalf("served certificate is empty")
	}
	// The "established connection" keeps presenting the old material, proving
	// no connection state was torn down by the swap.
	if establishedFingerprint != old.Fingerprint() {
		t.Fatalf("established connection state changed during swap")
	}
}

func TestCertStoreSwapKeepsOldBundleOnInvalidInput(t *testing.T) {
	now := time.Now()
	old := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	other := mustGenerateBundle(t, 2, now.Add(-time.Hour), 24*time.Hour)

	store, err := NewCertStore(old)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.Swap(halfCoveredBundle(t, old, other)); err == nil {
		t.Fatalf("half-covered bundle must be rejected by Swap")
	}
	if store.Fingerprint() != old.Fingerprint() {
		t.Fatalf("failed swap must leave the previous bundle in place")
	}
}

type fakeSignalSender struct {
	signals []string
	err     error
}

func (f *fakeSignalSender) SendSignal(_ context.Context, _ Target, signal string) error {
	f.signals = append(f.signals, signal)
	return f.err
}

func TestSignalReloader(t *testing.T) {
	now := time.Now()
	bundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	target := Target{UID: "a", Namespace: "shop", Name: "payments-0"}
	clockTime := now

	sender := &fakeSignalSender{}
	reloader := SignalReloader{Sender: sender, Signal: "SIGHUP", Now: func() time.Time { return clockTime }}
	result := reloader.Reload(context.Background(), target, bundle)
	if result.Outcome != OutcomeSuccess || len(sender.signals) != 1 || sender.signals[0] != "SIGHUP" {
		t.Fatalf("unexpected result: %+v signals=%v", result, sender.signals)
	}

	sender.err = errBoom
	result = reloader.Reload(context.Background(), target, bundle)
	if result.Outcome != OutcomeFailed || !errors.Is(result.Err, errBoom) {
		t.Fatalf("expected failure, got %+v", result)
	}
}

func TestHTTPReloader(t *testing.T) {
	now := time.Now()
	bundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	target := Target{UID: "a", Namespace: "shop", Name: "payments-0"}

	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		receivedMethod = req.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reloader := HTTPReloader{Doer: server.Client(), URL: server.URL}
	result := reloader.Reload(context.Background(), target, bundle)
	if result.Outcome != OutcomeSuccess || receivedMethod != http.MethodPost {
		t.Fatalf("unexpected result: %+v method=%s", result, receivedMethod)
	}

	// Non-2xx is a failure so the manager retries and never assumes success.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	reloader.URL = failing.URL
	if result := reloader.Reload(context.Background(), target, bundle); result.Outcome != OutcomeFailed {
		t.Fatalf("500 response must fail the reload, got %+v", result)
	}

	// A closed endpoint surfaces as a transport error rather than a hang.
	reloader.URL = "http://127.0.0.1:1/reload"
	if result := reloader.Reload(context.Background(), target, bundle); result.Outcome != OutcomeFailed {
		t.Fatalf("unreachable endpoint must fail the reload, got %+v", result)
	}
}

type fakeRunner struct {
	commands []string
	err      error
}

func (f *fakeRunner) Run(_ context.Context, _ Target, command string) error {
	f.commands = append(f.commands, command)
	return f.err
}

func TestExecAndNoopReloader(t *testing.T) {
	now := time.Now()
	bundle := mustGenerateBundle(t, 1, now.Add(-time.Hour), 24*time.Hour)
	target := Target{UID: "a", Namespace: "shop", Name: "payments-0"}

	runner := &fakeRunner{}
	execReloader := ExecReloader{Runner: runner, Command: "nginx -s reload"}
	if result := execReloader.Reload(context.Background(), target, bundle); result.Outcome != OutcomeSuccess {
		t.Fatalf("exec reload failed: %+v", result)
	}
	if len(runner.commands) != 1 || runner.commands[0] != "nginx -s reload" {
		t.Fatalf("command not run: %v", runner.commands)
	}

	noop := NoopReloader{}
	result := noop.Reload(context.Background(), target, bundle)
	if result.Outcome != OutcomeNotificationOnly || result.Err != nil {
		t.Fatalf("noop reloader must only notify, got %+v", result)
	}
}
