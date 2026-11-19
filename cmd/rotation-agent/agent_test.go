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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"syscall"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T, serial int64, lifetime time.Duration) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(lifetime),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pemEncode("PRIVATE KEY", keyDER)
	return certPEM, keyPEM
}

func TestAgentReloadsChangedBundleAndRejectsBrokenOne(t *testing.T) {
	certV1, keyV1 := selfSignedPEM(t, 1, 24*time.Hour)
	certV2, keyV2 := selfSignedPEM(t, 2, 24*time.Hour)
	certPath, keyPath := writeTempBundle(t, certV1, keyV1)

	var swapped [][]byte
	agent, err := NewAgent(AgentConfig{
		CertPath:     certPath,
		KeyPath:      keyPath,
		PollInterval: 50 * time.Millisecond,
		SettledFor:   time.Millisecond,
		Mode:         ReloadModeStore,
		Swap: func(certPEM, keyPEM []byte) error {
			swapped = append(swapped, certPEM)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	waitUntil(t, func() bool { return len(swapped) == 1 })

	// Rotate with a valid, matching bundle.
	writeBundle(t, certPath, keyPath, certV2, keyV2)
	waitUntil(t, func() bool { return len(swapped) == 2 })
	if agent.stats.reloads.Load() != 2 {
		t.Fatalf("expected two successful reloads, got %d", agent.stats.reloads.Load())
	}

	// Half-covered update: new cert, old key. It must be rejected and the
	// previous bundle stays in place; failures are counted for alerting.
	writeBundle(t, certPath, keyPath, certV2, keyV1)
	waitUntil(t, func() bool { return agent.stats.failures.Load() >= 1 })
	if agent.stats.reloads.Load() != 2 {
		t.Fatalf("broken bundle must not count as a reload")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("agent run: %v", err)
	}
}

func TestAgentExecAndNotifyModes(t *testing.T) {
	cert, key := selfSignedPEM(t, 1, 24*time.Hour)
	certPath, keyPath := writeTempBundle(t, cert, key)

	var ranCommand string
	agent, err := NewAgent(AgentConfig{
		CertPath:      certPath,
		KeyPath:       keyPath,
		Mode:          ReloadModeExec,
		ReloadCommand: "nginx -s reload",
		CommandRunner: func(_ context.Context, name string, args ...string) error {
			ranCommand = args[len(args)-1]
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	if err := agent.RunOnceForTest(); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if ranCommand != "nginx -s reload" {
		t.Fatalf("command not executed, got %q", ranCommand)
	}

	// Notify mode never touches a process.
	notifyAgent, err := NewAgent(AgentConfig{CertPath: certPath, KeyPath: keyPath, Mode: ReloadModeNotify})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	if err := notifyAgent.RunOnceForTest(); err != nil {
		t.Fatalf("notify run: %v", err)
	}
}

func TestAgentExpiryRiskDrivesHealth(t *testing.T) {
	// Expires in one hour, warning period is one week: risk must be raised.
	cert, key := selfSignedPEM(t, 1, time.Hour)
	certPath, keyPath := writeTempBundle(t, cert, key)

	agent, err := NewAgent(AgentConfig{
		CertPath:      certPath,
		KeyPath:       keyPath,
		Mode:          ReloadModeNotify,
		WarningPeriod: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	if err := agent.RunOnceForTest(); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if !agent.stats.atRisk.Load() {
		t.Fatalf("near-expiry certificate must mark the agent at risk")
	}

	recorder := httptestNewRecorder()
	agent.HealthHandler().ServeHTTP(recorder, httptestNewRequest())
	if recorder.Code != 503 {
		t.Fatalf("healthz = %d, want 503", recorder.Code)
	}
}

func TestNewAgentValidatesModeConfig(t *testing.T) {
	cert, key := selfSignedPEM(t, 1, 24*time.Hour)
	certPath, keyPath := writeTempBundle(t, cert, key)

	if _, err := NewAgent(AgentConfig{CertPath: certPath, KeyPath: keyPath, Mode: ReloadModeSignal}); err == nil {
		t.Fatalf("signal mode without PID must be rejected")
	}
	if _, err := NewAgent(AgentConfig{CertPath: certPath, KeyPath: keyPath, Mode: ReloadModeExec}); err == nil {
		t.Fatalf("exec mode without command must be rejected")
	}
	if _, err := NewAgent(AgentConfig{CertPath: certPath, KeyPath: keyPath, Mode: ReloadMode("bogus")}); err == nil {
		t.Fatalf("unknown mode must be rejected")
	}
	_ = syscall.SIGHUP
}
