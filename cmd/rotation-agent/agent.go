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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
)

// ReloadMode selects what the agent does after detecting a changed bundle.
type ReloadMode string

const (
	// ReloadModeStore swaps the in-process CertStore (for processes embedding
	// the agent as a library or serving TLS directly).
	ReloadModeStore ReloadMode = "store"
	// ReloadModeSignal sends a signal to a configured process.
	ReloadModeSignal ReloadMode = "signal"
	// ReloadModeExec runs an external reload command.
	ReloadModeExec ReloadMode = "exec"
	// ReloadModeNotify only records the change; another actor reloads.
	ReloadModeNotify ReloadMode = "notify"
)

// AgentConfig configures the polling agent.
type AgentConfig struct {
	CertPath      string
	KeyPath       string
	PollInterval  time.Duration
	SettledFor    time.Duration
	Mode          ReloadMode
	Signal        syscall.Signal
	ReloadCommand string
	NotifyPID     int
	WarningPeriod time.Duration
	Now           func() time.Time
	Swap          func(certPEM, keyPEM []byte) error
	CommandRunner func(ctx context.Context, name string, args ...string) error
	SignalSender  func(pid int, sig syscall.Signal) error
}

// AgentStats is the observable state of the agent, exposed on /metrics and
// the health endpoint.
type AgentStats struct {
	reloads     atomic.Int64
	failures    atomic.Int64
	lastSuccess atomic.Int64
	servedSHA   atomic.Value
	atRisk      atomic.Bool
	remaining   atomic.Int64
}

// Agent polls the mounted files and converges the served bundle.
type Agent struct {
	cfg   AgentConfig
	stats AgentStats
}

// NewAgent validates configuration and returns a ready agent.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, fmt.Errorf("certificate and key paths are required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Minute
	}
	if cfg.SettledFor <= 0 {
		cfg.SettledFor = 5 * time.Second
	}
	if cfg.WarningPeriod <= 0 {
		cfg.WarningPeriod = 7 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CommandRunner == nil {
		cfg.CommandRunner = func(ctx context.Context, name string, args ...string) error {
			return exec.CommandContext(ctx, name, args...).Run()
		}
	}
	if cfg.SignalSender == nil {
		cfg.SignalSender = func(pid int, sig syscall.Signal) error {
			process, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			return process.Signal(sig)
		}
	}
	switch cfg.Mode {
	case ReloadModeStore, ReloadModeSignal, ReloadModeExec, ReloadModeNotify:
	default:
		return nil, fmt.Errorf("unsupported reload mode %q", cfg.Mode)
	}
	if cfg.Mode == ReloadModeSignal && cfg.NotifyPID == 0 {
		return nil, fmt.Errorf("signal mode requires a target PID")
	}
	if cfg.Mode == ReloadModeExec && cfg.ReloadCommand == "" {
		return nil, fmt.Errorf("exec mode requires a reload command")
	}
	return &Agent{cfg: cfg}, nil
}

// Run polls until the context is cancelled. The first successful load
// establishes the baseline; transient stat/read errors are counted and retried
// rather than crashing the workload.
func (a *Agent) Run(ctx context.Context) error {
	baseline, err := StatBundle(a.cfg.CertPath, a.cfg.KeyPath)
	if err != nil {
		return fmt.Errorf("initial certificate read failed: %w", err)
	}
	previous := baseline
	pending := baseline
	if err := a.loadAndReload(ctx, baseline); err != nil {
		return fmt.Errorf("initial reload failed: %w", err)
	}

	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			snapshot, err := StatBundle(a.cfg.CertPath, a.cfg.KeyPath)
			if err != nil {
				a.stats.failures.Add(1)
				log.Printf("rotation-agent: stat failed, keeping previous bundle: %v", err)
				continue
			}
			if !snapshot.Changed(previous) {
				a.refreshExpiryStatus()
				continue
			}
			// A new snapshot must be observed twice in a row (and be old
			// enough) before reload, so a Secret mid-rewrite can never be
			// served.
			if !snapshot.Settled(pending, a.cfg.SettledFor, a.cfg.Now()) {
				pending = snapshot
				continue
			}
			if err := a.loadAndReload(ctx, snapshot); err != nil {
				a.stats.failures.Add(1)
				log.Printf("rotation-agent: reload failed, keeping previous bundle: %v", err)
				continue
			}
			previous = snapshot
			pending = snapshot
		}
	}
}

// RunOnceForTest performs exactly one convergence cycle without polling. It
// exists for deterministic unit tests; production code uses Run.
func (a *Agent) RunOnceForTest() error {
	snapshot, err := StatBundle(a.cfg.CertPath, a.cfg.KeyPath)
	if err != nil {
		return err
	}
	return a.loadAndReload(context.Background(), snapshot)
}

func (a *Agent) loadAndReload(ctx context.Context, snapshot FileSnapshot) error {
	certPEM, err := os.ReadFile(a.cfg.CertPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(a.cfg.KeyPath)
	if err != nil {
		return err
	}

	// Validate before anyone can serve the bundle: cert/key must match and
	// the certificate must parse. A broken or half-covered update is rejected
	// and the previous in-memory bundle keeps serving.
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("rejecting bundle that failed key pair load: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parsing leaf certificate: %w", err)
	}
	remaining := leaf.NotAfter.Sub(a.cfg.Now())
	a.stats.atRisk.Store(remaining <= a.cfg.WarningPeriod)
	a.stats.remaining.Store(int64(remaining))

	switch a.cfg.Mode {
	case ReloadModeStore:
		if a.cfg.Swap == nil {
			return fmt.Errorf("store mode requires a Swap callback")
		}
		if err := a.cfg.Swap(certPEM, keyPEM); err != nil {
			return err
		}
	case ReloadModeSignal:
		if err := a.cfg.SignalSender(a.cfg.NotifyPID, a.cfg.Signal); err != nil {
			return err
		}
	case ReloadModeExec:
		if err := a.cfg.CommandRunner(ctx, "sh", "-c", a.cfg.ReloadCommand); err != nil {
			return err
		}
	case ReloadModeNotify:
		log.Printf("rotation-agent: certificate changed to %s; notification-only mode", snapshot.CertSHA)
	}

	a.stats.reloads.Add(1)
	a.stats.lastSuccess.Store(a.cfg.Now().Unix())
	a.stats.servedSHA.Store(snapshot.CertSHA)
	log.Printf("rotation-agent: reloaded certificate %s via %s", snapshot.CertSHA, a.cfg.Mode)
	return nil
}

func (a *Agent) refreshExpiryStatus() {
	certPEM, err := os.ReadFile(a.cfg.CertPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	remaining := leaf.NotAfter.Sub(a.cfg.Now())
	a.stats.atRisk.Store(remaining <= a.cfg.WarningPeriod)
	a.stats.remaining.Store(int64(remaining))
}
