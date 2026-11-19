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
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		certPath      = flag.String("cert-path", "/certs/tls.crt", "Path to the mounted certificate file.")
		keyPath       = flag.String("key-path", "/certs/tls.key", "Path to the mounted private key file.")
		pollInterval  = flag.Duration("poll-interval", time.Minute, "Polling interval for file changes.")
		settledFor    = flag.Duration("settled-for", 5*time.Second, "Age a changed file must reach before reload.")
		mode          = flag.String("mode", string(ReloadModeNotify), "Reload mode: store, signal, exec or notify.")
		signalName    = flag.String("reload-signal", "SIGHUP", "Signal to send in signal mode.")
		pid           = flag.Int("pid", 0, "Target PID for signal mode.")
		command       = flag.String("reload-command", "", "Shell command for exec mode.")
		warningPeriod = flag.Duration("expiry-warning-period", 7*24*time.Hour, "Alert when expiry is closer than this duration.")
		listenAddr    = flag.String("listen-address", ":9490", "HTTP address for /metrics and /healthz.")
	)
	flag.Parse()

	reloadSignal := syscall.SIGHUP
	switch *signalName {
	case "SIGHUP":
		reloadSignal = syscall.SIGHUP
	case "SIGUSR1":
		reloadSignal = syscall.SIGUSR1
	case "SIGUSR2":
		reloadSignal = syscall.SIGUSR2
	default:
		log.Fatalf("unsupported reload signal %q", *signalName)
	}

	agent, err := NewAgent(AgentConfig{
		CertPath:      *certPath,
		KeyPath:       *keyPath,
		PollInterval:  *pollInterval,
		SettledFor:    *settledFor,
		Mode:          ReloadMode(*mode),
		Signal:        reloadSignal,
		ReloadCommand: *command,
		NotifyPID:     *pid,
		WarningPeriod: *warningPeriod,
	})
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", agent.MetricsHandler())
	mux.Handle("/healthz", agent.HealthHandler())
	server := &http.Server{Addr: *listenAddr, Handler: mux}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("rotation-agent listening on %s, watching %s", *listenAddr, *certPath)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("metrics server failed: %v", err)
		}
	}()

	if err := agent.Run(ctx); err != nil {
		log.Fatalf("rotation-agent failed: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	os.Exit(0)
}
