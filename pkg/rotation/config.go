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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Annotation keys used to declare rotation behaviour on a certificate Secret.
// They may be supplied directly or via Certificate.spec.secretTemplate.
const (
	AnnotationEnabled              = "rotation.cert-manager.io/enabled"
	AnnotationTargetSelector       = "rotation.cert-manager.io/target-selector"
	AnnotationReloadMethod         = "rotation.cert-manager.io/reload-method"
	AnnotationReloadSignal         = "rotation.cert-manager.io/reload-signal"
	AnnotationReloadURL            = "rotation.cert-manager.io/reload-url"
	AnnotationReloadCommand        = "rotation.cert-manager.io/reload-command"
	AnnotationReloadWindow         = "rotation.cert-manager.io/reload-window"
	AnnotationPollFallbackInterval = "rotation.cert-manager.io/poll-fallback-interval"
	AnnotationExpiryWarningPeriod  = "rotation.cert-manager.io/expiry-warning-period"
)

const (
	// DefaultExpiryWarningPeriod is how long before certificate expiry a
	// failed rotation escalates to a warning. One week leaves time for a
	// human to intervene.
	DefaultExpiryWarningPeriod = 7 * 24 * time.Hour

	// DefaultPollFallbackInterval is the polling hint used when the push
	// channel is unavailable and no explicit interval was configured.
	DefaultPollFallbackInterval = time.Minute

	// MaxPollFallbackInterval bounds a misconfigured polling interval so the
	// degraded path still converges inside a reasonable time.
	MaxPollFallbackInterval = time.Hour
)

// ReloadMethod describes how a workload is asked to reload its certificate.
type ReloadMethod string

const (
	// ReloadMethodSignal sends a POSIX signal to the workload process.
	ReloadMethodSignal ReloadMethod = "signal"
	// ReloadMethodHTTP POSTs to a loopback hot-reload endpoint.
	ReloadMethodHTTP ReloadMethod = "http"
	// ReloadMethodExec runs a command inside the target pod.
	ReloadMethodExec ReloadMethod = "exec"
	// ReloadMethodNone delivers the notification only and lets the operator
	// or the workload itself act on it.
	ReloadMethodNone ReloadMethod = "none"
)

// Config is the parsed rotation configuration for one certificate Secret.
type Config struct {
	// Enabled is false unless the Secret explicitly opts in. Default
	// deployments therefore keep the historical rotation behaviour.
	Enabled bool
	// TargetSelector is a Kubernetes label selector expression identifying
	// every workload consuming the Secret.
	TargetSelector string
	// Method selects the reload transport.
	Method ReloadMethod
	// Signal is the signal name for Method=signal, e.g. "SIGHUP".
	Signal string
	// ReloadURL is the loopback endpoint for Method=http.
	ReloadURL string
	// Command is the shell command for Method=exec.
	Command string
	// Window optionally restricts proactive reloads to cron-style windows.
	Window *Window
	// PollFallbackInterval is the hint for the degraded polling path.
	PollFallbackInterval time.Duration
	// ExpiryWarningPeriod is how long before expiry a failure must warn.
	ExpiryWarningPeriod time.Duration
}

// ParseConfig reads rotation configuration from a Secret's annotations.
// Absence of the opt-in annotation is valid and returns Config{Enabled:
// false}: the feature is additive and off by default.
func ParseConfig(annotations map[string]string) (Config, error) {
	cfg := Config{
		Enabled:              false,
		PollFallbackInterval: DefaultPollFallbackInterval,
		ExpiryWarningPeriod:  DefaultExpiryWarningPeriod,
	}

	if len(annotations) == 0 {
		return cfg, nil
	}

	if v, ok := annotations[AnnotationEnabled]; ok {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("annotation %s must be a boolean, got %q", AnnotationEnabled, v)
		}
		cfg.Enabled = enabled
	}

	if !cfg.Enabled {
		return cfg, nil
	}

	cfg.TargetSelector = strings.TrimSpace(annotations[AnnotationTargetSelector])

	switch method := ReloadMethod(annotations[AnnotationReloadMethod]); method {
	case ReloadMethodSignal, ReloadMethodHTTP, ReloadMethodExec, ReloadMethodNone:
		cfg.Method = method
	case "":
		return cfg, fmt.Errorf("annotation %s is required when rotation is enabled", AnnotationReloadMethod)
	default:
		return cfg, fmt.Errorf("annotation %s has unsupported reload method %q", AnnotationReloadMethod, method)
	}

	cfg.Signal = strings.TrimSpace(annotations[AnnotationReloadSignal])
	cfg.ReloadURL = strings.TrimSpace(annotations[AnnotationReloadURL])
	cfg.Command = strings.TrimSpace(annotations[AnnotationReloadCommand])

	if raw := annotations[AnnotationReloadWindow]; raw != "" {
		window, err := ParseWindow(raw)
		if err != nil {
			return cfg, fmt.Errorf("annotation %s is invalid: %w", AnnotationReloadWindow, err)
		}
		cfg.Window = window
	}

	if raw := annotations[AnnotationPollFallbackInterval]; raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return cfg, fmt.Errorf("annotation %s is invalid: %w", AnnotationPollFallbackInterval, err)
		}
		if interval <= 0 {
			return cfg, fmt.Errorf("annotation %s must be positive", AnnotationPollFallbackInterval)
		}
		if interval > MaxPollFallbackInterval {
			interval = MaxPollFallbackInterval
		}
		cfg.PollFallbackInterval = interval
	}

	if raw := annotations[AnnotationExpiryWarningPeriod]; raw != "" {
		period, err := time.ParseDuration(raw)
		if err != nil {
			return cfg, fmt.Errorf("annotation %s is invalid: %w", AnnotationExpiryWarningPeriod, err)
		}
		if period <= 0 {
			return cfg, fmt.Errorf("annotation %s must be positive", AnnotationExpiryWarningPeriod)
		}
		cfg.ExpiryWarningPeriod = period
	}

	return cfg, cfg.Validate()
}

// Validate checks method-specific prerequisites that ParseConfig cannot
// verify without knowing the method semantics.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if c.TargetSelector == "" {
		errs = append(errs, fmt.Errorf("annotation %s is required when rotation is enabled", AnnotationTargetSelector))
	}
	switch c.Method {
	case ReloadMethodSignal:
		if c.Signal == "" {
			errs = append(errs, fmt.Errorf("annotation %s is required for reload method %q", AnnotationReloadSignal, c.Method))
		}
	case ReloadMethodHTTP:
		if c.ReloadURL == "" {
			errs = append(errs, fmt.Errorf("annotation %s is required for reload method %q", AnnotationReloadURL, c.Method))
		} else if _, err := url.Parse(c.ReloadURL); err != nil {
			errs = append(errs, fmt.Errorf("annotation %s is not a valid URL: %w", AnnotationReloadURL, err))
		}
	case ReloadMethodExec:
		if c.Command == "" {
			errs = append(errs, fmt.Errorf("annotation %s is required for reload method %q", AnnotationReloadCommand, c.Method))
		}
	case ReloadMethodNone:
		// Notification only: nothing else to validate.
	}
	return errors.Join(errs...)
}
