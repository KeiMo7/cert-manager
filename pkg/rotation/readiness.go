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
)

// TargetState is the persisted state of one target's last reload attempt.
type TargetState struct {
	Fingerprint string
	Outcome     Outcome
	Err         string
	AttemptedAt time.Time
}

// TargetDiscovery resolves the selector to concrete workload instances.
type TargetDiscovery interface {
	Discover(ctx context.Context, namespace, selector string) ([]Target, error)
}

// ReadinessIssue explains why a target must not be reloaded yet.
type ReadinessIssue struct {
	Target Target
	Reason string
}

// CheckReadiness enforces the pre-rotation gates so that a rotation is never
// turned into an outage:

//   - the feature is opted in and its configuration is valid;
//   - the selector resolves to at least one target;
//   - the reload method is configured with the prerequisite it needs;
//   - the target's previous attempt is not still failing (a repeated failure
//     is retried by the manager, but readiness records the block and raises an
//     event instead of blindly hammering a broken target).
func CheckReadiness(cfg Config, targets []Target, states map[string]TargetState) ([]ReadinessIssue, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("rotation is not enabled for this Secret")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("rotation configuration is invalid: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target selector %q matched no workloads", cfg.TargetSelector)
	}

	var issues []ReadinessIssue
	for _, target := range targets {
		if state, ok := states[target.UID]; ok && state.Outcome == OutcomeFailed {
			issues = append(issues, ReadinessIssue{
				Target: target,
				Reason: fmt.Sprintf("previous reload at %s failed: %s", state.AttemptedAt.Format(time.RFC3339), state.Err),
			})
		}
	}
	return issues, nil
}

// ShouldReloadNow applies the reload-window policy. Outside an allowed window
// the reload is postponed, unless the served certificate is already inside its
// expiry warning period: an imminent-expiry override always proceeds and the
// caller is expected to record an event naming the override.
func ShouldReloadNow(cfg Config, served Bundle, now time.Time) (reload bool, nextOpen time.Time, override bool, err error) {
	atRisk, _, err := served.ExpiryRisk(now, cfg.ExpiryWarningPeriod)
	if err != nil {
		return false, time.Time{}, false, err
	}
	if cfg.Window == nil || cfg.Window.Contains(now) {
		return true, time.Time{}, false, nil
	}
	if atRisk {
		return true, time.Time{}, true, nil
	}
	return false, cfg.Window.NextOpen(now), false, nil
}
