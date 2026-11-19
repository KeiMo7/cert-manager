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
	"testing"
	"time"
)

func validEnabledConfig() Config {
	return Config{
		Enabled:              true,
		TargetSelector:       "app=payments",
		Method:               ReloadMethodSignal,
		Signal:               "SIGHUP",
		PollFallbackInterval: time.Minute,
		ExpiryWarningPeriod:  7 * 24 * time.Hour,
	}
}

func TestCheckReadiness(t *testing.T) {
	targets := testTargets(3)

	if _, err := CheckReadiness(Config{}, targets, nil); err == nil {
		t.Fatalf("disabled config must not be ready")
	}

	cfg := validEnabledConfig()
	if _, err := CheckReadiness(cfg, nil, nil); err == nil {
		t.Fatalf("empty target set must not be ready")
	}

	issues, err := CheckReadiness(cfg, targets, nil)
	if err != nil || len(issues) != 0 {
		t.Fatalf("healthy fleet must be ready, got issues=%v err=%v", issues, err)
	}

	states := map[string]TargetState{
		targets[1].UID: {
			Outcome:     OutcomeFailed,
			Err:         "connection refused",
			AttemptedAt: time.Now(),
		},
	}
	issues, err = CheckReadiness(cfg, targets, states)
	if err != nil {
		t.Fatalf("per-target failures must not be global errors: %v", err)
	}
	if len(issues) != 1 || issues[0].Target.UID != targets[1].UID {
		t.Fatalf("expected exactly the failing target to be blocked, got %+v", issues)
	}

	invalid := cfg
	invalid.Signal = ""
	if _, err := CheckReadiness(invalid, targets, nil); err == nil {
		t.Fatalf("invalid configuration must not be ready")
	}
}

func TestRetryBackoffBounded(t *testing.T) {
	values := []time.Duration{
		RetryBackoff(1),
		RetryBackoff(2),
		RetryBackoff(3),
		RetryBackoff(100),
	}
	if values[0] != 30*time.Second || values[1] != time.Minute || values[2] != 2*time.Minute {
		t.Fatalf("unexpected backoff sequence: %v", values)
	}
	if values[3] > 10*time.Minute {
		t.Fatalf("backoff must be capped, got %s", values[3])
	}
	if !sortedDurations(values) {
		t.Fatalf("backoff must be monotonic: %v", values)
	}
}

func sortedDurations(values []time.Duration) bool {
	for i := 1; i < len(values); i++ {
		if values[i] < values[i-1] {
			return false
		}
	}
	return true
}
