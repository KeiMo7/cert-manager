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

func TestParseConfigDisabledByDefault(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enabled {
		t.Fatalf("rotation must be opt-in")
	}

	cfg, err = ParseConfig(map[string]string{AnnotationEnabled: "false"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enabled {
		t.Fatalf("explicit false must keep rotation disabled")
	}
}

func TestParseConfigMethods(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantErr     bool
		method      ReloadMethod
	}{
		{
			name: "signal",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "signal",
				AnnotationReloadSignal:   "SIGHUP",
			},
			method: ReloadMethodSignal,
		},
		{
			name: "http",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "http",
				AnnotationReloadURL:      "http://127.0.0.1:9090/-/reload",
			},
			method: ReloadMethodHTTP,
		},
		{
			name: "exec",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "exec",
				AnnotationReloadCommand:  "nginx -s reload",
			},
			method: ReloadMethodExec,
		},
		{
			name: "notification only",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "none",
			},
			method: ReloadMethodNone,
		},
		{
			name: "missing method",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
			},
			wantErr: true,
		},
		{
			name: "signal without signal name",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "signal",
			},
			wantErr: true,
		},
		{
			name: "exec without command",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "exec",
			},
			wantErr: true,
		},
		{
			name: "unsupported method",
			annotations: map[string]string{
				AnnotationEnabled:        "true",
				AnnotationTargetSelector: "app=payments",
				AnnotationReloadMethod:   "magic",
			},
			wantErr: true,
		},
		{
			name: "missing selector",
			annotations: map[string]string{
				AnnotationEnabled:      "true",
				AnnotationReloadMethod: "none",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.annotations)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got cfg %+v", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Method != tt.method {
				t.Fatalf("method = %q, want %q", cfg.Method, tt.method)
			}
		})
	}
}

func TestParseConfigIntervalsAndWarning(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{
		AnnotationEnabled:              "true",
		AnnotationTargetSelector:       "app=payments",
		AnnotationReloadMethod:         "none",
		AnnotationPollFallbackInterval: "45s",
		AnnotationExpiryWarningPeriod:  "720h",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PollFallbackInterval != 45*time.Second {
		t.Fatalf("poll interval = %s", cfg.PollFallbackInterval)
	}
	if cfg.ExpiryWarningPeriod != 720*time.Hour {
		t.Fatalf("warning period = %s", cfg.ExpiryWarningPeriod)
	}

	// Out-of-range interval is capped, not rejected.
	cfg, err = ParseConfig(map[string]string{
		AnnotationEnabled:              "true",
		AnnotationTargetSelector:       "app=payments",
		AnnotationReloadMethod:         "none",
		AnnotationPollFallbackInterval: "6h",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PollFallbackInterval != MaxPollFallbackInterval {
		t.Fatalf("poll interval = %s, want cap %s", cfg.PollFallbackInterval, MaxPollFallbackInterval)
	}

	if _, err := ParseConfig(map[string]string{
		AnnotationEnabled:              "true",
		AnnotationTargetSelector:       "app=payments",
		AnnotationReloadMethod:         "none",
		AnnotationPollFallbackInterval: "soon",
	}); err == nil {
		t.Fatalf("expected error for invalid duration")
	}
}
