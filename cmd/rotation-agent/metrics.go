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
	"fmt"
	"net/http"
	"time"
)

// MetricsHandler renders the agent's telemetry in the Prometheus text
// exposition format without pulling in a metrics client dependency.
func (a *Agent) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP certmanager_rotation_agent_reloads_total Total successful certificate reloads.\n")
		fmt.Fprintf(w, "# TYPE certmanager_rotation_agent_reloads_total counter\n")
		fmt.Fprintf(w, "certmanager_rotation_agent_reloads_total %d\n", a.stats.reloads.Load())
		fmt.Fprintf(w, "# HELP certmanager_rotation_agent_failures_total Total reload attempts that failed and kept the old bundle.\n")
		fmt.Fprintf(w, "# TYPE certmanager_rotation_agent_failures_total counter\n")
		fmt.Fprintf(w, "certmanager_rotation_agent_failures_total %d\n", a.stats.failures.Load())
		fmt.Fprintf(w, "# HELP certmanager_rotation_agent_last_success_timestamp_seconds Timestamp of the last successful reload.\n")
		fmt.Fprintf(w, "# TYPE certmanager_rotation_agent_last_success_timestamp_seconds gauge\n")
		fmt.Fprintf(w, "certmanager_rotation_agent_last_success_timestamp_seconds %d\n", a.stats.lastSuccess.Load())
		fmt.Fprintf(w, "# HELP certmanager_rotation_agent_certificate_expiry_risk 1 when the served certificate is inside the warning period.\n")
		fmt.Fprintf(w, "# TYPE certmanager_rotation_agent_certificate_expiry_risk gauge\n")
		fmt.Fprintf(w, "certmanager_rotation_agent_certificate_expiry_risk %d\n", boolGauge(a.stats.atRisk.Load()))
		fmt.Fprintf(w, "# HELP certmanager_rotation_agent_certificate_remaining_seconds Seconds until the served certificate expires.\n")
		fmt.Fprintf(w, "# TYPE certmanager_rotation_agent_certificate_remaining_seconds gauge\n")
		fmt.Fprintf(w, "certmanager_rotation_agent_certificate_remaining_seconds %d\n", a.stats.remaining.Load()/int64(time.Second))
	})
}

// HealthHandler reports unhealthy while the served certificate is inside the
// expiry warning period so orchestration can alert early.
func (a *Agent) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if a.stats.atRisk.Load() {
			http.Error(w, "certificate inside expiry warning period", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func boolGauge(value bool) int {
	if value {
		return 1
	}
	return 0
}
