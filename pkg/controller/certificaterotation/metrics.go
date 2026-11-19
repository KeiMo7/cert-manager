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

package certificaterotation

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

// prometheusMetrics adapts pkg/rotation telemetry to Prometheus.
type prometheusMetrics struct {
	rotationTotal     *prometheus.CounterVec
	rotationLatency   *prometheus.HistogramVec
	pollFallbackTotal prometheus.Counter
	expiryRisk        *prometheus.GaugeVec
}

func newPrometheusMetrics(registerer prometheus.Registerer) *prometheusMetrics {
	metrics := &prometheusMetrics{
		rotationTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "certmanager",
			Subsystem: "rotation",
			Name:      "attempts_total",
			Help:      "Number of certificate rotation reload attempts, labelled by per-target outcome.",
		}, []string{"namespace", "secret", "outcome"}),
		rotationLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "certmanager",
			Subsystem: "rotation",
			Name:      "duration_seconds",
			Help:      "End-to-end duration of a rotation from Secret update to fan-out completion.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"namespace", "secret"}),
		pollFallbackTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "certmanager",
			Subsystem: "rotation",
			Name:      "poll_fallback_total",
			Help:      "Number of rotations converged through file polling because push was unavailable.",
		}),
		expiryRisk: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "certmanager",
			Subsystem: "rotation",
			Name:      "expiry_risk",
			Help:      "1 when a rotated Secret's certificate is inside its expiry warning period.",
		}, []string{"namespace", "secret"}),
	}
	registerer.MustRegister(
		metrics.rotationTotal,
		metrics.rotationLatency,
		metrics.pollFallbackTotal,
		metrics.expiryRisk,
	)
	return metrics
}

func (m *prometheusMetrics) ObserveRotation(ref rotation.SecretRef, duration time.Duration, outcomes map[rotation.Outcome]int) {
	for outcome, count := range outcomes {
		m.rotationTotal.WithLabelValues(ref.Namespace, ref.Name, string(outcome)).Add(float64(count))
	}
	m.rotationLatency.WithLabelValues(ref.Namespace, ref.Name).Observe(duration.Seconds())
}

func (m *prometheusMetrics) SetExpiryRisk(ref rotation.SecretRef, atRisk bool, remaining time.Duration) {
	value := 0.0
	if atRisk {
		value = 1
	}
	m.expiryRisk.WithLabelValues(ref.Namespace, ref.Name).Set(value)
}

func (m *prometheusMetrics) ObservePollFallback(rotation.SecretRef) {
	m.pollFallbackTotal.Inc()
}
