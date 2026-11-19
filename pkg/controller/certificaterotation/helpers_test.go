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
	"context"
	"encoding/pem"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

func pemEncodeBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func testPods(n int) []corev1.Pod {
	pods := make([]corev1.Pod, n)
	for i := range n {
		pods[i] = corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "payments-" + string(rune('0'+i)),
				Namespace: "shop",
				UID:       types.UID(string(rune('a' + i))),
				Labels:    map[string]string{"app": "payments"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0." + string(rune('1'+i))},
		}
	}
	return pods
}

type fakeExec struct {
	reloaded chan rotation.Target
}

func (e *fakeExec) Exec(_ context.Context, namespace, pod, _ string, _ []string) error {
	e.reloaded <- rotation.Target{Namespace: namespace, Name: pod}
	return nil
}

type staticPoller struct{}

func (staticPoller) Converge(_ context.Context, _ rotation.SecretRef, targets []rotation.Target, bundle rotation.Bundle) []rotation.ReloadResult {
	results := make([]rotation.ReloadResult, 0, len(targets))
	for _, target := range targets {
		results = append(results, rotation.ReloadResult{Target: target, Outcome: rotation.OutcomeSuccess, Fingerprint: bundle.Fingerprint(), AttemptedAt: time.Now()})
	}
	return results
}

type alwaysHealthy struct{}

func (alwaysHealthy) PushHealthy() bool { return true }

type noopMetrics struct{}

func (noopMetrics) ObserveRotation(rotation.SecretRef, time.Duration, map[rotation.Outcome]int) {}
func (noopMetrics) SetExpiryRisk(rotation.SecretRef, bool, time.Duration)                       {}
func (noopMetrics) ObservePollFallback(rotation.SecretRef)                                      {}

type noopEvents struct{}

func (noopEvents) Event(any, string, string, string) {}

type noopRecorder struct{}

func (noopRecorder) Event(_ runtime.Object, _, _, _ string)            {}
func (noopRecorder) Eventf(_ runtime.Object, _, _, _ string, _ ...any) {}
func (noopRecorder) AnnotatedEventf(_ runtime.Object, _ map[string]string, _, _, _ string, _ ...any) {
}

func notifyAll(t *testing.T, ch chan rotation.Target, want int) {
	t.Helper()
	seen := map[string]bool{}
	deadline := time.Now().Add(3 * time.Second)
	for len(seen) < want && time.Now().Before(deadline) {
		select {
		case target := <-ch:
			seen[target.Namespace+"/"+target.Name] = true
		case <-time.After(time.Second):
		}
	}
	if len(seen) != want {
		t.Fatalf("notified %d unique targets, want %d: %v", len(seen), want, seen)
	}
}

func waitForSecret(t *testing.T, controller *Controller, namespace, name string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := controller.secretLister.Secrets(namespace).Get(name); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("secret %s/%s never appeared in lister", namespace, name)
}
