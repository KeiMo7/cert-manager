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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

func TestConfigMapStateStoreRoundTrip(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	store := newConfigMapStateStore(client.CoreV1())
	ref := rotation.SecretRef{Namespace: "shop", Name: "payments-tls"}

	states, previous, err := store.Load(context.Background(), ref)
	if err != nil {
		t.Fatalf("load before create: %v", err)
	}
	if len(states) != 0 || previous != "" {
		t.Fatalf("expected empty initial state")
	}

	wantStates := map[string]rotation.TargetState{
		"a": {Fingerprint: "sha256:abc", Outcome: rotation.OutcomeSuccess, AttemptedAt: time.Now()},
		"b": {Fingerprint: "sha256:abc", Outcome: rotation.OutcomeFailed, Err: "boom", AttemptedAt: time.Now()},
	}
	if err := store.Save(context.Background(), ref, wantStates, "sha256:old"); err != nil {
		t.Fatalf("save: %v", err)
	}

	gotStates, gotPrevious, err := store.Load(context.Background(), ref)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if gotPrevious != "sha256:old" {
		t.Fatalf("previous fingerprint = %q", gotPrevious)
	}
	if gotStates["a"].Outcome != rotation.OutcomeSuccess || gotStates["b"].Err != "boom" {
		t.Fatalf("state round trip lost data: %+v", gotStates)
	}

	// A second Secret in the same namespace shares the ConfigMap without
	// clobbering the first one's keys.
	other := rotation.SecretRef{Namespace: "shop", Name: "checkout-tls"}
	if err := store.Save(context.Background(), other, map[string]rotation.TargetState{
		"c": {Fingerprint: "sha256:xyz", Outcome: rotation.OutcomeSuccess, AttemptedAt: time.Now()},
	}, "sha256:older"); err != nil {
		t.Fatalf("save second: %v", err)
	}
	if _, gotPrevious, err := store.Load(context.Background(), ref); err != nil || gotPrevious != "sha256:old" {
		t.Fatalf("first Secret state corrupted, previous=%q err=%v", gotPrevious, err)
	}
}

func TestConfigMapAuditWriteAndPrune(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	store := newConfigMapStateStore(client.CoreV1())

	for i := range maxAuditEntries + 5 {
		record := rotation.AuditRecord{
			Time:        time.Date(2026, 11, 20, 0, 0, i, 0, time.UTC),
			Namespace:   "shop",
			SecretName:  "payments-tls",
			Trigger:     rotation.TriggerSecretChange,
			Fingerprint: "sha256:new",
		}
		if err := store.Write(context.Background(), record); err != nil {
			t.Fatalf("write audit %d: %v", i, err)
		}
	}

	configMap, err := client.CoreV1().ConfigMaps("shop").Get(context.Background(), StatusConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	var auditKeys int
	for key := range configMap.Data {
		if len(key) >= 6 && key[:6] == "audit/" {
			auditKeys++
		}
	}
	if auditKeys != maxAuditEntries {
		t.Fatalf("audit entries = %d, want cap %d", auditKeys, maxAuditEntries)
	}
}

func TestPodDiscoveryFiltersTerminatedPods(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "shop", UID: types.UID("1")}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "done", Namespace: "shop", UID: types.UID("2")}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{ObjectMeta: metav1.ObjectMeta{Name: "dead", Namespace: "shop", UID: types.UID("3")}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
	}
	discovery := podDiscovery{lister: staticPodLister{pods: pods}}
	targets, err := discovery.Discover(context.Background(), "shop", "app=payments")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(targets) != 1 || targets[0].Name != "live" {
		t.Fatalf("expected only the running pod, got %+v", targets)
	}
}

type staticPodLister struct {
	pods []corev1.Pod
}

func (l staticPodLister) ListPods(_ context.Context, _, _ string) ([]corev1.Pod, error) {
	return l.pods, nil
}
