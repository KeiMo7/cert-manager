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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

func TestEnqueueAllOptedIn(t *testing.T) {
	cert, key := testCertPEM(t, 1)
	optedIn := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop",
			Name:      "opted-in",
			Annotations: map[string]string{
				rotation.AnnotationEnabled:        "true",
				rotation.AnnotationTargetSelector: "app=payments",
				rotation.AnnotationReloadMethod:   "none",
			},
		},
		Data: map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key},
	}
	optedOut := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "opted-out"},
		Data:       map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key},
	}

	controller, _, _, _ := buildTestController(t, optedIn, optedOut)
	controller.EnqueueAllOptedIn(context.Background())

	if controller.queue.Len() != 1 {
		t.Fatalf("queue length = %d, want exactly the opted-in Secret", controller.queue.Len())
	}
	item, _ := controller.queue.Get()
	if item != (types.NamespacedName{Namespace: "shop", Name: "opted-in"}) {
		t.Fatalf("queued %v, want the opted-in Secret", item)
	}
}
