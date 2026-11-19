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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	clocktesting "k8s.io/utils/clock/testing"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/rotation"
)

func testCertPEM(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certPEM := pemEncodeBlock("CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return certPEM, pemEncodeBlock("PRIVATE KEY", keyDER)
}

func buildTestController(t *testing.T, secrets ...*corev1.Secret) (*Controller, *fake.Clientset, *fakeExec, chan rotation.Target) {
	t.Helper()
	objects := make([]runtime.Object, len(secrets))
	for i, secret := range secrets {
		objects[i] = secret
	}
	client := fake.NewClientset(objects...)
	factory := internalinformers.NewBaseKubeInformerFactory(client, 0, "")

	secretInformer := factory.Secrets()
	// Force informer construction before Start, otherwise the factory starts
	// with no registered informers and WaitForCacheSync is an empty no-op.
	secretInformer.Informer()
	factory.Pods().Informer()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	reloaded := make(chan rotation.Target, 16)
	execClient := &fakeExec{reloaded: reloaded}

	controller := &Controller{
		client:       client,
		secretLister: secretInformer.Lister(),
		podLister:    staticPodLister{pods: testPods(10)},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName](),
			workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{Name: ControllerName + "-test"},
		),
		recorder:   noopRecorder{},
		clock:      clocktesting.NewFakeClock(time.Now()),
		httpClient: nil,
		metrics:    noopMetrics{},
		served:     newFingerprintCache(),
		newManager: func() *rotation.Manager {
			return &rotation.Manager{
				Discovery: podDiscovery{lister: staticPodLister{pods: testPods(10)}},
				ReloaderFor: func(cfg rotation.Config) (rotation.Reloader, error) {
					return rotation.SignalReloader{Sender: podSignalSender{exec: execClient}, Signal: cfg.Signal}, nil
				},
				Store:   newConfigMapStateStore(client.CoreV1()),
				Poller:  staticPoller{},
				Audit:   newConfigMapStateStore(client.CoreV1()),
				Events:  noopEvents{},
				Metrics: noopMetrics{},
				Push:    alwaysHealthy{},
				Clock:   clocktesting.NewFakeClock(time.Now()),
			}
		},
	}
	return controller, client, execClient, reloaded
}

func TestProcessItemFansOutToAllPods(t *testing.T) {
	cert, key := testCertPEM(t, 1)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop",
			Name:      "payments-tls",
			Annotations: map[string]string{
				rotation.AnnotationEnabled:        "true",
				rotation.AnnotationTargetSelector: "app=payments",
				rotation.AnnotationReloadMethod:   "signal",
				rotation.AnnotationReloadSignal:   "SIGHUP",
			},
		},
		Data: map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key},
		Type: corev1.SecretTypeTLS,
	}

	controller, client, _, reloaded := buildTestController(t, secret)
	keyRef := types.NamespacedName{Namespace: "shop", Name: "payments-tls"}

	if err := controller.ProcessItem(context.Background(), keyRef); err != nil {
		t.Fatalf("process item: %v", err)
	}

	notifyAll(t, reloaded, 10)

	configMap, err := client.CoreV1().ConfigMaps("shop").Get(context.Background(), StatusConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("status configmap: %v", err)
	}
	if len(configMap.Data) < 2 {
		t.Fatalf("expected state plus at least one audit entry, got %d keys", len(configMap.Data))
	}
	var hasAudit bool
	for key := range configMap.Data {
		if len(key) >= 6 && key[:6] == "audit/" {
			hasAudit = true
		}
	}
	if !hasAudit {
		t.Fatalf("audit record missing from ConfigMap: %v", configMap.Data)
	}

	// Reconcile again with the same Secret: no duplicate notifications.
	if err := controller.ProcessItem(context.Background(), keyRef); err != nil {
		t.Fatalf("second process: %v", err)
	}
	if len(reloaded) != 0 {
		t.Fatalf("converged Secret must not renotify, got %d pending", len(reloaded))
	}
}

func TestProcessItemIgnoresOptedOutAndRejectsHalfCovered(t *testing.T) {
	cert, key := testCertPEM(t, 1)

	// Opted out: no annotations, so the Secret is left alone.
	optedOut := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "plain-tls"},
		Data:       map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key},
		Type:       corev1.SecretTypeTLS,
	}
	controller, _, _, reloaded := buildTestController(t, optedOut)
	if err := controller.ProcessItem(context.Background(), types.NamespacedName{Namespace: "shop", Name: "plain-tls"}); err != nil {
		t.Fatalf("opted-out reconcile: %v", err)
	}
	if len(reloaded) != 0 {
		t.Fatalf("opted-out Secret must not notify")
	}

	// Half-covered: valid cert paired with an unrelated private key must be
	// rejected without any notification.
	_, otherKey := testCertPEM(t, 2)
	broken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop",
			Name:      "broken-tls",
			Annotations: map[string]string{
				rotation.AnnotationEnabled:        "true",
				rotation.AnnotationTargetSelector: "app=payments",
				rotation.AnnotationReloadMethod:   "signal",
				rotation.AnnotationReloadSignal:   "SIGHUP",
			},
		},
		Data: map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: otherKey},
		Type: corev1.SecretTypeTLS,
	}
	if _, err := controller.secretLister.Secrets("shop").Get("broken-tls"); err == nil {
		t.Fatalf("broken secret should not exist yet")
	}
	// Inject via the fake client and refresh the lister through a new controller.
	controller2, client2, _, reloaded2 := buildTestController(t, optedOut)
	if _, err := client2.CoreV1().Secrets("shop").Create(context.Background(), broken, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create broken secret: %v", err)
	}
	waitForSecret(t, controller2, "shop", "broken-tls")
	if err := controller2.ProcessItem(context.Background(), types.NamespacedName{Namespace: "shop", Name: "broken-tls"}); err != nil {
		t.Fatalf("broken bundle should be handled, not error the queue: %v", err)
	}
	if len(reloaded2) != 0 {
		t.Fatalf("half-covered Secret must never notify")
	}
}
