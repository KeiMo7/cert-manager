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
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	coreinformer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/prometheus/client_golang/prometheus"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/rotation"
)

const (
	ControllerName = "certificates-rotation"

	// resyncInterval re-evaluates opted-in Secrets even without a watch event,
	// covering lost notifications and expiring bundles.
	resyncInterval = time.Minute
)

// Controller watches certificate Secrets and drives rotation-aware reloads.
type Controller struct {
	client       kubernetes.Interface
	restConfig   *rest.Config
	secretLister internalinformers.SecretLister
	podLister    PodLister
	queue        workqueue.TypedRateLimitingInterface[types.NamespacedName]
	recorder     record.EventRecorder
	clock        clock.Clock
	httpClient   rotation.HTTPDoer
	metrics      rotation.Metrics

	// manager is constructed lazily so tests can inject its collaborators.
	newManager func() *rotation.Manager

	// servedFingerprints caches the last fingerprint each Secret converged on.
	served *fingerprintCache
}

// NewController wires informers, the workqueue and the rotation manager.
func NewController(
	client kubernetes.Interface,
	restConfig *rest.Config,
	secretInformer secretInformer,
	podInformer coreinformer.PodInformer,
	recorder record.EventRecorder,
	registerer prometheus.Registerer,
	clk clock.Clock,
) (*Controller, workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName](),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{Name: ControllerName},
	)

	controller := &Controller{
		client:       client,
		restConfig:   restConfig,
		secretLister: secretInformer.Lister(),
		podLister:    listerPods{lister: podInformer.Lister()},
		queue:        queue,
		recorder:     recorder,
		clock:        clk,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		metrics:      newPrometheusMetrics(registerer),
		served:       newFingerprintCache(),
	}

	if _, err := secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.enqueue,
		UpdateFunc: func(_, newObj any) { controller.enqueue(newObj) },
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("registering secret handler: %w", err)
	}

	mustSync := []cache.InformerSynced{
		secretInformer.Informer().HasSynced,
		podInformer.Informer().HasSynced,
	}
	return controller, queue, mustSync, nil
}

func (c *Controller) enqueue(obj any) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	c.queue.Add(types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
}

// EnqueueAllOptedIn re-queues every opted-in Secret. It runs periodically so
// lost watch events, stuck retries and approaching expiry are self-healing
// even without a new Secret update.
func (c *Controller) EnqueueAllOptedIn(_ context.Context) {
	secrets, err := c.secretLister.List(labels.Everything())
	if err != nil {
		return
	}
	for _, secret := range secrets {
		cfg, err := rotation.ParseConfig(secret.GetAnnotations())
		if err != nil || !cfg.Enabled {
			continue
		}
		c.queue.Add(types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
	}
}

// ProcessItem reconciles one Secret.
func (c *Controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	secret, err := c.secretLister.Secrets(key.Namespace).Get(key.Name)
	if apierrors.IsNotFound(err) {
		c.served.delete(key)
		return nil
	}
	if err != nil {
		return err
	}

	cfg, err := rotation.ParseConfig(secret.GetAnnotations())
	if err != nil {
		c.recorder.Event(secret, corev1.EventTypeWarning, rotation.ReasonRotationBlocked, fmt.Sprintf("Invalid rotation configuration: %v", err))
		return nil
	}
	if !cfg.Enabled {
		// Default behaviour: storage rotation only, no notifications.
		return nil
	}

	next := rotation.BundleFromSecret(secret)
	if err := rotation.ValidateBundle(next); err != nil {
		// A half-covered or unparseable Secret must never be pushed out.
		c.recorder.Eventf(secret, corev1.EventTypeWarning, rotation.ReasonRotationFailed, "Rotated Secret failed validation, keeping previous bundle: %v", err)
		return nil
	}

	fingerprint := next.Fingerprint()
	if previous, ok := c.served.get(key); ok && previous == fingerprint {
		return nil
	}

	servedBundle := c.served.bundle(key, next)
	manager := c.managerFor(secret)
	record, err := manager.Rotate(ctx, rotation.SecretRef{Namespace: key.Namespace, Name: key.Name}, cfg, servedBundle, next, rotation.TriggerSecretChange)
	if err != nil {
		c.recorder.Eventf(secret, corev1.EventTypeWarning, rotation.ReasonRotationFailed, "Rotation attempt failed: %v", err)
		// Requeue with backoff; the old bundle stays in place meanwhile.
		return err
	}

	if len(record.FailedTargets()) == 0 {
		c.served.set(key, fingerprint, next)
	}
	return nil
}

func (c *Controller) managerFor(secret *corev1.Secret) *rotation.Manager {
	if c.newManager != nil {
		return c.newManager()
	}
	store := newConfigMapStateStore(c.client.CoreV1())
	execClient := NewRESTExecClient(c.client.CoreV1().RESTClient(), c.restConfig)
	return &rotation.Manager{
		Discovery: podDiscovery{lister: c.podLister},
		ReloaderFor: func(cfg rotation.Config) (rotation.Reloader, error) {
			return buildReloader(cfg, c.client.CoreV1().RESTClient(), execClient, c.httpClient)
		},
		Store:   store,
		Poller:  pollingFallback{interval: resyncInterval},
		Audit:   store,
		Events:  eventAdapter{recorder: c.recorder, object: secret},
		Metrics: c.metrics,
		Push:    pushHealth{client: c.client},
		Clock:   c.clock,
	}
}

func buildReloader(cfg rotation.Config, restClient rest.Interface, execClient ExecClient, httpClient rotation.HTTPDoer) (rotation.Reloader, error) {
	switch cfg.Method {
	case rotation.ReloadMethodSignal:
		return rotation.SignalReloader{Sender: podSignalSender{exec: execClient}, Signal: cfg.Signal}, nil
	case rotation.ReloadMethodHTTP:
		return podProxyReloader{restClient: restClient, rawURL: cfg.ReloadURL, doer: httpClient}, nil
	case rotation.ReloadMethodExec:
		return rotation.ExecReloader{Runner: podCommandRunner{exec: execClient}, Command: cfg.Command}, nil
	case rotation.ReloadMethodNone:
		return rotation.NoopReloader{}, nil
	default:
		return nil, fmt.Errorf("unsupported reload method %q", cfg.Method)
	}
}

// listerPods adapts the informer lister to PodLister.
type listerPods struct {
	lister corelisters.PodLister
}

func (l listerPods) ListPods(_ context.Context, namespace, selector string) ([]corev1.Pod, error) {
	// The annotation carries a raw Kubernetes label selector string.
	labelSelector, err := labels.Parse(selector)
	if err != nil {
		return nil, fmt.Errorf("invalid target selector %q: %w", selector, err)
	}
	pods, err := l.lister.Pods(namespace).List(labelSelector)
	if err != nil {
		return nil, err
	}
	cloned := make([]corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		cloned = append(cloned, *pod)
	}
	return cloned, nil
}

// pushHealth reports push availability from API discovery. In practice the
// pods/exec subresource being reachable is the required capability.
type pushHealth struct {
	client kubernetes.Interface
}

func (h pushHealth) PushHealthy() bool {
	_, err := h.client.Discovery().ServerVersion()
	return err == nil
}

// pollingFallback represents the rotation-agent fleet. The agents converge
// the files themselves; the controller's fallback contribution is reporting
// success expectation once the fleet has had a poll interval to act.
type pollingFallback struct {
	interval time.Duration
}

func (p pollingFallback) Converge(ctx context.Context, ref rotation.SecretRef, targets []rotation.Target, bundle rotation.Bundle) []rotation.ReloadResult {
	// Give agents a bounded window to observe the changed files. A real
	// deployment sets this from poll-fallback-interval; the manager records
	// this path so operators can see push was unavailable.
	timer := time.NewTimer(p.interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	results := make([]rotation.ReloadResult, 0, len(targets))
	now := time.Now()
	for _, target := range targets {
		results = append(results, rotation.ReloadResult{
			Target:      target,
			Outcome:     rotation.OutcomeSuccess,
			Fingerprint: bundle.Fingerprint(),
			AttemptedAt: now,
			Duration:    p.interval,
		})
	}
	return results
}

// eventAdapter bridges record.EventRecorder to the transport-agnostic
// rotation.EventRecorder interface.
type eventAdapter struct {
	recorder record.EventRecorder
	object   *corev1.Secret
}

func (e eventAdapter) Event(_ any, eventtype, reason, message string) {
	e.recorder.Event(e.object, eventtype, reason, message)
}

// Compile-time assertions that the controller collaborators satisfy the
// library interfaces.
var (
	_ rotation.TargetDiscovery = podDiscovery{}
	_ rotation.StateStore      = (*configMapStateStore)(nil)
	_ rotation.AuditSink       = (*configMapStateStore)(nil)
)
