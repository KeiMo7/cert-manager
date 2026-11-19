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

// Package certificaterotation wires the transport-agnostic pkg/rotation
// orchestration into Kubernetes: it watches certificate Secrets, fans
// reload notifications out to every consuming pod and persists audit/state in
// a namespace ConfigMap. The feature is alpha and disabled by default.
package certificaterotation

import (
	"context"
	"fmt"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	restclient "k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

// PodLister lists pods matching a label selector inside one namespace.
type PodLister interface {
	ListPods(ctx context.Context, namespace, selector string) ([]corev1.Pod, error)
}

// podDiscovery adapts the Kubernetes pod lister to rotation.TargetDiscovery.
type podDiscovery struct {
	lister PodLister
}

func (d podDiscovery) Discover(ctx context.Context, namespace, selector string) ([]rotation.Target, error) {
	pods, err := d.lister.ListPods(ctx, namespace, selector)
	if err != nil {
		return nil, err
	}
	targets := make([]rotation.Target, 0, len(pods))
	for _, pod := range pods {
		// Terminated pods cannot reload and must not be counted as missing
		// notifications; the selector may briefly match them during rollover.
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		targets = append(targets, rotation.Target{
			UID:       string(pod.UID),
			Namespace: pod.Namespace,
			Name:      pod.Name,
			PodIP:     pod.Status.PodIP,
		})
	}
	return targets, nil
}

// podSignalSender implements rotation.SignalSender over the pods/exec
// subresource. Sending a signal is achieved by running `kill -<signal> 1` in
// the pod, which needs no binaries beyond a POSIX shell in the target.
type podSignalSender struct {
	exec ExecClient
}

func (s podSignalSender) SendSignal(ctx context.Context, target rotation.Target, signal string) error {
	return s.exec.Exec(ctx, target.Namespace, target.Name, "", []string{"sh", "-c", "kill -" + signal + " 1"})
}

// podCommandRunner implements rotation.CommandRunner over pods/exec.
type podCommandRunner struct {
	exec ExecClient
}

func (r podCommandRunner) Run(ctx context.Context, target rotation.Target, command string) error {
	return r.exec.Exec(ctx, target.Namespace, target.Name, "", []string{"sh", "-c", command})
}

// podProxyReloader resolves a target's in-pod loopback reload URL against the
// Kubernetes pods/proxy subresource. A hot-reload endpoint such as
// http://127.0.0.1:9090/-/reload is only reachable inside the pod's network
// namespace, so the controller cannot call it directly: the apiserver proxies
// the request to the pod instead.
type podProxyReloader struct {
	restClient restclient.Interface
	rawURL     string
	doer       rotation.HTTPDoer
	now        func() time.Time
}

func (r podProxyReloader) Reload(ctx context.Context, target rotation.Target, bundle rotation.Bundle) rotation.ReloadResult {
	started := r.nowTime()
	proxied, err := r.proxyURL(target)
	if err != nil {
		return rotation.ReloadResult{
			Target:      target,
			Outcome:     rotation.OutcomeFailed,
			Fingerprint: bundle.Fingerprint(),
			Err:         err,
			AttemptedAt: started,
		}
	}
	return rotation.HTTPReloader{Doer: r.doer, URL: proxied, Now: r.now}.Reload(ctx, target, bundle)
}

func (r podProxyReloader) proxyURL(target rotation.Target) (string, error) {
	parsed, err := url.Parse(r.rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" {
		return "", fmt.Errorf("reload URL must be a loopback address inside the pod, got %q", r.rawURL)
	}
	if parsed.Scheme != "http" {
		return "", fmt.Errorf("only http loopback reload URLs are supported through pods/proxy, got %q", r.rawURL)
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
	}
	// GET-style proxy URL: /api/v1/namespaces/<ns>/pods/<name>:<port>/proxy/<path>
	request := r.restClient.Get().
		Namespace(target.Namespace).
		Resource("pods").
		Name(target.Name + ":" + port).
		SubResource("proxy").
		Suffix(parsed.Path)
	for key, values := range parsed.Query() {
		for _, value := range values {
			request.Param(key, value)
		}
	}
	return request.URL().String(), nil
}

func (r podProxyReloader) nowTime() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
