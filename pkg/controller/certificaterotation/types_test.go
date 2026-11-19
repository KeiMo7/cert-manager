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
	"net/http"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	restfake "k8s.io/client-go/rest/fake"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

func testRESTClient() *restfake.RESTClient {
	return &restfake.RESTClient{
		GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
		NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		Client: restfake.CreateHTTPClient(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK}, nil
		}),
	}
}

func TestPodProxyURL(t *testing.T) {
	target := rotation.Target{Namespace: "shop", Name: "payments-0"}

	reloader := podProxyReloader{
		restClient: testRESTClient(),
		rawURL:     "http://127.0.0.1:9090/-/reload?force=true",
	}
	got, err := reloader.proxyURL(target)
	if err != nil {
		t.Fatalf("proxy url: %v", err)
	}
	for _, want := range []string{
		"namespaces/shop",
		"pods/payments-0:9090",
		"proxy/-/reload",
		"force=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("proxy URL %q missing %q", got, want)
		}
	}

	reloader.rawURL = "http://localhost/reload"
	if _, err := reloader.proxyURL(target); err != nil {
		t.Fatalf("localhost alias: %v", err)
	}

	for _, invalid := range []string{
		"http://10.1.2.3:9090/reload",
		"https://127.0.0.1/reload",
		"::not-a-url",
	} {
		reloader.rawURL = invalid
		if _, err := reloader.proxyURL(target); err == nil {
			t.Fatalf("invalid URL %q must be rejected", invalid)
		}
	}
}

func TestBuildReloaderMethods(t *testing.T) {
	restClient := testRESTClient()
	execClient := &fakeExec{reloaded: make(chan rotation.Target, 4)}

	cfg := rotation.Config{
		Signal:    "SIGHUP",
		ReloadURL: "http://127.0.0.1:9090/reload",
		Command:   "nginx -s reload",
	}
	tests := []struct {
		method rotation.ReloadMethod
		want   string
	}{
		{method: rotation.ReloadMethodSignal, want: "SignalReloader"},
		{method: rotation.ReloadMethodHTTP, want: "podProxyReloader"},
		{method: rotation.ReloadMethodExec, want: "ExecReloader"},
		{method: rotation.ReloadMethodNone, want: "NoopReloader"},
	}
	for _, tt := range tests {
		cfg.Method = tt.method
		reloader, err := buildReloader(cfg, restClient, execClient, nil)
		if err != nil {
			t.Fatalf("method %s: %v", tt.method, err)
		}
		if typeName(reloader) != tt.want {
			t.Fatalf("method %s built %s, want %s", tt.method, typeName(reloader), tt.want)
		}
	}

	if _, err := buildReloader(rotation.Config{Method: "magic"}, restClient, execClient, nil); err == nil {
		t.Fatalf("unknown reload method must be rejected")
	}
}

func typeName(v any) string {
	switch v.(type) {
	case rotation.SignalReloader:
		return "SignalReloader"
	case podProxyReloader:
		return "podProxyReloader"
	case rotation.ExecReloader:
		return "ExecReloader"
	case rotation.NoopReloader:
		return "NoopReloader"
	default:
		return "unknown"
	}
}
