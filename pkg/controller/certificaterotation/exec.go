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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecClient runs a command in a pod via the pods/exec subresource.
type ExecClient interface {
	Exec(ctx context.Context, namespace, pod, container string, command []string) error
}

// RESTExecClient is the production ExecClient built from a rest.Config.
type RESTExecClient struct {
	client rest.Interface
	config *rest.Config
}

func NewRESTExecClient(client rest.Interface, config *rest.Config) *RESTExecClient {
	return &RESTExecClient{client: client, config: config}
}

func (c *RESTExecClient) Exec(ctx context.Context, namespace, pod, container string, command []string) error {
	req := c.client.Post().
		Resource("pods").
		Namespace(namespace).
		Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec).
		Timeout(30 * time.Second)
	executor, err := remotecommand.NewSPDYExecutor(c.config, http.MethodPost, req.URL())
	if err != nil {
		return fmt.Errorf("building exec executor: %w", err)
	}
	var stdout, stderr bytes.Buffer
	streamOptions := remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}
	if err := executor.StreamWithContext(ctx, streamOptions); err != nil {
		return fmt.Errorf("exec %v in %s/%s failed: %w: %s", command, namespace, pod, err, stderr.String())
	}
	return nil
}
