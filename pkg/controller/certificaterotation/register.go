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

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
)

func (g *gateCheckedWrapper) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	log := logs.FromContext(ctx.RootContext, ControllerName)

	if !utilfeature.DefaultFeatureGate.Enabled(feature.RotationAwareWorkloadReload) {
		log.V(logs.DebugLevel).Info("rotation feature gate disabled, controller not registered")
		return nil, nil, nil
	}

	secretInformer := ctx.KubeSharedInformerFactory.Secrets()
	podInformer := ctx.KubeSharedInformerFactory.Pods()

	// The Secrets informer is wrapped (filtered caching); its concrete type
	// satisfies the minimal interface NewController consumes.
	controller, queue, mustSync, err := NewController(
		ctx.Client,
		ctx.RESTConfig,
		secretInformerAdapter{inner: secretInformer},
		podInformer,
		ctx.Recorder,
		ctx.Metrics.Registry(),
		ctx.Clock,
	)
	if err != nil {
		return nil, nil, err
	}
	log.V(logs.DebugLevel).Info("rotation controller registered")
	g.controller = controller
	return queue, mustSync, nil
}

func (g *gateCheckedWrapper) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	if g.controller == nil {
		return nil
	}
	return g.controller.ProcessItem(ctx, key)
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		wrapper := &gateCheckedWrapper{}
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(wrapper).
			With(func(runCtx context.Context) {
				// Periodic re-scan self-heals lost notifications and retries
				// targets whose previous reload failed even without a new
				// Secret watch event.
				if wrapper.controller != nil {
					wrapper.controller.EnqueueAllOptedIn(runCtx)
				}
			}, resyncInterval).
			Complete()
	})
}

// gateCheckedWrapper only runs the controller when the alpha feature gate is
// enabled, keeping default deployments on the historical behaviour.
type gateCheckedWrapper struct {
	controller *Controller
}
