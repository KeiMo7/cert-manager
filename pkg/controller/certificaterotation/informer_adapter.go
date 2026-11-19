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
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
)

// secretInformer is the minimal Secret informer surface the controller needs.
// It is satisfied by both cert-manager's filtered Secret informer and the
// standard client-go Secret informer.
type secretInformer interface {
	Informer() internalinformers.Informer
	Lister() internalinformers.SecretLister
}

// secretInformerAdapter exposes cert-manager's filtered Secret informer
// through the secretInformer shape consumed by NewController.
type secretInformerAdapter struct {
	inner internalinformers.SecretInformer
}

func (a secretInformerAdapter) Informer() internalinformers.Informer {
	return a.inner.Informer()
}

func (a secretInformerAdapter) Lister() internalinformers.SecretLister {
	return a.inner.Lister()
}

var _ secretInformer = secretInformerAdapter{}
