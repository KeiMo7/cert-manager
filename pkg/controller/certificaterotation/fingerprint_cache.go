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
	"sync"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

type servedEntry struct {
	fingerprint string
	bundle      rotation.Bundle
}

// fingerprintCache remembers the last bundle each Secret converged on so the
// controller can pass the currently-served bundle into window/expiry checks
// and suppress duplicate reconciles.
type fingerprintCache struct {
	mu      sync.RWMutex
	entries map[types.NamespacedName]servedEntry
}

func newFingerprintCache() *fingerprintCache {
	return &fingerprintCache{entries: map[types.NamespacedName]servedEntry{}}
}

func (c *fingerprintCache) set(key types.NamespacedName, fingerprint string, bundle rotation.Bundle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = servedEntry{fingerprint: fingerprint, bundle: bundle}
}

func (c *fingerprintCache) get(key types.NamespacedName) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	return entry.fingerprint, ok
}

func (c *fingerprintCache) bundle(key types.NamespacedName, fallback rotation.Bundle) rotation.Bundle {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.entries[key]; ok {
		return entry.bundle
	}
	return fallback
}

func (c *fingerprintCache) delete(key types.NamespacedName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
