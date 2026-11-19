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

// Package rotation implements rotation-aware workload reload: given a
// certificate Secret that has been rotated by the existing issuance pipeline,
// it notifies every workload consuming the Secret and drives a configurable
// reload without dropping established connections.
//
// The package is transport-agnostic and clock-injectable so that every
// behaviour is unit testable. Kubernetes-specific wiring lives in
// pkg/controller/certificaterotation and the polling fallback agent in
// cmd/rotation-agent.
package rotation
