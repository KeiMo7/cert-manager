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

package options

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	rotationcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterotation"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
)

func TestRotationControllerGateDefaultsOff(t *testing.T) {
	if err := utilfeature.DefaultMutableFeatureGate.Set("RotationAwareWorkloadReload=false"); err != nil {
		t.Fatalf("disabling gate: %v", err)
	}
	t.Cleanup(func() { _ = utilfeature.DefaultMutableFeatureGate.Set("RotationAwareWorkloadReload=false") })

	enabled := EnabledControllers(&config.ControllerConfiguration{Controllers: []string{"*"}})
	if enabled.Has(rotationcontroller.ControllerName) {
		t.Fatalf("rotation controller must stay disabled behind the default-off gate")
	}

	if err := utilfeature.DefaultMutableFeatureGate.Set("RotationAwareWorkloadReload=true"); err != nil {
		t.Fatalf("enabling gate: %v", err)
	}
	enabled = EnabledControllers(&config.ControllerConfiguration{Controllers: []string{"*"}})
	if !enabled.Has(rotationcontroller.ControllerName) {
		t.Fatalf("rotation controller must be enabled when gate is on")
	}

	// Explicit controller selection still works with the gate enabled.
	if got := EnabledControllers(&config.ControllerConfiguration{Controllers: []string{rotationcontroller.ControllerName}}); !got.Equal(sets.New(rotationcontroller.ControllerName)) {
		t.Fatalf("explicit selection mismatch: %v", sets.List(got))
	}
}
