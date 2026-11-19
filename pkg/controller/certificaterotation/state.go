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
	"encoding/json"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/cert-manager/cert-manager/pkg/rotation"
)

const (
	// StatusConfigMapName holds per-Secret rotation state and audit history.
	StatusConfigMapName = "cert-manager-rotation-status"

	statusOwnerLabel = "rotation.cert-manager.io/component"
	maxAuditEntries  = 50
)

// configMapStateStore implements rotation.StateStore and rotation.AuditSink
// against one ConfigMap per namespace.
type configMapStateStore struct {
	client coreclient.ConfigMapsGetter
}

func newConfigMapStateStore(client coreclient.ConfigMapsGetter) *configMapStateStore {
	return &configMapStateStore{client: client}
}

type secretStatePayload struct {
	PreviousFingerprint string                          `json:"previousFingerprint"`
	Targets             map[string]rotation.TargetState `json:"targets"`
}

func stateKey(ref rotation.SecretRef) string {
	return ref.Namespace + "/" + ref.Name
}

func (s *configMapStateStore) Load(ctx context.Context, ref rotation.SecretRef) (map[string]rotation.TargetState, string, error) {
	configMap, err := s.client.ConfigMaps(ref.Namespace).Get(ctx, StatusConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return map[string]rotation.TargetState{}, "", nil
	}
	if err != nil {
		return nil, "", err
	}

	var payload secretStatePayload
	if raw := configMap.Data[stateKey(ref)]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			return nil, "", fmt.Errorf("decoding rotation state: %w", err)
		}
	}
	if payload.Targets == nil {
		payload.Targets = map[string]rotation.TargetState{}
	}
	return payload.Targets, payload.PreviousFingerprint, nil
}

func (s *configMapStateStore) Save(ctx context.Context, ref rotation.SecretRef, states map[string]rotation.TargetState, previousFingerprint string) error {
	configMap, err := s.client.ConfigMaps(ref.Namespace).Get(ctx, StatusConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      StatusConfigMapName,
				Namespace: ref.Namespace,
				Labels:    map[string]string{statusOwnerLabel: "true"},
			},
			Data: map[string]string{},
		}
	} else if err != nil {
		return err
	}
	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}

	raw, err := json.Marshal(secretStatePayload{PreviousFingerprint: previousFingerprint, Targets: states})
	if err != nil {
		return fmt.Errorf("encoding rotation state: %w", err)
	}
	configMap.Data[stateKey(ref)] = string(raw)

	return upsertConfigMap(ctx, s.client, configMap)
}

// Write appends an audit record under a distinct key. History is bounded so a
// busy namespace cannot grow the ConfigMap without limit.
func (s *configMapStateStore) Write(ctx context.Context, record rotation.AuditRecord) error {
	configMap, err := s.client.ConfigMaps(record.Namespace).Get(ctx, StatusConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      StatusConfigMapName,
				Namespace: record.Namespace,
				Labels:    map[string]string{statusOwnerLabel: "true"},
			},
			Data: map[string]string{},
		}
	} else if err != nil {
		return err
	}
	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}

	auditKey := "audit/" + record.SecretName + "/" + record.Time.UTC().Format("20060102T150405.000000000Z")
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encoding audit record: %w", err)
	}
	configMap.Data[auditKey] = string(raw)
	pruneAuditHistory(configMap, record.SecretName)

	return upsertConfigMap(ctx, s.client, configMap)
}

// upsertConfigMap creates the ConfigMap or updates it when it already exists.
// Treating AlreadyExists as a retry keeps the write correct against both a
// real apiserver (which stamps creation metadata) and test fakes (which may
// not), and tolerates concurrent writers racing on first creation.
func upsertConfigMap(ctx context.Context, client coreclient.ConfigMapsGetter, configMap *corev1.ConfigMap) error {
	namespace := configMap.Namespace
	if _, err := client.ConfigMaps(namespace).Create(ctx, configMap, metav1.CreateOptions{}); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return err
	}

	latest, err := client.ConfigMaps(namespace).Get(ctx, configMap.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	latest.Data = configMap.Data
	if latest.Labels == nil {
		latest.Labels = map[string]string{}
	}
	for key, value := range configMap.Labels {
		latest.Labels[key] = value
	}
	_, err = client.ConfigMaps(namespace).Update(ctx, latest, metav1.UpdateOptions{})
	return err
}

func pruneAuditHistory(configMap *corev1.ConfigMap, secretName string) {
	prefix := "audit/" + secretName + "/"
	var keys []string
	for key := range configMap.Data {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	if len(keys) <= maxAuditEntries {
		return
	}
	// Keys carry RFC3339 timestamps, so lexicographic order is chronological.
	slices.Sort(keys)
	for _, key := range keys[:len(keys)-maxAuditEntries] {
		delete(configMap.Data, key)
	}
}
