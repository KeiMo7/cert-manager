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

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempBundle(t *testing.T, cert, key []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestStatBundleDetectsChange(t *testing.T) {
	certPath, keyPath := writeTempBundle(t, []byte("cert-v1"), []byte("key-v1"))

	first, err := StatBundle(certPath, keyPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	second, err := StatBundle(certPath, keyPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if first.Changed(second) {
		t.Fatalf("identical files must not be reported as changed")
	}

	if err := os.WriteFile(certPath, []byte("cert-v2"), 0o600); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	third, err := StatBundle(certPath, keyPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if !third.Changed(second) {
		t.Fatalf("changed certificate must be detected")
	}

	if _, err := StatBundle(filepath.Join(t.TempDir(), "missing"), keyPath); err == nil {
		t.Fatalf("missing file must return an error")
	}
}

func TestSnapshotSettled(t *testing.T) {
	now := time.Date(2026, time.November, 20, 12, 0, 0, 0, time.UTC)
	first := FileSnapshot{CertSHA: "a", KeySHA: "b", ModTime: now.Add(-10 * time.Second)}
	second := FileSnapshot{CertSHA: "a", KeySHA: "b", ModTime: now.Add(-10 * time.Second)}

	if !first.Settled(second, 5*time.Second, now) {
		t.Fatalf("identical, aged snapshots must be settled")
	}
	if first.Settled(second, 30*time.Second, now) {
		t.Fatalf("snapshot younger than settle period must not be settled")
	}
	third := second
	third.CertSHA = "c"
	if first.Settled(third, 5*time.Second, now) {
		t.Fatalf("distinct snapshots must not be considered settled")
	}
}
