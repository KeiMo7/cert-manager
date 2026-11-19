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

// Package main implements the rotation-agent: a standard-library-only
// sidecar/node helper that watches mounted certificate files and reloads them
// without restarting the workload. It is the degraded path used when the
// controller's push notification channel is unavailable, and it also works
// standalone for workloads that opt out of automatic push entirely.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// FileSnapshot is the content identity of the watched bundle.
type FileSnapshot struct {
	CertSHA string
	KeySHA  string
	ModTime time.Time
}

// StatBundle hashes the certificate and key files. A missing or unreadable
// file returns an error; the caller keeps serving the previous snapshot.
func StatBundle(certPath, keyPath string) (FileSnapshot, error) {
	certBytes, certInfo, err := readFileInfo(certPath)
	if err != nil {
		return FileSnapshot{}, err
	}
	keyBytes, _, err := readFileInfo(keyPath)
	if err != nil {
		return FileSnapshot{}, err
	}
	certSum := sha256.Sum256(certBytes)
	keySum := sha256.Sum256(keyBytes)
	return FileSnapshot{
		CertSHA: "sha256:" + hex.EncodeToString(certSum[:]),
		KeySHA:  "sha256:" + hex.EncodeToString(keySum[:]),
		ModTime: certInfo.ModTime(),
	}, nil
}

func readFileInfo(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return bytes, info, nil
}

// Changed reports whether either file identity differs.
func (s FileSnapshot) Changed(other FileSnapshot) bool {
	return s.CertSHA != other.CertSHA || s.KeySHA != other.KeySHA
}

// Settled guards against reading a Secret while the kubelet is still
// rewriting its files: the same snapshot must have been observed on the
// previous poll (observed == current) and the files must be older than
// settledFor.
func (s FileSnapshot) Settled(observed FileSnapshot, settledFor time.Duration, now time.Time) bool {
	if s.Changed(observed) {
		return false
	}
	return now.Sub(s.ModTime) >= settledFor
}
