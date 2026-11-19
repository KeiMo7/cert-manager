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

package rotation

import (
	"testing"
	"time"
)

func TestParseWindowErrors(t *testing.T) {
	invalid := []string{
		"",
		"Mon-Fri",
		"Funday 01:00-02:00",
		"Mon 25:00-02:00",
		"Mon 01:00-01:00",
		"Mon 01:00",
	}
	for _, raw := range invalid {
		if _, err := ParseWindow(raw); err == nil {
			t.Fatalf("expected error parsing %q", raw)
		}
	}
}

func TestWindowContains(t *testing.T) {
	// Monday 2026-11-16 00:00 UTC is a fixed, known weekday.
	monday := time.Date(2026, time.November, 16, 0, 0, 0, 0, time.UTC)

	weekdayWindow, err := ParseWindow("Mon-Fri 01:00-03:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !weekdayWindow.Contains(monday.Add(2 * time.Hour)) {
		t.Fatalf("Monday 02:00 must be inside Mon-Fri 01:00-03:00")
	}
	if weekdayWindow.Contains(monday.Add(4 * time.Hour)) {
		t.Fatalf("Monday 04:00 must be outside the window")
	}
	saturday := monday.Add(5 * 24 * time.Hour)
	if weekdayWindow.Contains(saturday.Add(2 * time.Hour)) {
		t.Fatalf("Saturday must be outside a Mon-Fri window")
	}

	overnight, err := ParseWindow("Sat 22:00-02:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !overnight.Contains(saturday.Add(23 * time.Hour)) {
		t.Fatalf("Saturday 23:00 must be inside the overnight window")
	}
	if !overnight.Contains(saturday.Add(25 * time.Hour)) {
		t.Fatalf("Sunday 01:00 must be inside the overnight window")
	}
	if overnight.Contains(saturday.Add(3 * time.Hour)) {
		t.Fatalf("Saturday 03:00 must be outside the overnight window")
	}
}

func TestWindowNextOpen(t *testing.T) {
	mondayNoon := time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC)
	window, err := ParseWindow("Mon-Fri 01:00-03:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	next := window.NextOpen(mondayNoon)
	want := time.Date(2026, time.November, 17, 1, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next open = %s, want %s", next, want)
	}
}

func TestShouldReloadNowWindowAndExpiryOverride(t *testing.T) {
	now := time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) // Monday noon
	window, err := ParseWindow("Mon-Fri 01:00-03:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	longLived := mustGenerateBundle(t, 1, now.Add(-time.Hour), 30*24*time.Hour)
	cfg := Config{
		Enabled:             true,
		Window:              window,
		ExpiryWarningPeriod: 7 * 24 * time.Hour,
	}

	reload, nextOpen, override, err := ShouldReloadNow(cfg, longLived, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reload || override {
		t.Fatalf("healthy cert outside window must be postponed")
	}
	if !nextOpen.Equal(time.Date(2026, time.November, 17, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("next open = %s", nextOpen)
	}

	// Certificate expiring within the warning period overrides the window.
	expiring := mustGenerateBundle(t, 2, now.Add(-23*time.Hour), 24*time.Hour)
	reload, _, override, err = ShouldReloadNow(cfg, expiring, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reload || !override {
		t.Fatalf("imminent expiry must override the window, got reload=%v override=%v", reload, override)
	}

	// No window means reload immediately.
	cfg.Window = nil
	reload, _, _, err = ShouldReloadNow(cfg, longLived, now)
	if err != nil || !reload {
		t.Fatalf("without a window reload must proceed, got reload=%v err=%v", reload, err)
	}
}
