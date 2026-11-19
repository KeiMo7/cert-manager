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
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// weekdayNames lists the accepted weekday prefixes in window expressions.
var weekdayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// Window is a cron-style, UTC, weekly reload window. A rotation that lands
// outside every configured window is postponed until the next one, unless the
// current certificate is inside its expiry warning period, in which case the
// reload proceeds immediately (safety overrides convenience).
type Window struct {
	raw      string
	weekdays []time.Weekday
	start    time.Duration // offset from 00:00 UTC
	end      time.Duration // offset from 00:00 UTC, may be > 24h to span midnight
}

// ParseWindow parses expressions of the form "Mon-Fri 01:00-03:00" or
// "Sat,Sun 22:00-02:00". Weekday ranges and lists may be combined; times are
// UTC.
func ParseWindow(raw string) (*Window, error) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected \"<weekdays> <start>-<end>\", got %q", raw)
	}

	weekdays, err := parseWeekdays(parts[0])
	if err != nil {
		return nil, err
	}

	times := strings.Split(parts[1], "-")
	if len(times) != 2 {
		return nil, fmt.Errorf("expected <start>-<end>, got %q", parts[1])
	}
	start, err := parseClock(times[0])
	if err != nil {
		return nil, err
	}
	end, err := parseClock(times[1])
	if err != nil {
		return nil, err
	}
	if end == start {
		return nil, fmt.Errorf("window start and end must differ")
	}

	return &Window{raw: raw, weekdays: weekdays, start: start, end: end}, nil
}

func parseWeekdays(raw string) ([]time.Weekday, error) {
	var weekdays []time.Weekday
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if strings.Contains(item, "-") {
			bounds := strings.Split(item, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid weekday range %q", item)
			}
			from, err := weekday(bounds[0])
			if err != nil {
				return nil, err
			}
			to, err := weekday(bounds[1])
			if err != nil {
				return nil, err
			}
			for day := from; ; day = (day + 1) % 7 {
				weekdays = append(weekdays, day)
				if day == to {
					break
				}
			}
			continue
		}
		day, err := weekday(item)
		if err != nil {
			return nil, err
		}
		weekdays = append(weekdays, day)
	}
	slices.Sort(weekdays)
	return slices.Compact(weekdays), nil
}

func weekday(raw string) (time.Weekday, error) {
	for idx, name := range weekdayNames {
		if strings.EqualFold(name, raw) {
			return time.Weekday(idx), nil
		}
	}
	return 0, fmt.Errorf("unknown weekday %q, want one of %s", raw, strings.Join(weekdayNames, ","))
}

func parseClock(raw string) (time.Duration, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid clock value %q, want HH:MM", raw)
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, fmt.Errorf("invalid hour in %q", raw)
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid minute in %q", raw)
	}
	return time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute, nil
}

// Contains reports whether instant t (UTC) falls inside the window. Windows
// whose end is earlier than their start span midnight.
func (w *Window) Contains(t time.Time) bool {
	t = t.UTC()
	offset := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute
	if w.end > w.start {
		return slices.Contains(w.weekdays, t.Weekday()) && offset >= w.start && offset < w.end
	}
	// Overnight window: the pre-midnight part belongs to the listed weekday,
	// the post-midnight part belongs to an occurrence that started on the
	// previous listed weekday.
	if offset >= w.start {
		return slices.Contains(w.weekdays, t.Weekday())
	}
	if offset < w.end {
		previous := (t.Weekday() + 6) % 7
		return slices.Contains(w.weekdays, previous)
	}
	return false
}

// NextOpen returns the first instant at or after t when the window opens.
func (w *Window) NextOpen(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute)
	for range 8 {
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		if slices.Contains(w.weekdays, t.Weekday()) {
			open := day.Add(w.start)
			if !open.Before(t) {
				return open
			}
		}
		t = day.Add(24 * time.Hour)
	}
	// Unreachable: every window contains at least one weekday.
	return t
}

func (w *Window) String() string {
	return w.raw
}
