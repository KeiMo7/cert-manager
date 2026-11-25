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

package retry

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyValidate(t *testing.T) {
	tests := map[string]struct {
		policy    Policy
		wantErr   bool
		wantErrIs bool
	}{
		"default policy is valid": {
			policy: Policy{Minimum: DefaultMinimum, Maximum: DefaultMaximum},
		},
		"zero minimum is invalid": {
			policy:    Policy{Minimum: 0, Maximum: DefaultMaximum},
			wantErr:   true,
			wantErrIs: true,
		},
		"negative minimum is invalid": {
			policy:    Policy{Minimum: -time.Second, Maximum: DefaultMaximum},
			wantErr:   true,
			wantErrIs: true,
		},
		"maximum smaller than minimum is still a valid policy": {
			policy: Policy{Minimum: DefaultMinimum, Maximum: time.Minute},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.policy.Validate()
			if !test.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			if test.wantErrIs {
				assert.True(t, errors.Is(err, ErrInvalidPolicy), "error %q must wrap ErrInvalidPolicy", err)
			}
		})
	}
}

func TestDecideDelay(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	lastFailure := now

	tests := map[string]struct {
		policy      Policy
		attempts    int32
		wantDelay   time.Duration
		wantWaiting bool
	}{
		"attempt 1 uses the minimum":                 {attempts: 1, wantDelay: time.Hour, wantWaiting: true},
		"attempt 2 doubles":                          {attempts: 2, wantDelay: 2 * time.Hour, wantWaiting: true},
		"attempt 3 quadruples":                       {attempts: 3, wantDelay: 4 * time.Hour, wantWaiting: true},
		"attempt 4":                                  {attempts: 4, wantDelay: 8 * time.Hour, wantWaiting: true},
		"attempt 5":                                  {attempts: 5, wantDelay: 16 * time.Hour, wantWaiting: true},
		"attempt 6 caps at maximum":                  {attempts: 6, wantDelay: 32 * time.Hour, wantWaiting: true},
		"attempt 31 saturates at maximum":            {attempts: 31, wantDelay: 32 * time.Hour, wantWaiting: true},
		"attempt math.MaxInt32 saturates at maximum": {attempts: math.MaxInt32, wantDelay: 32 * time.Hour, wantWaiting: true},
		"attempt 0 is treated as one":                {attempts: 0, wantDelay: time.Hour, wantWaiting: true},
		"negative attempts are treated as one":       {attempts: -5, wantDelay: time.Hour, wantWaiting: true},
		"maximum below minimum caps at minimum":      {policy: Policy{Minimum: time.Hour, Maximum: time.Minute}, attempts: 6, wantDelay: time.Hour, wantWaiting: true},
		"maximum above minimum is respected":         {policy: Policy{Minimum: time.Minute, Maximum: 10 * time.Minute}, attempts: 3, wantDelay: 4 * time.Minute, wantWaiting: true},
		"maximum equal to minimum is constant":       {policy: Policy{Minimum: time.Hour, Maximum: time.Hour}, attempts: 6, wantDelay: time.Hour, wantWaiting: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			policy := test.policy
			if policy.Minimum == 0 {
				policy = Policy{Minimum: DefaultMinimum, Maximum: DefaultMaximum}
			}

			got, err := policy.Decide(now, State{Attempts: test.attempts, LastFailure: lastFailure})
			require.NoError(t, err)
			assert.Equal(t, test.wantDelay, got.Delay)
			assert.Equal(t, now.Add(test.wantDelay), got.NextAttempt)
			assert.Equal(t, test.wantDelay, got.Wait)
			assert.Equal(t, test.wantWaiting, got.Waiting)
		})
	}
}

func TestDecideWait(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	policy := Policy{Minimum: DefaultMinimum, Maximum: DefaultMaximum}

	tests := map[string]struct {
		state       State
		wantWaiting bool
		wantDelay   time.Duration
		wantWait    time.Duration
		wantNext    time.Time
	}{
		"zero last failure never waits": {
			state:       State{Attempts: 1},
			wantWaiting: false,
			wantDelay:   time.Hour,
			wantWait:    0,
			wantNext:    time.Time{},
		},
		"half the backoff remains": {
			state:       State{Attempts: 1, LastFailure: now.Add(-30 * time.Minute)},
			wantWaiting: true,
			wantDelay:   time.Hour,
			wantWait:    30 * time.Minute,
			wantNext:    now.Add(30 * time.Minute),
		},
		"exactly due is not waiting": {
			state:       State{Attempts: 1, LastFailure: now.Add(-time.Hour)},
			wantWaiting: false,
			wantDelay:   time.Hour,
			wantWait:    0,
			wantNext:    now,
		},
		"past due clamps to zero": {
			state:       State{Attempts: 2, LastFailure: now.Add(-10 * time.Hour)},
			wantWaiting: false,
			wantDelay:   2 * time.Hour,
			wantWait:    0,
			wantNext:    now.Add(-8 * time.Hour),
		},
		"future last failure uses now as base and waits a full delay": {
			state:       State{Attempts: 2, LastFailure: now.Add(48 * time.Hour)},
			wantWaiting: true,
			wantDelay:   2 * time.Hour,
			wantWait:    2 * time.Hour,
			wantNext:    now.Add(2 * time.Hour),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := policy.Decide(now, test.state)
			require.NoError(t, err)
			assert.Equal(t, test.wantWaiting, got.Waiting)
			assert.Equal(t, test.wantDelay, got.Delay)
			assert.Equal(t, test.wantWait, got.Wait)
			assert.Equal(t, test.wantNext, got.NextAttempt)
			assert.GreaterOrEqual(t, got.Wait, time.Duration(0), "wait must never be negative")
			assert.LessOrEqual(t, got.Wait, got.Delay, "wait must never exceed the delay")
		})
	}
}

func TestDecideInvalidPolicy(t *testing.T) {
	tests := map[string]Policy{
		"zero minimum":     {Minimum: 0, Maximum: DefaultMaximum},
		"negative minimum": {Minimum: -time.Minute, Maximum: DefaultMaximum},
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := policy.Decide(time.Now(), State{Attempts: 1, LastFailure: time.Now()})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidPolicy), "error %q must wrap ErrInvalidPolicy", err)
		})
	}
}

func TestDecideIsUTC(t *testing.T) {
	loc := time.FixedZone("test", 3*60*60)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, loc)
	policy := Policy{Minimum: DefaultMinimum, Maximum: DefaultMaximum}

	got, err := policy.Decide(now, State{Attempts: 1, LastFailure: now})
	require.NoError(t, err)
	assert.Equal(t, time.UTC, got.NextAttempt.Location())
	require.NoError(t, policy.Validate())
}

func TestDecideConcurrent(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	policy := Policy{Minimum: DefaultMinimum, Maximum: DefaultMaximum}

	done := make(chan struct{})
	for i := 0; i < 16; i++ {
		go func(attempts int32) {
			defer func() { done <- struct{}{} }()
			got, err := policy.Decide(now, State{Attempts: attempts, LastFailure: now})
			assert.NoError(t, err)
			want := policy.Minimum
			for a := int32(1); a < attempts; a++ {
				if want >= policy.Maximum/2 {
					want = policy.Maximum
					break
				}
				want *= 2
			}
			assert.Equal(t, want, got.Delay)
		}(int32(i%5 + 1))
	}
	for i := 0; i < 16; i++ {
		<-done
	}
}
