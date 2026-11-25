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

// Package retry provides a reusable decision about when a failed Certificate
// issuance should be retried.
//
// The package is deliberately free of global state: it does not read
// configuration, randomness or the system clock. Everything a decision depends
// on is passed in as an argument, which makes Decide side-effect free and safe
// to call from multiple workers concurrently.
package retry

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// ErrInvalidPolicy is returned, wrapped, when a Policy cannot be used to
// compute a backoff. Callers should test for it with errors.Is. Callers that
// see this error should treat issuance as not being blocked by a backoff.
var ErrInvalidPolicy = errors.New("invalid retry policy")

// DefaultMinimum is the default minimum delay between a failed issuance and
// its retry.
const DefaultMinimum = time.Hour

// DefaultMaximum is the default maximum delay between a failed issuance and
// its retry.
const DefaultMaximum = 32 * time.Hour

// Policy describes the exponential backoff applied between failed issuance
// attempts.
type Policy struct {
	// Minimum is the delay before the first retry. It must be greater than
	// zero.
	Minimum time.Duration
	// Maximum caps the delay. If Maximum is smaller than Minimum, Minimum is
	// used as the effective cap.
	Maximum time.Duration
}

// Validate reports whether the policy can be used to compute a backoff. A
// policy with a non-positive Minimum is invalid; the returned error wraps
// ErrInvalidPolicy.
func (p Policy) Validate() error {
	if p.Minimum <= 0 {
		return fmt.Errorf("%w: minimum backoff duration must be greater than zero, got %s", ErrInvalidPolicy, p.Minimum)
	}
	return nil
}

// cap returns the effective upper bound for the delay. A Maximum that is not
// greater than Minimum is replaced by Minimum, so the delay never falls below
// the minimum.
func (p Policy) cap() time.Duration {
	if p.Maximum < p.Minimum {
		return p.Minimum
	}
	return p.Maximum
}

// State is the observed failure state of a Certificate.
type State struct {
	// Attempts is the number of consecutive failed issuance attempts. Values
	// less than one are treated as a single attempt.
	Attempts int32
	// LastFailure is the time of the most recent failure. Its zero value means
	// no failure has been recorded.
	LastFailure time.Time
}

// AttemptsFromInt converts a failed issuance attempt count held in an int to
// the int32 range understood by State. Values outside the int32 range are
// saturated rather than wrapped, so a manually patched huge or negative value
// can never produce an unexpected delay.
func AttemptsFromInt(attempts int) int32 {
	switch {
	case attempts > math.MaxInt32:
		return math.MaxInt32
	case attempts < math.MinInt32:
		return math.MinInt32
	default:
		return int32(attempts)
	}
}

// Decision is the outcome of a backoff calculation.
type Decision struct {
	// Waiting reports whether a retry is still in the future. It is only true
	// when Wait is greater than zero.
	Waiting bool
	// Delay is the full backoff period for the given state.
	Delay time.Duration
	// Wait is the remaining time until NextAttempt, clamped to the inclusive
	// range [0, Delay].
	Wait time.Duration
	// NextAttempt is the time at which the retry becomes due. It is the zero
	// time when LastFailure is the zero value.
	NextAttempt time.Time
}

// Decide computes the backoff decision for the given state at the given time
// using the default policy (DefaultMinimum and DefaultMaximum).
//
// It is a convenience wrapper around Policy.Decide for callers that do not
// configure their own backoff durations.
func Decide(now time.Time, state State) (Decision, error) {
	return (Policy{Minimum: DefaultMinimum, Maximum: DefaultMaximum}).Decide(now, state)
}

// Decide computes the backoff decision for the given state at the given time.
// All returned times are in UTC. Decide does not read the system clock and has
// no side effects.
//
// The delay is Minimum multiplied by 2^(Attempts-1), capped at Maximum; when
// Maximum is smaller than Minimum, Minimum is used as the cap. The
// multiplication saturates instead of overflowing, and an attempt count below
// one is treated as a single attempt.
//
// When LastFailure is later than now, now is used as the base time so that a
// bogus future timestamp cannot postpone the retry indefinitely. When
// LastFailure is the zero value, Waiting is false.
func (p Policy) Decide(now time.Time, state State) (Decision, error) {
	if err := p.Validate(); err != nil {
		return Decision{}, err
	}

	now = now.UTC()
	delay := p.delay(state.Attempts)

	decision := Decision{Delay: delay}
	if state.LastFailure.IsZero() {
		// No failure has been recorded: the caller should not be waiting.
		return decision, nil
	}

	lastFailure := state.LastFailure.UTC()
	base := lastFailure
	if base.After(now) {
		// A failure stamped in the future must not push the retry further out:
		// an erroneous or forged timestamp would otherwise postpone issuance
		// indefinitely.
		base = now
	}

	nextAttempt := base.Add(delay)
	wait := nextAttempt.Sub(now)
	if wait < 0 {
		wait = 0
	}
	if wait > delay {
		wait = delay
	}

	decision.NextAttempt = nextAttempt
	decision.Wait = wait
	decision.Waiting = wait > 0
	return decision, nil
}

// delay returns Minimum * 2^(attempts-1) saturated at the policy's cap. A
// non-positive attempt count is treated as a single attempt.
func (p Policy) delay(attempts int32) time.Duration {
	if attempts <= 1 {
		return p.Minimum
	}

	upper := p.cap()

	// exp is the number of doublings: attempts-1.
	exp := attempts - 1
	// A shift of 63 or more is guaranteed to exceed any positive cap that can
	// be represented in an int64, so saturate without shifting.
	if exp >= 63 {
		return upper
	}

	// Saturating multiplication: Minimum << exp <= upper exactly when
	// Minimum <= upper >> exp. Shifting first would otherwise wrap around and
	// could produce a negative or zero delay.
	if p.Minimum > upper>>uint(exp) {
		return upper
	}

	computed := p.Minimum << uint(exp)
	if computed > upper {
		return upper
	}
	if computed < p.Minimum {
		return p.Minimum
	}
	return computed
}
