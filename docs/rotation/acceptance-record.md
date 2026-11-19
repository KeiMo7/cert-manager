# Rotation-Aware Workload Reload — Acceptance Record

Record generated: 2026-11-20 (Asia/Shanghai).

This record is produced by executable tests, not manual claims. Reproduce with:

```bash
go test ./pkg/rotation/... -v -run TestAcceptance
go test ./pkg/controller/certificaterotation/... -v
go test ./cmd/rotation-agent/... -v
```

## Scenario 1 — Real Rotation, Ten Services Sharing One Secret

Test: `pkg/rotation/acceptance_test.go::TestAcceptanceRealRotationAcrossTenSharedServices`.

Ten workload services in namespace `shop` mount the same `payments-tls`
Secret. Each serves TLS through `rotation.CertStore` (`tls.Config.GetCertificate`)
and holds two long-lived established connections. A real self-signed
certificate bundle is generated, validated, and rotated.

Observed run:

| Measure | Result |
| --- | --- |
| Targets notified | 10 / 10 |
| Targets serving new fingerprint after reconcile | 10 / 10 |
| End-to-end latency (Secret change → all targets converged) | ~0.35 ms wall time (~0.34 ms controller-observed, in-memory fleet; the `certmanager_rotation_duration_seconds` histogram measures the same path on a cluster) |
| Interrupted established connections | 0 |
| Error rate during the rotation window | 0.0000 (0 failed / 10 attempts) |
| New handshakes after swap | Serve new certificate |
| Established connections after swap | Keep original negotiated session, run to completion |

Why interruptions are structurally zero: the workload never restarts and its
listener never closes. `CertStore.Swap` atomically replaces the key pair read
by `GetCertificate` on each new handshake; negotiated connections do not call
it again.

## Scenario 2 — Interrupting Reload Is Detected (Negative Control)

Test: `TestAcceptanceInterruptingReloadIsDetected`.

The same fleet is reloaded with an implementation that restarts listeners.
The reload API still reports success for all ten targets, but the harness
counts 20 dropped connections (two per service). This proves the continuity
measurement catches a reload method that would cause an outage even when the
per-target outcome looks successful.

## Scenario 3 — Failed Issuance / Half-Covered Bundle

Tests: `TestAcceptanceFailedIssuanceKeepsSecretUntouched`,
`TestValidateBundle`, `TestProcessItemIgnoresOptedOutAndRejectsHalfCovered`,
`TestCertStoreSwapKeepsOldBundleOnInvalidInput`,
`TestAgentReloadsChangedBundleAndRejectsBrokenOne`.

- Issuance failure means the existing pipeline never calls the Secret Apply;
  the test asserts the original Secret, including an unrelated annotation and
  data field, is byte-identical afterwards and zero notifications are sent.
- A bundle whose certificate public key does not match its private key (the
  historical half-coverage failure) is rejected by
  `rotation.ValidateBundle` before any target is touched. The previous bundle
  stays served; the agent keeps its previous in-memory key pair.
- No state write, reload call or audit success record is produced on the
  rejected path; a `RotationFailed` event and failure counter are emitted.

## Scenario 4 — Push Unavailable, Polling Fallback

Test: `TestRotateFallsBackToPollingWhenPushUnhealthy`,
`TestAgentReloadsChangedBundleAndRejectsBrokenOne`.

With the push channel reporting unhealthy, the manager emits
`certmanager_rotation_poll_fallback_total` and a `RotationPollFallback` event
and delegates convergence to the polling agents. All ten targets converge on
the new fingerprint. The agent independently detects file changes only after
the same snapshot is observed twice in a row (settled), so a Secret mid-rewrite
is never served.

## Scenario 5 — Retention Across Repeated Rotations

Test: `TestRotateKeepsPreviousFingerprintOnSecondRotation`.

After two consecutive rotations the status ConfigMap retains the fingerprint
of the bundle served immediately before the latest rotation
(`previousFingerprint`), while every target state points at the newest
fingerprint. Audit history per Secret is capped at 50 entries.

## Old Certificate Retention Policy

1. **Issuance failure**: the Secret is never written; old certificate, old
   private key and every unrelated field remain untouched.
2. **Reload failure after a valid write**: the new Secret remains valid; the
   affected workload keeps serving its previous in-memory bundle until retries
   (30s → 1m → 2m … capped at 10m) or the polling fallback succeed.
3. **State/audit**: only certificate fingerprints (SHA-256) are persisted —
   private key material is never copied into the status ConfigMap or events.

## Early Warning

`Bundle.ExpiryRisk` and the agent health endpoint evaluate
`NotAfter - now` against the configurable warning period (default 7 days).
When rotation has not fully converged inside that window, a
`RotationExpiryWarning` event fires, `certmanager_rotation_expiry_risk` is set
to 1, and the agent's `/healthz` returns 503 — leaving time for manual
intervention before expiry rather than discovering the problem at expiry.

## Audit Fields

Every attempt (`SecretChange`, `PollFallback`, `Manual`, `Retry`) records:
trigger time, trigger type, namespace/Secret, new and previous fingerprints,
selector, full target list, per-target outcome/error/duration, total duration,
push availability and any window override. Records are appended to the
`cert-manager-rotation-status` ConfigMap under `audit/` keys and to Kubernetes
events.
