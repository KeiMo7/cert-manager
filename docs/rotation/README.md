# Rotation-Aware Workload Reload

cert-manager rotates the certificate and updates the `Secret`; this feature
makes sure every workload actually starts serving the new certificate without
a restart and without dropping established connections.

## Enablement

1. Turn on the alpha feature gate (off by default, so existing behaviour is
   unchanged unless you opt in):

   ```bash
   --feature-gates=RotationAwareWorkloadReload=true
   ```

2. Annotate the certificate `Secret` (directly or via
   `Certificate.spec.secretTemplate.annotations`).

## Reload Methods

| Method | Annotations | Mechanism |
| --- | --- | --- |
| Signal | `reload-method: signal`, `reload-signal: SIGHUP` | `kill -<signal> 1` through pods/exec |
| HTTP | `reload-method: http`, `reload-url: http://127.0.0.1:9090/-/reload` | POST to the pod's loopback endpoint |
| Exec | `reload-method: exec`, `reload-command: nginx -s reload` | command through pods/exec |
| Notification only | `reload-method: none` | event/audit only; you handle reload |

Applications embedding a hot-reload hook should swap their served key pair
atomically (see `pkg/rotation.CertStore`) so new handshakes use the new
certificate while established connections run to completion.

## Example

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: payments-tls
  namespace: shop
spec:
  secretName: payments-tls
  dnsNames: ["payments.shop.svc"]
  issuerRef:
    name: internal-ca
    kind: ClusterIssuer
  secretTemplate:
    annotations:
      rotation.cert-manager.io/enabled: "true"
      rotation.cert-manager.io/target-selector: "app in (payments,checkout)"
      rotation.cert-manager.io/reload-method: "signal"
      rotation.cert-manager.io/reload-signal: "SIGHUP"
      rotation.cert-manager.io/reload-window: "Mon-Fri 01:00-03:00"
      rotation.cert-manager.io/expiry-warning-period: "168h"
      rotation.cert-manager.io/poll-fallback-interval: "60s"
```

All pods matching the selector receive the notification, including every pod
of every Deployment sharing the Secret. If a reload cannot be delivered, the
`rotation-agent` sidecar converges the mounted files by polling instead.

## Polling Agent

`cmd/rotation-agent` is a standard-library-only sidecar:

```bash
rotation-agent \
  --cert-path=/certs/tls.crt --key-path=/certs/tls.key \
  --mode=exec --reload-command="nginx -s reload" \
  --poll-interval=1m --expiry-warning-period=168h
```

It exposes `/metrics` and `/healthz` (503 while inside the expiry warning
period) and never serves a bundle whose certificate and key do not match.

## Guarantees

- Default rotation behaviour is unchanged unless the gate and Secret opt in.
- No new third-party dependencies; exec uses the client-go subresource.
- Failed issuance leaves the Secret and all its fields untouched.
- Reload failures keep the old in-memory certificate and retry, then poll.
- Every attempt is audited in the `cert-manager-rotation-status` ConfigMap.
- Acceptance evidence: `docs/rotation/acceptance-record.md`.
