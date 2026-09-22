# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting for this repository.

## Security model

The provider receives a pod-bound Kubernetes ServiceAccount token from kubelet,
exchanges it for a short-lived Yandex Cloud IAM token, and returns the IAM token
to kubelet as the password for `cr.yandex`.

- Tokens are never written to disk or intentionally logged.
- HTTP redirects are disabled to prevent forwarding a token to another host.
- The token endpoint must use HTTPS.
- The provider only handles the configured registry hostname.
- Yandex federated credentials should bind one exact Kubernetes ServiceAccount
  subject to one least-privilege Yandex Cloud service account.

The binary and its kubelet configuration are part of the trusted node computing
base. Install releases by immutable checksum and restrict both files to root.

### Lockbox ESO provider

`lockbox-eso-provider` runs as a separate container and is not part of the
kubelet trusted execution path. It reads a projected, audience-bound Kubernetes
ServiceAccount token from a file and keeps the exchanged Yandex IAM token only
in memory.

- Keep the HTTP listener on loopback and deploy it as an ESO sidecar.
- Bind the federated credential to the exact ESO Kubernetes ServiceAccount.
- Grant `lockbox.payloadViewer` only on explicitly required secrets.
- Configure the provider's exact secret ID allowlist as a second authorization
  boundary.
- Do not log HTTP request URLs, bodies, responses, IAM tokens, or Lockbox
  payloads.
- Pin the container by digest and run it as non-root with a read-only root
  filesystem.

ESO necessarily receives plaintext secret values before creating Kubernetes
Secrets. Use Kubernetes RBAC and encryption at rest for Secrets in etcd.
