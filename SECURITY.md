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
