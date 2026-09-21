# YCR kubelet credential provider

`ycr-credential-provider` lets a self-managed Kubernetes cluster pull private
images from Yandex Container Registry without `imagePullSecrets` or long-lived
service account keys.

It implements the Kubernetes kubelet Credential Provider API. Kubelet passes a
pod-bound Kubernetes ServiceAccount token to the binary, the binary exchanges it
through Yandex Cloud Workload Identity Federation, and kubelet receives a
short-lived IAM token for `cr.yandex`.

> Status: early preview. Review and test the provider in a non-production
> cluster before rollout.

## Requirements

- Kubernetes 1.34 or newer.
- `KubeletServiceAccountTokenForCredentialProviders` enabled (default from
  Kubernetes 1.34).
- A publicly reachable Kubernetes OIDC issuer and JWKS endpoint.
- A Yandex Cloud workload identity federation and federated credential.
- A Yandex Cloud service account with only
  `container-registry.images.puller` on the required registry or repository.

## How it works

```text
kubelet
  -> pod-bound Kubernetes ServiceAccount JWT
  -> ycr-credential-provider
  -> https://auth.yandex.cloud/oauth/token
  -> short-lived Yandex IAM token
  -> kubelet pulls from cr.yandex with username "iam"
```

The Yandex Cloud service account ID is read from this Kubernetes ServiceAccount
annotation by default:

```text
yandex.cloud/federated-yc-service-account-id
```

The annotation name matches Yandex Cloud's workload identity convention.

## Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o bin/ycr-credential-provider \
  ./cmd/ycr-credential-provider
```

## Installation

Copy the binary to every worker node, for example:

```text
/usr/local/libexec/kubelet-credential-providers/ycr-credential-provider
```

Copy [`examples/credential-provider.yaml`](examples/credential-provider.yaml)
to every worker node and start kubelet with:

```text
--image-credential-provider-bin-dir=/usr/local/libexec/kubelet-credential-providers
--image-credential-provider-config=/etc/kubernetes/credential-provider.yaml
```

Restart worker kubelets one node at a time. The executable name must match the
`providers[].name` value in the kubelet configuration.

## Kubernetes identity

Create a Kubernetes ServiceAccount with the Yandex Cloud service account ID:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: website
  namespace: asmblyr-website
  annotations:
    yandex.cloud/federated-yc-service-account-id: aje00000000000000000
```

Configure the Deployment to use it:

```yaml
spec:
  template:
    spec:
      serviceAccountName: website
      containers:
        - name: website
          image: cr.yandex/<registry-id>/website@sha256:<digest>
```

Grant nodes permission to request tokens for the configured audience. A narrow
example is included in [`examples/kubernetes.yaml`](examples/kubernetes.yaml).

## Yandex Cloud identity

Create a workload identity federation using the Kubernetes OIDC issuer and JWKS
URL. Add the same audience used by `serviceAccountTokenAudience` in the kubelet
configuration.

Create a federated credential whose external subject is exact:

```text
system:serviceaccount:<namespace>:<service-account-name>
```

Bind it to the annotated Yandex Cloud service account. Grant that account only
`container-registry.images.puller` on the repositories it needs.

## Configuration

| Flag | Environment | Default |
| --- | --- | --- |
| `--registry-host` | `YCR_REGISTRY_HOST` | `cr.yandex` |
| `--token-url` | `YC_TOKEN_URL` | `https://auth.yandex.cloud/oauth/token` |
| `--service-account-id` | `YC_SERVICE_ACCOUNT_ID` | ServiceAccount annotation |
| `--service-account-annotation` | `YC_SERVICE_ACCOUNT_ANNOTATION` | `yandex.cloud/federated-yc-service-account-id` |
| `--timeout` | - | `10s` |
| `--cache-safety-margin` | - | `5m` |

Setting `--service-account-id` gives every matching workload the same Yandex
Cloud identity. Prefer the annotation for namespace and workload isolation.

## Security notes

- The provider is installed on the node and runs as part of kubelet's trusted
  execution path.
- Never pass tokens in command-line arguments or environment variables.
- Do not log stdin, form bodies, or provider responses.
- Pin release checksums when distributing the binary through configuration
  management.
- Scope every Yandex federated credential to one exact Kubernetes
  ServiceAccount subject.
- Use `cacheType: ServiceAccount`; the returned IAM token is not the input
  Kubernetes token and can be safely cached per ServiceAccount until shortly
  before expiry.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and trust boundaries.

## Development

```bash
gofmt -w .
go test -race ./...
go vet ./...
```

## License

Apache-2.0
