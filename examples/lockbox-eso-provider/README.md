# ESO sidecar for Yandex Lockbox Workload Identity

This example adds `lockbox-eso-provider` as a loopback-only sidecar to the
official External Secrets Operator deployment. ESO calls the generic webhook on
`127.0.0.1`, so Lockbox payloads never cross the pod network.

## Yandex Cloud setup

1. Add `<YANDEX_WIF_AUDIENCE>` to the accepted audiences of the Kubernetes
   workload identity federation.
2. Create a dedicated Yandex Cloud service account.
3. Bind this exact external subject to the account:

   ```text
   system:serviceaccount:<ESO_NAMESPACE>:external-secrets
   ```

4. Grant that account `lockbox.payloadViewer` on each explicitly allowed
   Lockbox secret, not on the entire folder.

## Kubernetes setup

1. Merge `helm-values.yaml` into the pinned official ESO `HelmRelease` values.
2. Put every allowed Lockbox secret ID in `--allowed-secret-ids`. The provider
   refuses all other IDs even if IAM is accidentally broader.
3. Create a namespace-scoped `SecretStore` and its `ExternalSecret`.

The example sets a pod `fsGroup` so the non-root sidecar can read only the
projected workload token. Verify that this group does not conflict with your
ESO pod security policy before deployment.

The Yandex service account ID, audience, and Lockbox secret IDs are identifiers,
not secret values. Do not put Lockbox payloads or authorized keys in Git.

The provider currently supports text-valued Lockbox entries. Binary entries are
rejected to avoid ambiguous double-base64 encoding.
