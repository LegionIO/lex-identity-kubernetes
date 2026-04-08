# lex-identity-kubernetes

Kubernetes service account identity provider for LegionIO. Reads projected SA tokens from the standard mount path and optionally validates them via Vault Kubernetes auth.

**Gem**: `lex-identity-kubernetes`
**Version**: 0.1.0
**License**: MIT

## Overview

When running inside a Kubernetes pod, LegionIO can establish machine identity from the pod's service account. This provider:

1. Reads the projected SA token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. If Vault is connected: validates the token via `auth/kubernetes/login` and derives groups from Vault policies (verified path)
3. If Vault is not connected: decodes the JWT payload without signature verification (unverified fallback) — groups are always empty on this path for RBAC safety

## Identity Shape

```ruby
{
  canonical_name: 'legionio-legion-worker',   # namespace-sa_name
  kind:           :machine,
  source:         :kubernetes,
  persistent:     true,
  groups:         ['default', 'legionio'],    # from Vault policies (verified only)
  metadata:       {
    namespace:        'legionio',
    service_account:  'legion-worker',
    verified:         true   # false on unverified path
  }
}
```

## Configuration

Settings at `Legion::Settings[:identity][:kubernetes]`:

| Key | Default | Description |
|-----|---------|-------------|
| `token_path` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | SA token file path |
| `namespace_path` | `/var/run/secrets/kubernetes.io/serviceaccount/namespace` | Namespace file path |
| `vault_role` | `legionio` | Vault Kubernetes auth role |
| `vault_auth_path` | `kubernetes` | Vault auth mount path |

## Provider Contract

| Method | Return |
|--------|--------|
| `provider_name` | `:kubernetes` |
| `provider_type` | `:auth` |
| `facing` | `:machine` |
| `priority` | `95` |
| `trust_weight` | `100` |
| `capabilities` | `[:authenticate, :vault_auth]` |

## Vault Setup

```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
  token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  kubernetes_host="https://kubernetes.default.svc"

vault write auth/kubernetes/role/legionio \
  bound_service_account_names=legion-worker \
  bound_service_account_namespaces=legionio \
  policies=default,legionio \
  ttl=1h
```

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```
