# Changelog

## [0.1.0] - 2026-04-07

### Added

- Initial release
- `Identity` module implementing the LegionIO identity provider contract
- `provider_type: :auth`, `facing: :machine`, `priority: 95`, `trust_weight: 100`
- `capabilities: [:authenticate, :vault_auth]`
- `resolve` reads projected SA token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Vault-verified path: when `Legion::Crypt::LeaseManager` is available, validates token via `auth/kubernetes/login` and populates groups from Vault policies
- Unverified JWT fallback: decodes JWT payload without signature verification; `groups` always `[]` on this path (RBAC safety); logs warning
- `provide_token` returns a `Legion::Identity::Lease` with `renewable: true` (projected tokens auto-rotate)
- `vault_auth` delegates to `LeaseManager#vault_logical` for namespace-aware Vault calls
- `canonical_name` derived from `namespace-sa_name` (dots and special chars replaced with hyphens)
- `Settings` module with configurable `token_path`, `namespace_path`, `vault_role`, `vault_auth_path`
- `normalize` strips non-alphanumeric characters, collapses consecutive hyphens, trims leading/trailing hyphens
