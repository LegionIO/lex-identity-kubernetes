# lex-identity-kubernetes: Kubernetes Service Account Identity Provider

**Repository Level 3 Documentation**
- **Parent (Level 2)**: `extensions/CLAUDE.md`
- **Parent (Level 1)**: `legion/CLAUDE.md`

## Purpose

Kubernetes service account identity provider for LegionIO. Reads projected SA tokens from the standard K8s mount path and validates them via Vault Kubernetes auth (preferred) or falls back to unverified JWT decode.

**GitHub**: https://github.com/LegionIO/lex-identity-kubernetes
**License**: MIT
**Version**: 0.1.0

## Architecture

```
Legion::Extensions::Identity::Kubernetes
├── Identity    # provider contract: resolve, provide_token, vault_auth, normalize, ...
└── Settings    # default settings (token_path, namespace_path, vault_role, vault_auth_path)
```

No runners, no actors, no transport. Identity-only gem.

## File Map

| File | Purpose |
|------|---------|
| `lib/legion/extensions/identity/kubernetes.rb` | Entry point — requires version/settings/identity, declares `identity_provider?`, `remote_invocable?`, top-level delegation methods |
| `lib/legion/extensions/identity/kubernetes/identity.rb` | Provider contract: `resolve`, `provide_token`, `vault_auth`, `normalize`, private helpers |
| `lib/legion/extensions/identity/kubernetes/settings.rb` | Default settings, `Settings.get` merges with `Legion::Settings` |
| `lib/legion/extensions/identity/kubernetes/version.rb` | `VERSION = '0.1.0'` |

## Provider Contract

| Method | Return |
|--------|--------|
| `provider_name` | `:kubernetes` |
| `provider_type` | `:auth` |
| `facing` | `:machine` |
| `priority` | `95` |
| `trust_weight` | `100` |
| `capabilities` | `[:authenticate, :vault_auth]` |
| `resolve` | identity hash or `nil` |
| `provide_token` | `Legion::Identity::Lease` or `nil` |
| `vault_auth(token:)` | Vault response or `nil` |
| `normalize(val)` | String |

## Key Design Rules

- `groups: []` on unverified path — NEVER populate groups from unverified JWT for RBAC safety
- Log warning when using unverified path: `"K8s identity resolved without cryptographic verification — groups empty"`
- `groups` from Vault-verified path only — populated from `response.auth.policies`
- `provide_token` re-reads SA token from file each call — projected tokens auto-rotate
- `renewable: true` — signals `LeaseRenewer` to call `provide_token` periodically
- `canonical_name` = `normalize("#{namespace}-#{sa_name}")` — dots replaced with hyphens
- `private_class_method` explicit method names for all private helpers
- `vault_logical` via `LeaseManager.instance.vault_logical` (NOT raw `::Vault.logical`)
- `Legion::JSON.load` returns SYMBOL keys — use `:sub`, `:exp`, `:groups`, NOT string keys

## Dependencies

| Gem | Purpose |
|-----|---------|
| `legion-json` | JSON serialization (`symbolize_names: true` — SYMBOL keys) |
| `legion-settings` | Configuration management |

## Testing

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

---

**Maintained By**: Matthew Iverson (@Esity)
