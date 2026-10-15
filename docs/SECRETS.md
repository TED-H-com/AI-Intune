# Secret providers

Phase 1 keeps the public default local and generic: environment and env-style
files require no external service. Configuration holds references, never secret
values. The `internal/secrets` registry selects a `SecretProvider` by URI scheme;
providers implement `Get(ctx, ref)`, `List(ctx, scope)`, and `Health(ctx)`.
The registry lists configured references only (optionally filtered by URI prefix),
not every environment variable or filesystem entry. Register backends at startup.
The registered `bws` backend returns “not configured” until Phase 2; consequently
aggregate registry health reports that backend unavailable even when local
providers work. A missing or empty value is `ErrMissing`; read/validation failures
are errors. Callers must not log backend errors or include them in status APIs.

## References

- `env://NAME` reads a process environment variable.
- `file:///absolute/path#KEY` reads KEY from a KEY=VALUE file. URI-escape special
  path and key characters. The parser ignores blank/comment lines, accepts
  `export ` and matching single/double quotes, and performs no shell expansion.
  Duplicate keys use the last value. Reads retain the legacy one MiB limit.
- `bws://project/key` identifies a planned Bitwarden Secrets Manager secret.

`Secret` has private storage and redacts String, GoString, every fmt verb, and
JSON output. Consumers explicitly call `Reveal()` at the integration boundary;
once revealed, the caller is responsible for keeping that string out of logs and
responses. Do not place secret values in names, references, or errors.

## Notify compatibility and status

`--notify-env` and `CLAWCTL_NOTIFY_ENV` remain paths to the existing notify file.
The four existing Telegram/webhook keys are represented internally as file URIs.
Notify startup, delivery, and notify-check resolve them through the registry.
File parsing, trimming, permission warnings, channel validation, legacy command
precedence, and re-reading on delivery for rotation remain supported. Notify does
not fall back to process environment values.

The read-only `/secrets` page and `GET /v1/operator/secrets` list configured names,
references, and `present`, `missing`, or `error` status. They never return resolved
values or backend error details. Both require the existing operator `Admin`
capability, with a shared authorization check for future operator-admin scope
support, and disable response caching. The navigation link is admin-only.
No secret editing or arbitrary caller-supplied reference lookup is exposed.

## Planned Phase 2: Bitwarden Secrets Manager

Bitwarden Secrets Manager will be the single source of truth. Use machine
accounts and per-machine read-only project tokens, with each machine restricted
to its required projects. Agents pull directly rather than receiving secrets
through Hub APIs. Cache last known values locally for temporary outages, with
restricted storage permissions, explicit freshness/expiry policy, and safe status
reporting. Define rotation, revocation, cache expiration and outage behavior before
enabling this backend. Never use `bw serve`; the personal vault CLI server is not
the machine secret delivery architecture. Token provisioning and cache storage
must also avoid plaintext values in application configuration, logs, and APIs.
