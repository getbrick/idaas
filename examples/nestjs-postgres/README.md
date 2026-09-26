# @getbrick/example-nestjs-postgres

Minimal Getbrick IDaaS delivery example: NestJS + Postgres + audit + control plane.

```bash
pnpm db:up
pnpm migrate
pnpm migrate:dry-run
pnpm test
pnpm typecheck
pnpm build
```

`pnpm db:up` starts the local Postgres service. `pnpm migrate` applies the Better Auth schema, the PostgreSQL OIDC artifact schema, the application-management tables, the open-platform, commerce, and compliance schemas through `src/migrate.ts`; use `pnpm migrate:dry-run` to print the same SQL plans without applying them. After installing `@getbrick/idaas-cli`, the equivalent local runner command is `getbrick idaas migrate --auth-file src/auth.ts --config getbrick.config.ts`; `--config` is optional when the auth file is `src/auth.ts`. Add `--dry-run` for a read-only plan. The runner discovers the exported `migrationIntegration` from `src/auth.ts`; a missing export, unsupported Better Auth migration API, or failed integration exits non-zero without printing credentials. `pnpm test` runs the signup, cookie, protected-route, OIDC, control-plane e2e, and migration-integration flows against the database.

## Migration entry points

Both entry points use the exported migration APIs of `@getbrick/idaas-control-plane` and never inline SQL. They share the same fixed tenant (`IDAAS_TENANT_ID`, default `getbrick-example`), require transaction-capable execution, and take the per-series migration lock before applying.

| Order | Migration | API | Tables |
|-------|-----------|-----|--------|
| 1 | Better Auth core | `getMigrations()` from `better-auth/db/migration` | `gb_idaas_user`, `gb_idaas_session`, `gb_idaas_account`, `gb_idaas_verification`, `gb_idaas_two_factor` |
| 2 | PostgreSQL OIDC artifacts | `getPostgresOidcMigrationSql()` / `migratePostgresOidcSchema()` | `gb_idaas_oidc_artifact` |
| 3 | Application management v2–v5 | `getApplicationManagementMigrations()` / `applyVersionedApplicationManagementMigrations()` | `gb_idaas_tenant`, `gb_idaas_application`, `gb_idaas_application_platform`, `gb_idaas_application_client`, `gb_idaas_platform_login_state`, `gb_idaas_client_session`, `gb_idaas_webview_ticket`, `gb_idaas_client_auth_bff_state`, `gb_idaas_audit`, `gb_idaas_schema_migration` |
| 4 | Open platform v1–v4 | `getOpenPlatformMigrations()` / `applyVersionedOpenPlatformMigration()` | `gb_open_tenant`, `gb_open_developer_organization`, `gb_open_application`, `gb_open_application_environment`, `gb_open_api_product`, `gb_open_api_version`, `gb_open_credential`, `gb_open_subscription`, `gb_open_scope_grant`, `gb_open_usage`, `gb_open_idempotency` (v1); `gb_open_webhook`, `gb_open_webhook_delivery`, `gb_open_audit_event` (v2); delivery `lease_id` / `lease_expires_at` (v3); `gb_open_domain_event` (v4); `gb_open_schema_migration` |
| 5 | Commerce v1–v3 | `getOpenCommerceMigrations()` applied through `MigrationCoordinator` | `gb_open_commerce_plan`, `gb_open_commerce_entitlement`, `gb_open_commerce_meter`, `gb_open_commerce_price`, `gb_open_commerce_subscription`, `gb_open_commerce_quota`, `gb_open_commerce_quota_reservation`, `gb_open_commerce_usage_event`, `gb_open_commerce_usage_aggregate`, `gb_open_commerce_invoice`, `gb_open_commerce_invoice_line`, `gb_open_commerce_invoice_status_event`, `gb_open_commerce_partner_account`, `gb_open_commerce_marketplace_listing`, `gb_open_commerce_commission_rule`, `gb_open_commerce_idempotency` (v2), `gb_open_commerce_invoice_dispute` (v3), `gb_open_commerce_schema_migration` |
| 6 | Compliance v1 | `getOpenComplianceMigrationDefinition()` / `applyVersionedOpenComplianceMigration()` | `gb_open_compliance_data_asset`, `gb_open_compliance_consent_record`, `gb_open_compliance_privacy_request`, `gb_open_compliance_retention_policy`, `gb_open_compliance_retention_execution`, `gb_open_compliance_cross_border_assessment`, `gb_open_compliance_vendor`, `gb_open_compliance_event`, `gb_open_compliance_schema_migration` |

`src/migrate.ts` is the executable entry (`pnpm migrate`, `pnpm migrate:dry-run`); `src/auth.ts` exports the same steps as `oidcMigration`, `applicationManagementMigration`, `openPlatformMigration`, `commerceMigration`, `complianceMigration`, and the combined `migrationIntegration` for CLI discovery. The commerce series has no single-call apply helper, so the example drives the exported `MigrationCoordinator` over the definitions returned by `getOpenCommerceMigrations()` and keeps the series lock table `gb_open_commerce_schema_migration_lock`. The compliance series has one definition, so the example calls `getOpenComplianceMigrationDefinition()` for the plan and `applyVersionedOpenComplianceMigration()` for the run under the same fixed tenant, transaction requirement, and lock key `getbrick-open-compliance-schema` (namespace `open-platform-compliance`) with history `gb_open_compliance_schema_migration` and lock `gb_open_compliance_schema_migration_lock`. `--dry-run` prints the plan of every series and executes no migration statement. Every migration is versioned, checksum-verified, and re-runnable.

## Migration security boundary

`gb_open_credential` stores `secret_digest` and `secret_reference`, never a plaintext secret; resolve the reference through the host secret manager. `gb_open_commerce_partner_account` stores a `settlement_reference`, and `gb_open_commerce_invoice` stores money as integer minor units; bank account numbers, payout instructions, and settlement credentials are not part of these tables and are not promised as plaintext columns. The compliance domain stores evidence references, workflow status, and decision metadata only: the schema records `evidence` / `*_evidence` references, `status` / `*_state` values, and actor and decision traces, and it draws no legal conclusion about any tenant's obligations — that judgment stays with the customer's own counsel. Raw personal information is never written to these tables: subjects are referenced by `subject_ref` plus `subject_count`, and `gb_open_compliance_retention_execution` / `gb_open_compliance_event` are append-only, enforced by trigger, with per-tenant row-level security on all eight tables. Migration output is schema only — it contains no rows, secrets, or connection strings, and a failed run reports a redacted message and exits non-zero.

## OIDC Provider Example

The example enables a development OIDC provider at `http://localhost:3000/oidc` for the statically registered `getbrick-demo-client`. Its user resolver reads the configured Better Auth user table, the client secret is injected at runtime through `OIDC_CLIENT_SECRET`, and the application refuses to start when that variable is missing. OIDC authorization artifacts use the PostgreSQL adapter created in `src/auth.ts`. The migration command also creates the namespaced `gb_idaas_oidc_artifact` table and indexes. Discovery is available at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`; the provider also exposes `/oidc/auth`, `/oidc/token`, `/oidc/me`, `/oidc/jwks`, introspection, revocation, and logout endpoints. The example still uses a development signing key; configure a stable JWKS and cookie keys before production. For rotation, publish the previous public key alongside the new private key, keep old keys for the maximum token/session lifetime, and run `oidcAdapter.cleanup()` on a scheduled job to remove expired artifacts.

The example also mounts `ApplicationManagementModule` with the PostgreSQL application repository. It creates and manages application records, WeChat official-account/mini-program channels, and OIDC client metadata under `/api/idaas/v1/applications`. Channel and client secrets are represented by `secretRef`; the example resolves only `env:<name>` references on the server. `ApplicationPlatformAuthService` can exchange platform codes and return a normalized identity without exposing provider tokens or mini-program session keys; the host should then bind that identity to a Better Auth session.

A lifecycle call keeps the returned version in the next request:

```bash
curl -sS -X POST http://localhost:3000/api/idaas/v1/applications/<application-id>/archive \
  -H 'content-type: application/json' \
  -H 'If-Match: "application:<application-id>:1"' \
  -d '{}'
curl -sS http://localhost:3000/api/idaas/v1/applications/<application-id>/external-identities
```

The archive, restore, and purge routes require their corresponding application permissions. A purge returns an accepted job; it does not expose or accept a raw credential. The admin list components also expose readiness checks, lifecycle/effective status, version/ETag, and masked secret state for the same records.

## Offline database operations

The CLI delegates to the locally installed `pg_dump`, `createdb`, and `pg_restore`; it never builds a shell command. Provide `DATABASE_URL` or the PostgreSQL `PG*` variables in the runtime environment. The backup is an unencrypted custom-format dump and the CLI does not set or claim customer encryption or file-permission policy.

```bash
export DATABASE_URL='postgres://user:password@localhost:5432/getbrick'
getbrick idaas backup:create --output ./backups
BACKUP_FILE=./backups/backup-2026-01-02T03-04-05-678Z.dump
SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
getbrick idaas backup:verify --input "$BACKUP_FILE"
getbrick idaas restore:plan --input "$BACKUP_FILE" --target-db getbrick_restore
getbrick idaas restore:apply --input "$BACKUP_FILE" --target-db getbrick_restore --confirm "$SHA256"
```

`backup:create` writes a timestamped `.dump` and a `.dump.manifest.json` sidecar containing its SHA-256 digest. `backup:verify` checks the dump and manifest; use `--digest <sha256>` for an explicit digest check when no sidecar is available. Both restore commands require an explicit, simple new target database name. `restore:apply` always requires the exact matching 64-character SHA-256 `--confirm` value; `--yes` never replaces that confirmation. It rejects the current database, creates the target with `createdb --template=template0`, and invokes `pg_restore` with exit-on-error and without clean/drop operations. The target database must not already exist; prepare credentials and any customer-side encryption or permission handling separately. CLI-generated errors do not echo credential values, manifest contents, or full input/output paths.

Entry points:

- `getbrick.config.ts` — IDaaS policy config
- `src/auth.ts` — auth instance, OIDC user resolver, PostgreSQL application repository, client-secret injection, and the `migrationIntegration` export discovered by the CLI
- `src/migrate.ts` — executable Better Auth, OIDC, application-management, open-platform, commerce, and compliance migration entry
- `src/app.module.ts` — NestJS wiring (`ControlPlaneModule`, `ApplicationManagementModule`, generated role graph, OIDC provider)
- `test/e2e.test.ts` — full loop: sign-up → set-cookie → protected `/me` → OIDC flow → WeChat application/channel/client persistence
- `test/migration.test.ts` — migration integration discovery, version series, SQL order, and secret-free schema assertions

## Outbox load test

`scripts/open-platform-outbox-load.ts` drives the open-platform domain event outbox under concurrency and prints a machine-readable JSON summary. It is a manual tool: it is not part of `pnpm test`, `pnpm build`, or `pnpm check`, so nothing runs it in CI. The script itself is transpiled on the fly by `tsx`; the workspace packages it imports are read from their built `dist`, so run `pnpm build` once before the first load run.

```bash
pnpm db:up                                  # required unless --dry-run
pnpm load:open-platform --dry-run --tenants 2 --events 20 --flushers 4
pnpm load:open-platform --tenants 8 --events 200 --flushers 4
pnpm load:open-platform --help
pnpm --silent --filter @getbrick/example-nestjs-postgres load:open-platform:dry-run | jq .backlog
```

`pnpm --silent` drops pnpm's own run banner so stdout is exactly one JSON document; without it the first lines are pnpm's `> package@version script` header. `load:open-platform:dry-run` is a convenience alias that passes `--dry-run`.

By default the tool connects to PostgreSQL using the same configuration as the rest of the example (`DATABASE_URL`, otherwise `postgres://postgres:gbtest@localhost:54329/getbrick` from `src/open-platform-smoke.ts`), applies the open-platform migrations, and creates one `gb_open_tenant` row per load tenant. `--dry-run` runs the same code path against the in-memory outbox and never opens a socket. When PostgreSQL is unreachable the tool prints a `DATABASE_UNAVAILABLE` JSON object with a `db:up` hint and exits `2` instead of throwing; argument errors print `INVALID_ARGUMENT` the same way.

| Option | Default | Meaning |
|--------|---------|---------|
| `--tenants <n>` | 4 | tenants written and flushed, each with its own outbox instance |
| `--events <n>` | 50 | events appended per tenant |
| `--flushers <n>` | 4 | concurrent delivery loops; every loop drains every tenant, so the claim lease is contended |
| `--batch-size <n>` | 25 | events claimed per tenant per tick (relay limit, 1–500) |
| `--fail-rate <ratio>` | 0 | share of sink deliveries that throw, exercising retry and backoff |
| `--latency-ms <n>` | 0 | sink latency per delivery, widening the claim window |
| `--max-ticks <n>` | 500 | drain rounds per flusher |
| `--drain-timeout-ms <n>` | 60000 | wall-clock drain budget per flusher |
| `--tenant-prefix <text>` | `load` | tenant id prefix; each run appends a unique suffix |
| `--database-url <url>` | `DATABASE_URL` | connection override |

The summary is printed to stdout as JSON and contains `events` (total, appended, `appendErrors`, redacted `appendErrorSamples`), `claims` (`granted`, `rejected`, `completes`, `fails`), `deliveries` (`attempts`, `succeeded`, `failed`, `deadLettered`, `duplicates`, `duplicateEventIds`), `backlog` (per status plus `drained`), `throughput` (`eventsPerSecond` and the per-phase rates), `latencyMs` (`append`, `claim`, `deliver`, `endToEnd`; each with `count`, `p50`, `p95`, `max`), `relay` (`instances`, the summed `aggregate` of every `snapshot()`, and each raw `snapshots` entry), `readiness` and `warnings`.

`claims.granted` is the authoritative number of successful claims: the tool wraps the outbox port and counts `claim()` results directly. `relay.aggregate.claimed` is a verbatim sum of `relay.snapshot()` across instances, and the relay increments that counter for every flush outcome, including outcomes whose claim lost the race — so it is larger than `claims.granted` whenever flushers contend. `relay.aggregate.skipped` counts events deferred by the lease or by `next_attempt_at`, and each of these relays runs without a lease port (so `leaseKey` is `null` and `leader` is `true` for all of them).

`deliveries.duplicates` counts a second delivery of an event that was already in flight or already settled, so retries of a failed event are not counted. The tool exits `1` when `duplicates` is not `0`, and also when any append failed; `0` otherwise. `gb_open_domain_event` has a `BEFORE DELETE` trigger that rejects deletion, so runs leave rows behind — point `--database-url` at a scratch database rather than a shared one.
