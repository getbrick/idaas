# Database Integration

## Supported databases

`createIdaas({ database })` accepts everything better-auth accepts — a raw `pg.Pool` / `mysql2` pool / Kysely instance / Prisma / Drizzle. For delivery projects we recommend the two patterns below.

## PostgreSQL (raw pool — recommended default)

```bash
pnpm add pg
```

```ts
// src/auth.ts
import { Pool } from "pg";
import { createIdaas } from "@getbrick/idaas-core";
import { idaas } from "../getbrick.config.js";

export const auth = createIdaas({
  config: idaas,
  database: new Pool({
    connectionString: process.env.DATABASE_URL,
  }),
});
```

better-auth wraps the pool with a Postgres dialect automatically; `gb_idaas_*` table names come from the preset.

## Kysely (explicit dialect, schema support)

```ts
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";

const db = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString }) }) });

export const auth = createIdaas({
  config: idaas,
  database: { db, type: "postgres" },
});
```

## Migrations

```bash
docker compose up -d          # local postgres
getbrick idaas migrate --auth-file src/auth.ts
```

Tables created by the preset (verified against Postgres 16):

| Table | Purpose |
|-------|---------|
| `gb_idaas_user` | users |
| `gb_idaas_session` | sessions (server-side, revocable) |
| `gb_idaas_account` | credentials / OAuth accounts |
| `gb_idaas_verification` | email/phone verification tokens |
| `gb_idaas_two_factor` | TOTP secrets & recovery codes |
| `gb_idaas_oidc_artifact` | OIDC sessions, grants, authorization codes, and replay state |
| `gb_idaas_application` | Application catalog and lifecycle |
| `gb_idaas_application_platform` | WeChat and other platform channels; stores `secret_ref`, not raw secrets |
| `gb_idaas_application_client` | Managed OIDC client metadata and lifecycle |
| `gb_idaas_platform_login_state` | One-time platform login transactions and return-to state |
| `gb_idaas_client_session` | Hashed opaque client sessions for native, mini-program, and webview channels |
| `gb_idaas_webview_ticket` | One-time webview handoff tickets |
| `gb_idaas_client_auth_bff_state` | Persistent BFF OIDC state, PKCE, client, redirect, and binding claims |
| `gb_idaas_audit` | Application-management audit events |

Table names are configurable via `defineIdaasConfig({ tables: { overrides: { user: "..." } } })`.

Application-management tables are created by the versioned `createApplicationManagementMigrationSql()` / `applyApplicationManagementMigrations()` APIs from `@getbrick/idaas-control-plane`; the current series is v2–v5, with v5 adding the persistent BFF state table. The migration is idempotent for the default schema; keep credential material outside these tables and resolve `secret_ref` through the host application's secret manager.

## Open platform, commerce, and compliance tables

`getOpenPlatformMigrations()` / `applyVersionedOpenPlatformMigration()`, `getOpenCommerceMigrations()`, and `getOpenComplianceMigrationDefinition()` / `applyVersionedOpenComplianceMigration()` from `@getbrick/idaas-control-plane` add three independent versioned series with their own history and lock tables.

Open platform (current series v1–v5, history `gb_open_schema_migration`, lock `gb_open_schema_migration_lock`):

| Version | Tables |
|---------|--------|
| v1 foundation | `gb_open_tenant`, `gb_open_developer_organization`, `gb_open_application`, `gb_open_application_environment`, `gb_open_api_product`, `gb_open_api_version`, `gb_open_credential`, `gb_open_subscription`, `gb_open_scope_grant`, `gb_open_usage`, `gb_open_idempotency` |
| v2 management | `gb_open_webhook`, `gb_open_webhook_delivery`, `gb_open_audit_event` |
| v3 delivery lease | `lease_id` / `lease_expires_at` on `gb_open_webhook_delivery` |
| v4 domain event outbox | `gb_open_domain_event` |
| v5 relay lease | `gb_open_relay_lease` |

Commerce (current series v1–v4, history `gb_open_commerce_schema_migration`, lock `gb_open_commerce_schema_migration_lock`):

| Version | Tables |
|---------|--------|
| v1 foundation | `gb_open_commerce_plan`, `gb_open_commerce_entitlement`, `gb_open_commerce_meter`, `gb_open_commerce_price`, `gb_open_commerce_subscription`, `gb_open_commerce_quota`, `gb_open_commerce_quota_reservation`, `gb_open_commerce_usage_event`, `gb_open_commerce_usage_aggregate`, `gb_open_commerce_invoice`, `gb_open_commerce_invoice_line`, `gb_open_commerce_invoice_status_event`, `gb_open_commerce_partner_account`, `gb_open_commerce_marketplace_listing`, `gb_open_commerce_commission_rule` |
| v2 idempotency | `gb_open_commerce_idempotency` |
| v3 invoice dispute | `gb_open_commerce_invoice_dispute` |
| v4 invoice dispute adjudication | `gb_open_commerce_invoice_dispute` (columns only, no new table) |

`gb_open_commerce_invoice_dispute` is created by v3 as append-only evidence and is extended by v4 for review and adjudication. v4 is additive and re-runnable: it adds the nullable evidence of a decision, backfills the write timestamp, relaxes the `version` constraint from `= 1` to `> 0`, and replaces the append-only trigger with a column-immutability trigger so only the decision columns can change.

| v4 column | Type | Meaning |
|---|---|---|
| `updated_at` | `TIMESTAMPTZ NOT NULL` | Last write of the adjudication row; backfilled from `recorded_at` and constrained to `>= created_at` |
| `resolution_note` | `TEXT` | Optional decision note, 1–500 characters, no control characters and no 8+ digit runs (same limits as `reason`) |
| `resolution_note_length` | `INTEGER` | `char_length(resolution_note)`, so audits can record the note length without the note |
| `resolution_from_status` | `TEXT` | Dispute status the decision started from (`open` or `underReview`) |

v4 adds two indexes on the same table: `(tenant_id, status, updated_at, id)` for the adjudication queue and `(tenant_id, resolution_outcome, resolved_at)` for decided-dispute reporting. The v3 append-only trigger `gb_open_commerce_in_append_only` is dropped and replaced by `gb_open_commerce_invo_immutable`, which rejects `DELETE` and any change to the tenant, identity, invoice, reason, evidence, actor, idempotency, or timestamp columns while allowing `status`, `resolution_*`, `resolved_at`, `updated_at`, and `version` to move exactly once per legal transition. `FORCE ROW LEVEL SECURITY` on `app.tenant_id` is re-applied, so adjudication writes stay tenant scoped. Application code must apply v3 before v4; the migration coordinator enforces the `requires: [3]` chain and its checksum.

Compliance (current series v1, history `gb_open_compliance_schema_migration`, lock `gb_open_compliance_schema_migration_lock`):

| Table | Purpose |
|-------|---------|
| `gb_open_compliance_data_asset` | data-asset inventory: classification, legal-basis label, residency, linked retention policy |
| `gb_open_compliance_consent_record` | consent grants and withdrawals: channel, scopes, policy version, proof references |
| `gb_open_compliance_privacy_request` | subject requests: type, SLA state and due date, identity-verification status, outcome |
| `gb_open_compliance_retention_policy` | retention policy control record: trigger, action, retention days, legal hold |
| `gb_open_compliance_retention_execution` | append-only retention run evidence: run id, result, recording actor |
| `gb_open_compliance_cross_border_assessment` | transfer assessment: source and destination regions, risk level, mechanisms, validity |
| `gb_open_compliance_vendor` | processor / sub-processor register: role, regions, assessment state, parent vendor |
| `gb_open_compliance_event` | append-only, hash-chained domain event log for every compliance record |

The compliance domain records evidence references and workflow status only. The schema keeps `evidence` / `*_evidence` arrays, `status` / `*_state` values, actor references, and decision metadata, and it states no legal conclusion: whether a deployment satisfies a statute, contract, or regulator is judged outside this schema, not asserted by it. Raw personal information is never persisted — a data subject appears as `subject_ref` plus `subject_count`, identity verification is stored as a status, method, attempt count, and evidence references, and the payload columns are JSONB evidence descriptors rather than copied records. `gb_open_compliance_retention_execution` and `gb_open_compliance_event` reject `UPDATE` and `DELETE` through a trigger, `gb_open_compliance_retention_policy` rejects changes to its control fields, and all eight tables enable forced row-level security keyed on `app.tenant_id`.

## Migration entry points

```ts
// src/auth.ts — single export discovered by `getbrick idaas migrate`
export const openPlatformMigration = {
  dryRun: () => OpenPlatformPersistence.getOpenPlatformMigrations(openPlatformOptions)
    .map((migration) => migration.sql)
    .join("\n\n"),
  run: () => OpenPlatformPersistence.applyVersionedOpenPlatformMigration(executor, openPlatformOptions),
};

export const commerceMigration = {
  dryRun: () => OpenPlatformCommercePersistence.getOpenCommerceMigrations(commerceOptions)
    .map((migration) => migration.sql)
    .join("\n\n"),
  run: () => {
    const migrations = OpenPlatformCommercePersistence.getOpenCommerceMigrations(commerceOptions);
    return new MigrationCoordinator(executor, migrations, {
      tableName: OpenPlatformCommercePersistence.OPEN_COMMERCE_MIGRATION_TABLE,
      lockTableName: OpenPlatformCommercePersistence.OPEN_COMMERCE_MIGRATION_LOCK_TABLE,
      requireTransaction: true,
    }).run(migrations);
  },
};

export const complianceMigration = {
  dryRun: () => OpenPlatformCompliancePersistence
    .getOpenComplianceMigrationDefinition(complianceOptions).sql,
  run: () => OpenPlatformCompliancePersistence.applyVersionedOpenComplianceMigration(executor, complianceOptions),
};

export const migrationIntegration = {
  dryRun: async () => [await oidcMigration.dryRun(), await applicationManagementMigration.dryRun(),
    await openPlatformMigration.dryRun(), await commerceMigration.dryRun(), await complianceMigration.dryRun()].join("\n\n"),
  run: async () => { /* same order, awaits each series */ },
};
```

The runner reads `migrationIntegration` from the auth file and also discovers the individual `oidcMigration`, `applicationManagementMigration`, `openPlatformMigration`, `commerceMigration`, and `complianceMigration` exports — including the `openComplianceMigration` / `openPlatformComplianceMigration` / `compliancePersistenceMigration` spellings — or the raw `getOpenPlatformMigrations` / `applyVersionedOpenPlatformMigration` / `getOpenCommerceMigrations` / `getOpenComplianceMigrationDefinition` / `applyVersionedOpenComplianceMigration` functions of a package re-export. `--dry-run` prints the SQL plan of every series and executes no migration statement. Every series requires a transaction-capable executor, takes its per-series advisory lock, and records the version, name, and checksum; re-running is safe and a changed checksum fails instead of silently re-applying. See `examples/nestjs-postgres` for the executable entry (`src/migrate.ts`) and its `pnpm migrate` / `pnpm migrate:dry-run` scripts.

## Security boundary of the migrated schema

`gb_open_credential` persists `secret_digest` and `secret_reference`; the plaintext credential only ever leaves the issuing call. `gb_open_commerce_invoice` stores money as integer minor units, and `gb_open_commerce_partner_account` stores a `settlement_reference` — bank account numbers, payout instructions, and settlement credentials are not columns of these tables and are not offered as plaintext storage. The `gb_open_compliance_*` tables record evidence references and workflow status, never raw personal information and never a legal conclusion. Migration SQL and the CLI's dry-run output carry schema only: no rows, secrets, or connection strings, and failures are reported redacted with a non-zero exit code.

## Audit

Wire a sink through `createIdaas({ auditSink })`; events (`user.created`, `session.created`, `session.revoked`, ...) are emitted from better-auth database hooks with sensitive fields redacted.
