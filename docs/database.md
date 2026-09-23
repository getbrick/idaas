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

Table names are configurable via `defineIdaasConfig({ tables: { overrides: { user: "..." } } })`.

## Audit

Wire a sink through `createIdaas({ auditSink })`; events (`user.created`, `session.created`, `session.revoked`, ...) are emitted from better-auth database hooks with sensitive fields redacted.
