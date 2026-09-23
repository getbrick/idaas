# Getbrick IDaaS

Embeddable identity & access platform for Node.js delivery projects.

- Auth: password / SMS code / email / TOTP MFA
- Access: RBAC + org structure + route guards
- Strategy: password & session policies as code (`getbrick.config.ts`)
- Audit: pluggable event sinks
- Delivery: standard tables in *your* database, zero runtime lock-in

> Status: v0.1.0 (M1) — core preset + NestJS adapter + CLI shipped

## Quickstart

```bash
pnpm add @getbrick/idaas-core @getbrick/idaas-nestjs better-auth @nestjs/common
npx getbrick idaas init
```

Minimal setup:

```ts
// getbrick.config.ts
import { defineIdaasConfig } from "@getbrick/idaas-core";
export const idaas = defineIdaasConfig({ appName: "My App" });

// auth.ts
import { createIdaas } from "@getbrick/idaas-core";
import { idaas } from "./getbrick.config.js";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
export const auth = createIdaas({ config: idaas, database: drizzleAdapter(db) });

// app.module.ts
import { GetbrickIdaasModule } from "@getbrick/idaas-nestjs";
@Module({ imports: [GetbrickIdaasModule.forRoot({ auth })] })
export class AppModule {}
```

What you get out of the box:
- `gb_idaas_*` tables mapped into your database (migration via `getbrick idaas migrate`)
- audit events (`user.created`, `session.created`, `session.revoked`, ...) with sensitive-field redaction
- session guard + `@CurrentUser()` / `@GetbrickRoles()`
- TOTP 2FA, lockout policy, session policy — all from `getbrick.config.ts`

## Planned packages

| Package | Scope |
|---------|-------|
| `@getbrick/idaas-core` | Framework-free kernel: auth, token, rbac, org, policy, audit |
| `@getbrick/idaas-nestjs` | NestJS adapter: guards, decorators, admin module |
| `@getbrick/idaas-ui` | Pluggable login/admin UI components (white-label) |
| `@getbrick/idaas-cli` | `init` wizard, migrations, `upgrade` checks |

## License

MIT
