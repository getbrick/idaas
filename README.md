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
- RBAC: role inheritance, wildcard permissions (`project:write:own`), data scope — see [docs/rbac.md](docs/rbac.md)
- admin plugin: role management, ban, impersonation via better-auth admin endpoints
- organizations: multi-tenant orgs with member/invitation tables (`gb_idaas_organization`, `gb_idaas_member`, `gb_idaas_invitation`), member roles merged into effective permissions
- white-label React UI: `@getbrick/idaas-ui` — themed `AuthForm` / `AuthCard` / `SignOutButton`
- SMS OTP: `features.phoneNumber` with a pluggable `smsSender` — send OTP, verify, sign-up-on-verification, phone-number sign-in and password reset

## Examples

- [examples/nestjs-postgres](examples/nestjs-postgres) — NestJS + real Postgres, e2e verified (migration + signup + guarded routes)

## SMS OTP

```ts
export const idaas = defineIdaasConfig({
  appName: "My App",
  features: { phoneNumber: true },
  phoneNumber: { otpLength: 6, otpExpiresInSeconds: 300, signUpOnVerification: true },
});

export const auth = createIdaas({
  config: idaas,
  database: db,
  smsSender: async ({ phone, code }) => {
    await mySmsProvider.send({ to: phone, text: `Your code is ${code}` });
  },
});
```

Enabled endpoints: `sendPhoneNumberOTP`, `verifyPhoneNumber`, `signInPhoneNumber`, `requestPasswordResetPhoneNumber` / `resetPasswordPhoneNumber`.

## Packages

| Package | Scope |
|---------|-------|
| `@getbrick/idaas-core` | Framework-free kernel: auth, RBAC, organizations, policy, audit |
| `@getbrick/idaas-nestjs` | NestJS adapter: guards, decorators, org context |
| `@getbrick/idaas-ui` | White-label React login UI (theme tokens, CSS vars) |
| `@getbrick/idaas-cli` | `init` wizard, migrations, `upgrade` checks |

## License

MIT
