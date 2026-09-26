# Getbrick IDaaS

Embeddable identity & access platform for Node.js delivery projects.

- Auth: password / SMS code / email / TOTP MFA
- OIDC: external IdP login (RP) and standards-based authorization server (OP)
- Access: RBAC + org structure + route guards
- Strategy: password & session policies as code (`getbrick.config.ts`)
- Audit: pluggable event sinks with recursive secret/PII redaction
- Delivery: standard tables in *your* database, zero runtime lock-in
- Control plane alpha: single-tenant user/role/session/audit read APIs and health endpoints

> Status: v0.1.0 (M1) — core preset, NestJS adapter, CLI, contracts, admin UI primitives, and control-plane alpha shipped

## Quickstart

```bash
pnpm add @getbrick/idaas-core @getbrick/idaas-nestjs better-auth @nestjs/common
pnpm add -D @getbrick/idaas-cli
pnpm exec getbrick idaas init
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

## OIDC

OIDC is configured under `oidc.rp` for login through an external identity provider and under `oidc.op` for issuing tokens to downstream applications.

```ts
export const idaas = defineIdaasConfig({
  baseURL: "https://auth.example.com",
  trustedOrigins: ["https://app.example.com"],
  oidc: {
    rp: {
      enabled: true,
      providers: [{
        providerId: "corp",
        issuer: "https://login.example.com",
        discoveryUrl: "https://login.example.com/.well-known/openid-configuration",
        clientId: "getbrick-rp",
        redirectURI: "https://auth.example.com/api/auth/callback/corp",
        scopes: ["openid", "profile", "email"],
      }],
    },
    op: {
      enabled: true,
      issuer: "https://id.example.com/oidc",
      basePath: "/oidc",
      clients: [{
        clientId: "dashboard",
        redirectUris: ["https://dashboard.example.com/oidc/callback"],
        scopes: ["openid", "profile", "email"],
      }],
    },
  },
});

export const auth = createIdaas({
  config: idaas,
  database,
  oidcRpClientSecrets: { corp: process.env.OIDC_RP_CLIENT_SECRET! },
});
```

Mount the OP endpoints with `GetbrickOidcModule.forRoot({ auth, config: idaas, findUser, clientSecrets })`. The module serves discovery, JWKS, authorization, token, userinfo, introspection, revocation, and RP-initiated logout endpoints below `oidc.basePath`. Authorization uses Authorization Code + S256 PKCE, ID-token verification is mandatory for RP providers, OAuth tokens are encrypted, state cookies are database-backed, and implicit account linking is disabled.

For PostgreSQL deployments, use the bundled adapter and run its migration before starting the provider:

```ts
import { assertPostgresOidcAdapterReady, createPostgresOidcAdapterFactory, migratePostgresOidcSchema } from "@getbrick/idaas-core";

const oidcAdapter = createPostgresOidcAdapterFactory(pool, { namespace: "tenant-a" });
await migratePostgresOidcSchema(pool, { namespace: "tenant-a" });
```

Production OP deployments must provide a persistent `oidc-provider` adapter, a configured JWKS, database-backed sessions, and stable cookie keys. Call `oidcAdapter.cleanup()` periodically to remove expired artifacts. The development defaults use in-memory authorization state and an ephemeral development signing key and must not be used for production.

For a rolling key rotation, configure a JWKS containing the current private signing key and the previous public key, each with a unique `kid`. Keep the previous key published until the longest lifetime of tokens signed with it has elapsed, then remove it. Keep cookie keys stable across restarts and retain old keys while existing OIDC sessions can still be decrypted. Load private keys and cookie keys from a secret manager; never commit them to configuration files. Use `assertPostgresOidcAdapterReady(oidcAdapter)` in a startup or readiness probe before accepting OIDC traffic.

## Application management

Applications are managed as a first-class control-plane resource. An application owns platform channels and OIDC clients; platform records support `web`, `wechat_official_account`, `wechat_open_platform`, `wechat_mini_program`, Alipay/Douyin/QQ/Baidu/Feishu mini-program types, and extensible custom types. The management API is available under `/api/idaas/v1/applications` and uses separate read/write permissions for applications, platforms, and clients.

Use `ApplicationManagementModule` with `InMemoryApplicationRepository` for tests or `SqlApplicationRepository` for PostgreSQL. Run `createApplicationManagementMigrationSql()` before serving the module. The SQL schema stores only a `secret_ref`; resolve the actual credential through a server-side secret manager callback. API responses expose `credentialConfigured`/`hasSecret`, never the credential or secret reference.

`ApplicationPlatformAuthService` and the core platform adapters provide server-side exchanges for WeChat official-account OAuth, WeChat Open Platform website login, and WeChat mini-program `jscode2session`. `createGenericMiniProgramAdapter` supports other platforms through a validated endpoint and response mapper. Returned identities prefer `unionid` and otherwise namespace `openid` with the AppID; provider access tokens and mini-program `session_key` are never returned. Bind the normalized identity to a Better Auth user/account/session in the host application after validating the login state.

Lifecycle writes use dedicated permissions and are optimistic-concurrency protected. `status` is the operational state, `lifecycleStatus` is `active`, `disabled`, `archived`, or `purged`, and `effectiveStatus` also reflects readiness. Resource responses also expose the current ETag as a quoted `ETag` header. Send the returned `version` as `expectedVersion` or send the returned `etag` in `If-Match` when rotating or changing a resource:

```bash
BASE_URL=https://auth.example.com/api/idaas/v1
curl -sS "$BASE_URL/applications" -H 'Authorization: Bearer <admin-token>'
curl -sS -X POST "$BASE_URL/applications/<application-id>/archive" \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'If-Match: "application:<application-id>:4"' \
  -H 'content-type: application/json' -d '{}'
curl -sS -X POST "$BASE_URL/applications/<application-id>/restore" \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'If-Match: "application:<application-id>:5"' \
  -H 'content-type: application/json' -d '{}'
curl -sS -X POST "$BASE_URL/applications/<application-id>/purge" \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'If-Match: "application:<application-id>:6"' \
  -H 'content-type: application/json' \
  -d '{"idempotencyKey":"release-2026-01"}'
```

Platform and client secret changes use `rotate-secret` and `revoke-secret`; ordinary `PATCH` requests cannot change credential references. The admin primitives render readiness checks, lifecycle/effective status, versions/ETags, masked secret state, and external identities without rendering secret references or provider tokens. All control-plane failures use one envelope:

```json
{
  "error": {
    "code": "CONFLICT",
    "message": "Application resource version changed"
  },
  "requestId": "request-123"
}
```

Managed OIDC clients can be projected into the OP with `ApplicationOidcClientStore` plus `createDynamicOidcClientAdapter`; configure `GetbrickOidcModule.forRoot({ clientStore })`. Static clients remain supported, but static configuration takes precedence if the same `client_id` is registered in both places. The admin UI exports `ApplicationList`, `ApplicationPlatformList`, and `ApplicationClientList` for management consoles.

What you get out of the box:
- `gb_idaas_*` Better Auth tables mapped into your database (migration via `getbrick idaas migrate`); application-management tables use `createApplicationManagementMigrationSql()`
- audit events (`user.created`, `session.created`, `session.revoked`, ...) with recursive secret and personal-data redaction
- global NestJS guard by default, explicit `@Public()` escape hatch, and `@RequireOrganization()` fail-closed context
- session guard + `@CurrentUser()` / `@CurrentSession()` / `@GetbrickRoles()`
- TOTP 2FA, lockout policy, session policy — all from `getbrick.config.ts`
- RBAC: role inheritance, wildcard permissions (`project:write:own`), data scope — see [docs/rbac.md](docs/rbac.md)
- open-platform domain event relay: outbox claim/lease, optional multi-instance leader lease, delivery metrics snapshot and runbook — see [docs/open-platform-operations.md](docs/open-platform-operations.md)
- open-platform production rollout order, database/RLS roles, readiness gates and pre-launch checklist — see [docs/deployment.md](docs/deployment.md)
- admin plugin: role management, ban, impersonation via better-auth admin endpoints
- organizations: multi-tenant orgs with member/invitation tables (`gb_idaas_organization`, `gb_idaas_member`, `gb_idaas_invitation`), member roles merged into effective permissions
- white-label React UI: `@getbrick/idaas-ui` — themed `AuthForm` / `AuthCard` / `SignOutButton`, plus `@getbrick/idaas-ui/admin` control-plane primitives
- SMS OTP: `features.phoneNumber` with a pluggable `smsSender` — send OTP, verify, sign-up-on-verification, phone-number sign-in and password reset
- CI gate: Node 20/22/24 and PostgreSQL 16 run `pnpm check`

## Examples

- [examples/nestjs-postgres](examples/nestjs-postgres) — NestJS + real Postgres + control-plane alpha, e2e verified (migration + signup + guarded routes + health/401)

## Control plane alpha

`@getbrick/idaas-control-plane` provides a single-tenant management boundary for a private deployment. It currently exposes authenticated read APIs for capabilities, users, roles, sessions and audit events, plus public liveness/readiness checks:

- `GET /api/idaas/v1/capabilities`
- `GET /api/idaas/v1/users`
- `GET /api/idaas/v1/users/:id`
- `GET /api/idaas/v1/roles`
- `GET /api/idaas/v1/sessions`
- `GET /api/idaas/v1/audit-events`
- `GET /api/idaas/v1/audit-events/:id`
- `GET /api/idaas/v1/system/info`
- `GET /api/idaas/v1/health/live`
- `GET /api/idaas/v1/health/ready`

Use `ControlPlaneModule.forRoot` as the IDaaS module in a control-plane deployment, provide a repository implementation, and pass the generated role graph:

```ts
import { buildRoleGraph } from "@getbrick/idaas-core";
import { ControlPlaneModule, InMemoryControlPlaneRepository } from "@getbrick/idaas-control-plane";

@Module({
  imports: [
    ControlPlaneModule.forRoot({
      auth,
      rbac: buildRoleGraph(idaas),
      repository: new InMemoryControlPlaneRepository(),
    }),
  ],
})
export class AppModule {}
```

The bundled repository is an in-memory reference implementation for wiring and tests. A production deployment should provide a persistent repository implementation before enabling customer data.

## Production profile

Production mode fails fast unless the deployment provides a strong secret, HTTPS `baseURL`, trusted origins, closed public signup, and required email verification:

```ts
export const idaas = defineIdaasConfig({
  profile: "production",
  appName: "Private App",
  baseURL: "https://auth.example.com",
  secret: process.env.GETBRICK_IDAAS_SECRET,
  trustedOrigins: ["https://app.example.com"],
  registration: {
    publicSignUp: false,
    requireEmailVerification: true,
  },
  audit: {
    redactPersonalData: true,
  },
});
```

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
| `@getbrick/idaas-nestjs` | NestJS adapter: guards, decorators, org context, OIDC OP endpoints |
| `@getbrick/idaas-ui` | White-label React login UI (theme tokens, CSS vars) |
| `@getbrick/idaas-cli` | `init`, `doctor`, and local migration runner |
| `@getbrick/idaas-contracts` | Shared control-plane DTOs, error codes and pagination contracts |
| `@getbrick/idaas-control-plane` | Single-tenant control-plane NestJS module and repository contracts |

## License

MIT
