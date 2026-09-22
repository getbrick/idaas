# Getbrick IDaaS

Embeddable identity & access platform for Node.js delivery projects.

- Auth: password / SMS code / email / TOTP MFA
- Access: RBAC + org structure + route guards
- Strategy: password & session policies as code (`getbrick.config.ts`)
- Audit: pluggable event sinks
- Delivery: standard tables in *your* database, zero runtime lock-in

> Status: pre-alpha, PRD in [`docs/idaas-prd.md`](docs/idaas-prd.md)

## Planned packages

| Package | Scope |
|---------|-------|
| `@getbrick/idaas-core` | Framework-free kernel: auth, token, rbac, org, policy, audit |
| `@getbrick/idaas-nestjs` | NestJS adapter: guards, decorators, admin module |
| `@getbrick/idaas-ui` | Pluggable login/admin UI components (white-label) |
| `@getbrick/idaas-cli` | `init` wizard, migrations, `upgrade` checks |

## License

MIT
