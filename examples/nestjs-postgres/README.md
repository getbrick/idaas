# @getbrick/example-nestjs-postgres

Minimal Getbrick IDaaS delivery example: NestJS + Postgres + audit.

```bash
pnpm db:up                     # start postgres (docker)
pnpm migrate                   # create gb_idaas_* tables
pnpm test                      # e2e: signup -> cookie -> protected route
```

Entry points:

- `getbrick.config.ts` — IDaaS policy config
- `src/auth.ts` — auth instance (pg pool passthrough)
- `src/app.module.ts` — NestJS wiring (`GetbrickIdaasModule.forRoot`)
- `test/e2e.test.ts` — full loop: sign-up → set-cookie → protected `/me` → 401 without cookie
