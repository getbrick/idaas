# 生产部署清单（Open Platform）

本文是 `@getbrick/idaas-control-plane` 开放平台（open platform）**上线前的可执行清单**，覆盖部署顺序、数据库与 RLS、运行时门禁、relay 领导者、密钥、egress、可观测性与回滚。

与 [docs/open-platform-operations.md](open-platform-operations.md) 的分工：

- 本文只回答「上线时按什么顺序做什么、每步的验收标准是什么、失败了怎么退」。
- 运维手册回答「relay 怎么跑、指标字段含义、积压与死信怎么查、安全边界的原理」。本文出现的积压、死信、指标细节一律以运维手册为准，不在此重复。
- 数据库连接与备份/恢复的通用流程见 [docs/database.md](database.md)。

文中所有版本号、配置项、错误码与接口路径均对应仓库中已存在的常量与实现，未包含规划中的能力。

相关代码：

| 关注点 | 位置 |
|--------|------|
| 模块装配与启动门禁 | `packages/control-plane/src/open-platform/open-platform-module.ts` |
| 服务就绪聚合 | `packages/control-plane/src/open-platform/service.ts`（`isReady()`） |
| outbox 端口与内存实现 | `packages/control-plane/src/open-platform/events.ts` |
| relay、租约端口与内存租约 | `packages/control-plane/src/open-platform/events-relay.ts` |
| SQL outbox、SQL 租约表（`gb_open_relay_lease`）、RLS/租户上下文 | `packages/control-plane/src/open-platform/persistence/events.ts`、`persistence/adapter.ts` |
| 迁移定义与版本号 | `packages/control-plane/src/open-platform/persistence/migration.ts` |
| webhook 端点策略与签名 | `packages/control-plane/src/open-platform/webhook.ts` |
| 事件查询与重放接口 | `packages/control-plane/src/open-platform/http/open-platform-domain-events.controller.ts` |
| 可运行的部署/压测示例 | `examples/nestjs-postgres/` |

## 1. 部署顺序

严格按下列顺序推进。每一步都有「通过标准」，未通过不要进入下一步——后面每一步都会假定前一步已经完成。

### 1.1 依赖安装

1. 固定工具链：Node `>=20.19.0`、pnpm `10.33.2`（见根 `package.json` 的 `engines` / `packageManager`）。
2. 安装 workspace 依赖并构建产物：

   ```bash
   pnpm install --frozen-lockfile
   pnpm build
   ```

3. 校验：`pnpm check`（等价于 `pnpm typecheck && pnpm test && pnpm build`）在 CI 通过。`pnpm build` 必须包含 `tsc -p tsconfig.build.json`，因为运行时示例与压测工具读取的是各包的 `dist`。

**通过标准**：`pnpm build` 退出码 0，`packages/*/dist/index.js` 与 `packages/control-plane/dist/open-platform/index.js` 存在。

### 1.2 数据库角色与 RLS

在**任何迁移之前**建好角色并授权（见第 3 节）。顺序颠倒会导致迁移以超级用户身份执行，从而绕过 RLS 校验并让 `isReady()` 判定为未就绪。

### 1.3 迁移

按系列依次执行，每个系列独立加锁、独立记录历史。以下为仓库中实际定义的版本号：

| 系列 | 版本 | 迁移名（`migration.ts` 常量值） | 关键产物 |
|------|------|------------------------------|----------|
| open platform（core） | v1 | `open-platform-persistence-foundation` | `gb_open_tenant` … `gb_open_idempotency` |
| | v2 | `open-platform-management-audit-webhook` | `gb_open_webhook`、`gb_open_webhook_delivery`、`gb_open_audit_event` |
| | v3 | `open-platform-webhook-delivery-lease` | `gb_open_webhook_delivery` 的 `lease_id` / `lease_expires_at` |
| | v4 | `open-platform-domain-event-outbox` | `gb_open_domain_event`（outbox） |
| commerce | v1 | `open-platform-commerce-persistence-foundation` | `gb_open_commerce_*` 基础表 |
| | v2 | `open-platform-commerce-idempotency-store` | `gb_open_commerce_idempotency` |
| | v3 | `open-platform-commerce-invoice-dispute-evidence` | `gb_open_commerce_invoice_dispute` |
| | v4 | `open-platform-commerce-invoice-dispute-adjudication` | 发票争议裁决相关表/列 |
| compliance | v1 | `open-platform-compliance-persistence-foundation` | `gb_open_compliance_*`（含 `gb_open_compliance_event`） |

对应 API 与历史表（示例 `examples/nestjs-postgres/src/migrate.ts` 是可运行范例）：

- core：`getOpenPlatformMigrations()` / `applyVersionedOpenPlatformMigration()`，历史表 `gb_open_schema_migration`，锁表 `gb_open_schema_migration_lock`。
- commerce：`getOpenCommerceMigrations()` 交给 `MigrationCoordinator` 驱动（该系列没有单函数 apply 入口），历史表 `gb_open_commerce_schema_migration`，锁键 `getbrick-open-commerce-schema`，命名空间 `open-platform-commerce`。
- compliance：`getOpenComplianceMigrationDefinition()` / `applyVersionedOpenComplianceMigration()`，历史表 `gb_open_compliance_schema_migration`，锁键 `getbrick-open-compliance-schema`，命名空间 `open-platform-compliance`。

执行要求：

- 必须传 `requireTransaction`（或 `requireTransactions: true`）。`MigrationCoordinator` 会把每个版本包在事务里；示例 e2e 断言 `migration.atomic === true`。任一版本失败时该版本整体回滚，历史表不会记录它。
- 必须先 dry-run 打印 SQL 计划，确认没有 `CREATE DATABASE`、没有删表/改类型语句，再实际执行：

  ```bash
  pnpm --filter @getbrick/example-nestjs-postgres migrate:dry-run   # 只打印
  pnpm --filter @getbrick/example-nestjs-postgres migrate
  ```

- 多实例并发部署时依靠每个系列的锁表串行化，重复执行是幂等的（版本 + `checksum` 校验，已应用的版本会被跳过）。

**通过标准**：三个系列的历史表里出现上表的全部版本，且 `applied + skipped` 等于定义数量（core 为 4、commerce 为 4、compliance 为 1）。以 `getOpenPlatformMigrations()` / `getOpenCommerceMigrations()` / `getOpenComplianceMigrationDefinition()` 的实际返回为准，不要把版本数量写死在运维脚本里。

### 1.4 密钥管理接入

在应用实例启动前接入外部密钥管理（见第 6 节）。`mode: "production"` 下 `OpenPlatformService` 构造时会校验 `secretProvider.readiness`，内存实现 `productionReady` 为 `false`，不接入会直接启动失败——这是期望行为，不要用 `allowInMemoryInProduction` 绕过。

### 1.5 egress 策略

在应用实例开始接收流量前落地出网策略（见第 7 节）。库内 `assertOpenPlatformWebhookEndpoint` 校验是纵深防御，不能替代网络层隔离。

### 1.6 应用实例

1. 以非超级用户数据库角色启动（见第 3 节）。
2. 注入 `OpenPlatformPersistence.createSqlOpenPlatformRepositories({ adapter, mode, tenantId, requireTransactions: true })`。
3. 生产模式装配 `OpenPlatformModule.forRoot({ platform, commerce, compliance })`，并把同一个核心发布器显式传给 commerce / compliance（`OpenPlatformModule` 不会隐式共享发布器）。
4. 保持 HTTP 探针可用（第 4 节）。

**通过标准**：`OpenPlatformService.isReady()` 返回 `ready: true`、`storage: "persistent"`、`distributed: true`、`events: true`；Nest `app.init()` 不抛错。

### 1.7 relay 领导者

1. 单独一个 Deployment 运行 relay，与 HTTP 流量分离。
2. 注入 `OpenPlatformPersistence.SqlOpenPlatformRelayLease`（`productionReady === true`），`mode: "production"`。
3. 多副本时所有副本必须使用同一个 `leaseKey`（默认 `getbrick:open-platform:outbox-relay`）。
4. 确认 additive v5 迁移（`open-platform-relay-lease`，表 `gb_open_relay_lease`）已执行；`SqlOpenPlatformRelayLease.isReady()` 依赖该表。租约状态存在表里而非连接上，**不需要**为 relay 单独预留固定连接。

**通过标准**：standby 副本的 `relay.snapshot()` 显示 `leader: false`、`skipped` 递增、`claimed: 0`；leader 副本 `leader: true` 且 `claimed` 增长。细节见运维手册第 2.2、2.3 节。

### 1.8 冒烟与回滚

1. 冒烟：创建租户 → 创建一个应用/客户端 → 确认 `gb_open_domain_event` 出现 `pending` 记录 → 确认 `relay.snapshot().delivered` 增长 → 确认 `GET /api/open/v1/domain-events` 能查到该事件且 `status` 变为 `published`。
2. 回滚：应用层回滚到上一个镜像即可，**不要**回滚数据库（迁移只追加，见 4.3）。relay 回滚前先从调度摘除，让它在途 tick 结束并释放租约。

## 2. 运行时门禁

### 2.1 fail-closed 行为

`OpenPlatformProviderReadiness`（`open-platform-module.ts` 内的 `OnModuleInit` provider，在 `OpenPlatformProviderModule` 与 `OpenPlatformHttpModule` 两个分支都注册）在 `onModuleInit` 中调用 `service.isReady()`：

- `ready === true` → 放行。
- `readiness.events === false` → 抛 `[getbrick-idaas] open platform domain event outbox is not ready`。
- 其他情况 → 抛 `[getbrick-idaas] open platform storage is not ready`。
- `isReady()` 自身抛错时按未就绪处理（`.catch(() => undefined)`）。

含义：**存储或 outbox 不可用时，Nest 启动直接失败**，不会进入「半可用」状态。relay 侧同理：`OpenPlatformEventRelayLifecycle.onModuleInit` 在 `relay.start()` 失败时抛 `[getbrick-idaas] open platform event relay did not start: <message>`；`production` 模式下 relay 还会额外要求 `publisher.productionReady`、`outbox.productionReady`、`lease.productionReady` 全部为 `true`。

`OpenPlatformService.isReady()` 聚合的子项：仓储、幂等存储、密钥提供器、审计、webhook，以及 `events`（= 事件链路就绪；`eventsEnabled: false` 时恒为就绪）。`ready` 还额外要求生产模式下仓储 / 幂等 / 密钥三者都是 persistent + distributed。

### 2.2 探针建议

| 探针 | 判定 | 失败含义 |
|------|------|----------|
| liveness | 进程存活即可，**不要**包含数据库检查 | 数据库抖动不应触发重启 |
| readiness | `service.isReady().ready === true`，建议缓存 5–10s 避免每次探测都打库 | 摘流量，不重启 |
| 启动门禁 | 直接依赖 `app.init()` 成功（见 2.1），不额外实现 | 门禁失败即启动失败 |

`/api/idaas/v1/health/live` 与 `/api/idaas/v1/health/ready` 是 control-plane 的既有端点；开放平台就绪状态目前**没有**内置 HTTP 端点，需要部署方在运维端点里自行映射 `service.isReady()`。

### 2.3 迁移失败与回滚

- 迁移是**只追加**的：core v3 声明 `additive: true, requires: [2]`，core v4 声明 `additive: true, requires: [3]`，commerce v2/v3/v4 依次声明 `requires: [1]` / `requires: [2]` / `requires: [3]`。仓库中没有 down migration，也不提供版本回退 API。
- 每个版本在独立事务中执行：失败只回滚该版本，历史表不落记录，修复后可直接重跑。
- 已 `applied` 的版本带 `checksum`；**不要**手工改写 `gb_open_schema_migration` / `gb_open_commerce_schema_migration` / `gb_open_compliance_schema_migration` 的内容，改了会让后续执行判定为漂移。
- 迁移对既有表的变更只有 `ADD COLUMN IF NOT EXISTS` 与 `CREATE INDEX IF NOT EXISTS`（如 v3 的 `lease_id` / `lease_expires_at`），回退应用版本后这些列保留即可，不需要处理。
- `gb_open_domain_event`、`gb_open_audit_event`、`gb_open_usage` 上有 `BEFORE DELETE` / `BEFORE UPDATE` 触发器禁止改写与删除载荷（`gb_open_domain_event_immutable`、`gb_open_domain_event_payload_guard`）。**不要**为了「清理测试数据」直接 `DELETE`，需要清理时先在独立数据库验证。
- 应用回滚顺序：先停 relay（摘调度 → 等在途 tick 结束 → 释放租约），再回滚 HTTP 实例，最后才考虑数据库。

## 3. 数据库与 RLS

### 3.1 角色要求

- 应用与 relay 使用的角色必须是**非超级用户且不具 `BYPASSRLS`**。`OpenPlatformSqlRuntime.isReady()` 会查询 `pg_roles` 的 `rolsuper` / `rolbypassrls`，命中即判定未就绪（仅在 `requireRls` 生效时检查；共享模式强制要求）。禁止用超级用户连接运行 control-plane。
- 迁移可以使用具备 DDL 权限的角色，但**不要**让应用长期持有 DDL 权限；`gb_open_domain_event` 的追加不可变触发器意味着应用角色也不应被授予该表的 `DELETE`。
- `OpenPlatformSqlRuntime` 通过 executor 的 `transaction` 能力判断是否支持事务；传入的适配器若只有 `query` 而没有 `transaction`，`requireTransactions: true` 会直接判定未就绪。装配 SQL 仓储时把带 `transaction` 的适配器整体传入（形如 `{ adapter, mode, tenantId, requireTransactions: true }`），不要只把 `query` 函数拆出来传。

### 3.2 账号分离

| 账号 | 用途 | 权限 |
|------|------|------|
| 迁移账号 | 执行版本化迁移 | DDL + 迁移历史/锁表写权限；仅在发布流水线使用 |
| 应用账号 | HTTP 实例读写业务数据 | 业务表 `SELECT`/`INSERT`/`UPDATE`；outbox 无 `DELETE` |
| relay 账号 | 投递循环 | 与应用账号同库同表，但独立凭据，便于单独限流与审计；`gb_open_domain_event` 的 `INSERT`/`UPDATE` |
| 只读运维账号 | 排障查询 | 仅 `SELECT`；不得调用 `POST /api/open/v1/domain-events/retry`（该接口按租户校验 webhook 的 `record` 权限，只读账号会被拒绝） |

### 3.3 `app.tenant_id` 与租户模式

- 租户列默认 `tenant_id`；租户上下文通过事务内 `SELECT set_config('app.tenant_id', $1, true)` 设置，由 `OpenPlatformSqlRuntime.withTransaction()` / `withTenantContext()` 完成，调用方不要自己拼 `set_config`。
- 三种租户模式（`TenantMode`）：`shared`（同表 + RLS，强制要求事务与 RLS）、`dedicated`（每租户独立 schema/库）、`fixed`（单租户固定 `tenantId`）。开放平台 outbox 表在三种模式下都应启用并 `FORCE ROW LEVEL SECURITY`。
- 迁移 SQL 只在 `includeRls: true`、`requireRls: true` 或 `mode === "shared"` 时附带 RLS 语句。因此**若目标环境用 `shared` 模式，必须显式确认 RLS 策略已生成**（`USING` 与 `WITH CHECK` 同时存在，`relrowsecurity` 与 `relforcerowsecurity` 均为真），否则 `isReady()` 会判定未就绪。
- 领导者租约（`gb_open_relay_lease`）是数据库级全局对象，不带租户列、不参与 RLS，不区分租户：同一数据库只应有一组 relay 使用同一个 `leaseKey`。
- 跨租户聚合视图（某段时间失败最多的租户等）应由离线作业或日志聚合生成，不要通过放宽接口作用域实现。

## 4. Relay 部署

配置项与默认值（全部来自 `events-relay.ts` 的常量）：

| 配置 | 默认 | 范围 / 说明 |
|------|------|-------------|
| `mode` | — | 生产必须显式 `production` |
| `leaseKey` | `getbrick:open-platform:outbox-relay` | 长度 ≥ 8；同一库内区分环境时各环境用不同 key |
| `leaseTtlMs` | 30 000 | 1 000 – 3 600 000；应明显大于一轮 tick 的最长预期耗时 |
| `ownerId` | 自动生成 `relay_leader_<uuid>` | 仅用于日志与指标归因，不参与互斥 |
| `intervalMs` | 1 000 | 10 – 3 600 000 |
| `jitterMs` | 0 | 0 – 600 000 |
| `batchSize` | 50 | 1 – 500 |
| `tenantPageSize` / `maxTenantsPerTick` | 100 / 10 000 | 上限 10 000 |

- **单活 + 多副本 standby**：每轮 tick 开头 `acquire`，取不到就记 `skipped` 并继续按间隔调度；取到则投递并在 `finally` 中 `release`。租约获取失败（抛错或返回非法状态）按失败关闭处理，计入 `errors` 且以 `scope: "lease"` 上报，绝不退化为「无租约也投递」。
- **租约是表行，不是会话锁**：`SqlOpenPlatformRelayLease` 用一条 `INSERT ... ON CONFLICT DO UPDATE ... WHERE` 原子抢占 `gb_open_relay_lease`，`expires_at` 由数据库持有，因此 `leaseTtlMs` 是真实的服务端过期时间。`acquire` / `release` 落在不同连接或不同实例都不会泄漏；实例崩溃后到期即可被接管，不依赖其连接断开。可用 `holder(leaseKey)` 查询当前持有者。
- **指标接入**：仓库内没有内置 exporter，需要部署方周期性调用 `relay.snapshot()` 并映射为指标。字段含义、告警条件与导出建议见运维手册第 3 节；快照刻意不含租户标识与事件载荷，可直接作为指标标签来源。
- **积压与死信入口**：一律走既有运维接口，不要直接改库。
  - 查询：`GET /api/open/v1/domain-events?status=failed&limit=100`（单页上限 100，可用 `sequence` 游标翻页），CLI `getbrick open-platform events:list`。
  - 重放：`POST /api/open/v1/domain-events/retry`（`Idempotency-Key` 必填，`limit` 上限 100），CLI `getbrick open-platform events:retry`。
  - CLI 可用 `OPEN_PLATFORM_BASE_URL`、`OPEN_PLATFORM_TENANT_ID`、`OPEN_PLATFORM_TOKEN`（或 `IDAAS_*` / `GETBRICK_*` 前缀变体）提供连接与令牌。
  - 排查步骤、死信重放注意事项与常见原因见运维手册第 4 节。

## 5. 密钥与凭证

- webhook 签名密钥由 `OpenPlatformWebhookSecretPort` 提供（`issue` / `rotate` / `resolve` / `revoke`）。默认的进程内内存实现 `productionReady` 为 `false`，生产必须替换为 Vault / KMS 等外部实现，并在实现里把 `readiness.ready()` 接到真实的密钥后端探活上。
- 落库只存引用：webhook 记录保存 `signing_secret_reference`（形如 `vault://open-platform/webhook/<webhookId>/<version>`）与 `secret_version`；凭证表 `gb_open_credential` 保存 `secret_digest`（`sha256:<64 hex>`）与 `secret_reference`。**禁止明文落库**。
- 签名固定 `hmac-sha256`（`OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM`），请求头 `X-Webhook-Signature` 与 `X-Webhook-Timestamp`，另有 `X-Webhook-Secret-Version`。接收方应按 `timestampToleranceSeconds`（默认 300s）校验时间戳容差防重放。
- 轮换产生新版本号，旧版本可用于过渡期验签；`secretVersion` 记录在 webhook 上。轮换与撤销都要走既有接口，不要手工改库。
- **禁止**在日志、指标标签、错误消息中输出：签名密钥、密钥引用解析结果、完整请求头、访问令牌、数据库连接串。示例 `src/migrate.ts` 的 `safeMigrationError()` 给出了现成的脱敏做法（命中 `postgres://`、`password`、`token` 等模式时统一替换为一句通用失败信息）。CLI 的错误信息同样不回显凭证明文。
- relay 的 `leaseKey`、`ownerId`、数据库口令属于基础设施配置，同样不得进入对外可见的指标标签。

## 6. Egress

**egress 防火墙 / service mesh 出网策略是必须项，不是可选项。**

- 库内校验（`assertOpenPlatformWebhookEndpoint` 与 `OpenPlatformWebhookEndpointPolicy`：`requireHttps`、`allowLoopbackHttp`、`allowPrivateNetwork`、`allowHosts`、`allowedPorts`、`allowedCidrs`、`blockedCidrs`、`blockedHosts`、`requireResolution`、`resolver`）属于**应用层纵深防御**，在写入订阅时拒绝明显不合法的 URL。
- 它**不是网络隔离的替代品**：DNS 重绑定、TOCTOU、代理、IPv6、重定向等绕过面只能靠网络层阻断。仓库内目前没有独立的 egress 专章文档（`docs/open-platform-egress.md` 尚不存在），因此这里明确：**以库内校验为纵深防御，出网隔离由基础设施兜底。**
- 基础设施必须做到：默认拒绝；仅放行已登记的外部目标；按需限制端口；阻断内网地址段与云厂商元数据端点（含 `169.254.0.0/16`）；对重定向后的目标同样生效。
- 不要因为「库里已经校验过」而放开出网策略，也不要仅依赖 egress 策略而跳过库内校验。原理与更多绕过面见运维手册第 5.1 节。

## 7. 可观测性

### 7.1 日志字段

允许输出：实例/Pod 标识、`leaseKey`、`ownerId`、租户标识（平台内部日志）、`requestId`、`relay.snapshot()` 的聚合计数、错误 `code`、错误 `scope`、事件 `eventType` 与 `resourceType`。

禁止输出：任何凭证与密钥（含签名密钥、访问令牌、数据库连接串）、密钥引用解析结果、PII、事件载荷 `data`、webhook endpoint 完整 URL 与请求/响应正文。事件数据本身已由 `sanitizeOpenPlatformDomainEventData` 过滤敏感键，但排障时不要为了「看清数据」绕过该过滤。

relay 的错误通过 `onError` 回调获取，结构为 `{ scope, tenantId?, code, message, occurredAt }`；`message` 已做控制字符清理与 256 字符截断，但仍不要把 `tenantId` 写进对外可访问的指标标签。

### 7.2 告警项

| 告警 | 依据 | 严重度建议 |
|------|------|-----------|
| outbox 积压 | `gb_open_domain_event` 中 `pending` / `delivering` 数量或最老 `created_at` 超过阈值 | 高 |
| 死信率 | `relay.snapshot().deadLettered` 增长，或 `dead_lettered` 占比超过阈值 | 高 |
| relay 错误 | `snapshot().errors` 增长；`lastErrorCode` 为 `OPEN_PLATFORM_EVENT_RELAY_ERROR` 通常指向租户解析器 / 租约端口 / outbox 访问异常 | 高 |
| 无活跃 leader | `running === true` 但长期 `leader === false`，或 `now - lastSuccessAt` 超阈值 | 高 |
| 全部退化为 standby | `skipped` 持续高速增长而 `claimed` 不变 | 中 |
| readiness 失败 | 启动门禁报错（`open platform storage is not ready` / `open platform domain event outbox is not ready`）或就绪探针转红 | 高 |

注意 `lastSuccessAt` 只在「无错误完成」的轮次更新，投递失败体现在 `failed` 计数上；积压与死信的排查步骤见运维手册第 4 节。

## 8. 上线前检查清单

依赖与迁移：

- [ ] Node `>=20.19.0`、pnpm `10.33.2`；`pnpm install --frozen-lockfile && pnpm build` 退出码 0。
- [ ] `pnpm check` 在 CI 通过。
- [ ] 三个迁移系列的 dry-run SQL 已人工审阅，无破坏性语句。
- [ ] core v1–v4、commerce v1–v4、compliance v1 全部记录在各自的历史表里。
- [ ] 迁移以事务执行（`atomic`），失败版本已回滚且历史表无残留。

数据库：

- [ ] 应用与 relay 使用非超级用户、无 `BYPASSRLS` 的角色。
- [ ] 只读运维账号与 relay 账号分离；outbox 表未授予 `DELETE`。
- [ ] `app.tenant_id` 由 `OpenPlatformSqlRuntime` 在事务内设置，未手工拼接。
- [ ] 若使用 `shared` 模式：RLS 已生成且 `relforcerowsecurity` 为真，策略同时含 `USING` 与 `WITH CHECK`。

运行时门禁：

- [ ] `mode: "production"`，未使用 `allowInMemoryInProduction` 绕过检查。
- [ ] `service.isReady()` 返回 `ready: true`、`storage: "persistent"`、`distributed: true`、`events: true`。
- [ ] `app.init()` 成功；liveness 不含数据库检查；readiness 映射了 `service.isReady()`。
- [ ] 生产模式未注册开发授权实现（`createDevelopmentOpenPlatformAuthorization`）。

Relay：

- [ ] relay 独立 Deployment，多副本 standby；`lease.productionReady === true`。
- [ ] 所有副本 `leaseKey` 一致；`leaseTtlMs` 大于最长 tick 预期耗时。
- [ ] relay 租约使用固定连接，确认 `release` 与 `acquire` 落在同一会话。
- [ ] `relay.snapshot()` 已接入指标；第 7.2 节的告警已配置。
- [ ] 优雅停机：摘调度 → `stop()` → 释放租约。

密钥与 egress：

- [ ] 密钥管理已接入 Vault / KMS；`secretProvider.readiness.ready()` 探活真实后端。
- [ ] 抽查数据库与日志：无明文密钥、无密钥引用解析结果、无 PII、无事件载荷。
- [ ] egress 策略已落地（默认拒绝 + 白名单 + 阻断元数据地址段 + 覆盖重定向）。

演练：

- [ ] 冒烟链路通过：写入 → `pending` → relay `delivered` 增长 → `published` → `GET /api/open/v1/domain-events` 可见。
- [ ] 故障演练：杀掉 leader 后 standby 在 `leaseTtlMs` 内接管；未出现重复投递。
- [ ] 积压演练：人为拉高积压后按运维手册第 4.1 节恢复，确认告警触发过。
- [ ] 预发环境跑过一次 `examples/nestjs-postgres` 的 outbox 压测（见其 README 的 "Outbox load test"），`deliveries.duplicates` 为 0。

## 9. 已知限制

- **无大规模压测数据**：批量、租户分页与租约逻辑目前只有单元测试与并发确定性测试覆盖（`packages/control-plane/test/open-platform-outbox-contention.test.ts`），加上示例包里的手动压测工具；没有多实例、长时间运行的生产量级数据。首次上线前必须在预发环境做积压与故障切换演练。
- **无跨地域多活**：领导者租约是单活模型，没有跨地域选主、就近投递或双活写入合并；跨地域部署会退化为「一个区域持锁、其余 standby」，并受数据库单点延迟影响。
- **relay 租约依赖数据库 advisory lock**：数据库不可用或连接被中间件代理时，所有实例退化为 standby（`skipped` 递增、`errors` 增长），投递暂停但不丢事件。
- **会话锁与连接池耦合**：`acquire` / `release` 无法保证同一会话，需要严格释放语义时必须提供固定连接。
- **租约 TTL 无法在 tick 之外续约**：relay 只在 tick 边界获取与释放，超长 tick 应调大 `leaseTtlMs`。
- **指标不含租户维度、也没有内置 exporter**：`snapshot()` 只有聚合计数，租户级排查依赖既有查询接口与日志聚合；导出需部署方自行实现。
- **`holder()` 仅内存租约实现可用**：SQL advisory lock 无法查询当前持有者，`snapshot().leaseOwnerId` 只反映本实例最近一次交互结果。
- **`gb_open_domain_event` 追加不可变**：触发器禁止删除与改写载荷，测试与压测数据无法就地清理，需使用独立数据库。
- **迁移只追加**：没有 down migration，应用回滚不应回滚数据库（见 2.3）。
- **无内置 egress 文档与策略实现**：出网隔离依赖基础设施（见第 6 节）。
