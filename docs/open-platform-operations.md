# 开放平台 Outbox Relay 运维手册

本文面向运行 `@getbrick/idaas-control-plane` 开放平台（open platform）域事件投递链路的运维人员。内容全部对应仓库中已存在的代码、配置项与 HTTP 接口，不包含尚未实现的规划项；尚未实现或未验证的部分集中列在「已知限制」。

相关代码：

- 投递循环：`packages/control-plane/src/open-platform/events-relay.ts`（`OpenPlatformEventRelay`）
- 领导者租约端口与内存实现：同文件（`OpenPlatformRelayLeasePort`、`InMemoryOpenPlatformRelayLease`）
- SQL 租约表实现：`packages/control-plane/src/open-platform/persistence/events.ts`（`SqlOpenPlatformRelayLease`），迁移见同目录 `migration.ts`（additive v5 `open-platform-relay-lease`，表 `gb_open_relay_lease`）
- outbox 端口与投递器：`packages/control-plane/src/open-platform/events.ts`
- 迁移：`packages/control-plane/src/open-platform/persistence/migration.ts`

## 1. 组件与数据流

1. **写入 outbox**：开放平台领域服务在一次业务操作成功后调用事件发布器写入 outbox 表 `gb_open_domain_event`（可通过 `options.tables.domainEvent` 改名）。事件内容为追加不可变：迁移中的 `gb_open_domain_event_immutable`（禁止 DELETE）与 `gb_open_domain_event_payload_guard`（禁止修改事件主体字段）触发器保证载荷不被改写。事件类型与动作取值来自 `@getbrick/idaas-contracts` 的事件目录契约。
2. **claim / lease**：relay 每轮按租户分页扫描 outbox，把可投递事件交给发布器。发布器先 `claim`：把记录置为 `delivering`，写入 `attempt`、`lease_id`、`lease_expires_at`。SQL 实现的 claim 条件包含「状态为 `pending`/`failed`，或 `delivering` 但租约已过期」，因此崩溃实例遗留的 `delivering` 记录会在租约到期后被其他实例接手，不会永久卡住。
3. **webhook 投递**：claim 成功后交给事件 sink（`OpenPlatformEventSink`）。默认 sink 调用 webhook 服务的域事件分发，逐个订阅投递并记录 `webhookDelivery`。签名使用 `hmac-sha256`（`OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM`），签名头为 `X-Webhook-Signature`，时间戳头为 `X-Webhook-Timestamp`。
4. **重试 / 死信**：投递失败时事件回到 `failed` 并写入 `next_attempt_at`（指数退避，上限 300s）；`attempt` 达到 `max_attempts`（默认 `OPEN_PLATFORM_DOMAIN_EVENT_MAX_ATTEMPTS = 5`）或 sink 报告死信时进入 `dead_lettered`，之后不再被 relay 自动处理。webhook 投递自身也有独立的重试与死信状态（默认最多 5 次，退避上限 60s）。

状态机：`pending → delivering → published`，失败分支 `delivering → failed → delivering`，终止分支 `delivering → dead_lettered`。

relay 的循环行为：固定间隔（`intervalMs`，默认 1000ms）加抖动（`jitterMs`）触发一轮 tick；同一实例内不会重叠执行（`runOnce` 并发调用会合并为同一轮）；`stop()` 会等待在途 tick 结束后再返回。租户分页由 `maxTenantsPerTick` 与 `tenantPageSize` 控制，游标在整轮走完后自动回到起点。

## 2. 部署与扩缩容

### 2.1 单实例

不注入租约端口时，relay 不做领导权判定，行为与引入本特性之前完全一致（构造签名与既有测试均未改变）。适用于单副本部署或本地/测试环境。

### 2.2 多实例：领导者租约

多副本部署必须注入 `OpenPlatformRelayLeasePort`：

```ts
import {
  OpenPlatformPersistence,
  createOpenPlatformEventRelay,
} from "@getbrick/idaas-control-plane/open-platform";

const lease = new OpenPlatformPersistence.SqlOpenPlatformRelayLease(sqlRuntime);

const relay = createOpenPlatformEventRelay({
  publisher,
  outbox,
  lease,
  mode: "production",
  intervalMs: 1_000,
  jitterMs: 500,
  leaseTtlMs: 30_000,
});
```

语义：

- 每个 tick 开始前先 `acquire`；未取到则本轮记为 `skipped`（`claimed = 0`），不做任何投递，随后照常按间隔调度下一轮。
- 取到则执行本轮投递，并在 `finally` 中 `release`，因此正常情况下任意时刻只有一个实例在投递。
- 实例崩溃时不会 `release`，但 `gb_open_relay_lease.expires_at` 到期后其他实例可直接接管，不依赖崩溃实例的数据库连接断开。默认 `leaseTtlMs = 30_000`，可配置范围 1000ms–3600000ms。
- 租约获取失败（抛出异常或返回非法状态）按失败关闭处理：本轮不投递，计入 `errors` 并以 `scope = "lease"` 上报，不会退化为「无租约也投递」。
- `leaseKey` 默认 `getbrick:open-platform:outbox-relay`（`OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY`）。同一数据库内若要区分环境（例如 staging 与 production 共库），可为各环境设置不同的 `leaseKey`；不设置时所有实例必须使用同一 key。
- `ownerId` 默认自动生成（`relay_leader_<uuid>`），仅用于日志与指标归因，不参与互斥判定；可显式设置为 Pod 名等可读标识。
- `production` 模式下若注入的租约端口 `productionReady !== true`，relay 构造/启动直接失败。`InMemoryOpenPlatformRelayLease` 的 `productionReady` 为 `false`，因此不能用于生产多实例。

`SqlOpenPlatformRelayLease` 的 SQL 形状：

```sql
INSERT INTO "gb_open_relay_lease" ("lease_key", "owner_id", "acquired_at", "expires_at", "updated_at")
VALUES ($1, $2, $3::timestamptz, $4::timestamptz, $3::timestamptz)
ON CONFLICT ("lease_key") DO UPDATE
  SET "owner_id" = EXCLUDED."owner_id", "acquired_at" = EXCLUDED."acquired_at",
      "expires_at" = EXCLUDED."expires_at", "updated_at" = EXCLUDED."updated_at"
  WHERE "gb_open_relay_lease"."expires_at" <= $3::timestamptz
     OR "gb_open_relay_lease"."owner_id" = EXCLUDED."owner_id"
RETURNING "owner_id" AS "ownerId", "expires_at" AS "expiresAt";

DELETE FROM "gb_open_relay_lease" WHERE "lease_key" = $1 AND "owner_id" = $2
```

要点：

- 租约是一行数据，由 `gb_open_relay_lease`（additive v5 迁移 `open-platform-relay-lease`）承载，`lease_key` 为主键。`expires_at` 由数据库持有，**`leaseTtlMs` 是真实的服务端过期时间**，不是客户端视图。
- `acquire` 是一条 `INSERT ... ON CONFLICT DO UPDATE ... WHERE` 的原子语句：只有当该 key 不存在、已过期，或本实例本来就是持有者时才会写入并返回行；否则返回 0 行且不报错。因此多个实例并发抢锁时必然只有一个成功，不需要事务或会话级互斥。
- **不依赖会话**。锁状态存在表里而不是连接上，所以 `acquire` 与 `release` 落在不同连接、不同实例都不会泄漏；`release` 只删除自己持有的行，非持有者调用返回 `false`。
- 实例崩溃时不会 `release`，但行仍在，`expires_at` 到期后其他实例凭 `acquire` 直接接管，无需等待连接断开。
- `renew` 只在 `owner_id` 仍是自己时延长；租约已被他人接管时返回 `held = false`，不会误延长。
- 该实现提供 `holder()`，可直接查询当前持有者与到期时间；快照中的 `leaseOwnerId` / `leaseExpiresAt` 来自数据库而非本实例视图。
- 该实现通过 `OpenPlatformSqlRuntime` 执行，沿用既有 RLS/租户上下文约定（`requireRls` 时会包事务并设置 `app.tenant_id`），不绕过安全模式。
- 该表是数据库全局对象，不带租户列，也不参与 RLS：relay 领导权按数据库判定，不按租户判定。

### 2.3 扩缩容建议

- 先按「单活 + 多副本 standby」部署：副本数可以随时增减，实际只有持租约的副本产生投递流量，其余副本 `skipped` 递增。
- 扩缩容对吞吐的提升有限（单活设计），主要收益是故障切换。若需要更高吞吐，先提高 `batchSize`（默认 50，上限 500）、`maxTenantsPerTick`（默认 10000）与 `intervalMs`，再评估多分区/分片键设计（当前没有内置）。
- 建议把 relay 放在独立 Deployment（与 HTTP 流量分离），便于单独限速、单独伸缩与单独观察 `skipped`。
- `leaseTtlMs` 应明显大于「一轮 tick 的最长预期耗时」，否则极端情况下会出现两个实例短暂同时持领导权；即使如此，事件级 claim 租约（`lease_expires_at`）仍是第二道防线，避免同一事件被重复认领。
- 优雅停机：先从负载均衡/调度摘除再调用 `stop()`（Nest 模块的 `onModuleDestroy` 会自动调用），relay 会等待在途 tick 结束并释放租约。

## 3. 指标快照

`relay.snapshot()` 返回只读、冻结对象，字段仅包含计数与时间戳，不含租户标识、事件载荷、endpoint、凭证或任何 PII：

| 字段 | 类型 | 含义 |
|------|------|------|
| `mode` | string | 运行时模式（`development` / `test` / `production`） |
| `enabled` | boolean | 是否启用（生产模式默认启用） |
| `running` | boolean | 当前是否在运行 |
| `leader` | boolean | 最近一次租约交互中本实例是否取得领导权；未注入租约端口时恒为 `true` |
| `leaseKey` | string \| null | 生效的租约键；未注入租约端口时为 `null` |
| `leaseOwnerId` | string \| null | 最近一次租约交互观察到的持有者（实例标识），未知时为 `null` |
| `leaseExpiresAt` | string \| null | 上述持有者的租约到期时间（ISO 字符串） |
| `ticks` | number | 累计执行轮数（含被跳过的轮次） |
| `started` / `stopped` | number | 累计启动 / 停止次数 |
| `tenants` | number | 累计处理的租户 flush 次数 |
| `tenantErrors` | number | 累计租户级 flush 异常次数 |
| `claimed` | number | 累计取出并进入投递流程的 outbox 事件数 |
| `delivered` | number | 累计成功投递（状态 `published`）的事件数 |
| `failed` | number | 累计投递失败、已重新排期的事件数 |
| `retried` | number | 累计重试投递（`attempt > 0`）的事件数 |
| `deadLettered` | number | 累计进入死信的事件数 |
| `skipped` | number | 累计跳过数：未取得领导权的轮次（每轮记 1）+ 本轮未到 `next_attempt_at` 或 `delivering` 租约未到期的事件 + 未取得事件认领的事件 |
| `errors` | number | 累计错误数（租户解析、租户 flush、租约、tick 级异常） |
| `lastRunAt` | string \| null | 最近一轮结束时间（ISO 字符串） |
| `lastSuccessAt` | string \| null | 最近一轮「无错误完成」的时间（ISO 字符串）；被跳过的轮次不更新 |
| `lastErrorAt` | string \| null | 最近一次错误时间（ISO 字符串） |
| `lastErrorCode` | string \| null | 最近一次错误码（领域错误码，未知错误为 `OPEN_PLATFORM_EVENT_RELAY_ERROR`） |

`relay.metrics()` 保持原有返回结构（`published` 等字段名不变），仅新增 `claimed`；`OpenPlatformEventRelayTick` 同样新增 `claimed`，便于按轮核对。

### 3.1 导出建议

仓库内没有内置 Prometheus/OpenTelemetry exporter，指标需要由部署方自行暴露。常见做法（属于建议，不是现成功能）：

- 在运维端点或 `/metrics` 处理器中周期性调用 `relay.snapshot()`，把计数映射为 counter/gauge，把 `lastRunAt`/`lastSuccessAt`/`lastErrorAt` 映射为 timestamp gauge。
- 建议的告警条件：
  - `running == true && leader == false` 持续超过若干个 `intervalMs` → 没有活跃 leader，检查租约与数据库连接。
  - `now - lastSuccessAt` 超过阈值 → relay 停止成功推进（注意 `lastSuccessAt` 只在无错误轮次更新，投递失败会体现在 `failed` 计数上）。
  - `skipped` 持续高速增长且 `claimed` 不变 → 多实例全部退化为 standby。先确认各实例 `leaseKey` 一致；再用 `holder(leaseKey)` 查看当前持有者与 `expires_at`：若 `expires_at` 已过期却仍无人取得，说明 `gb_open_relay_lease` 迁移未执行。
  - `deadLettered` 增长 → 需要人工介入（见第 4 节）。
  - `errors` 增长且 `lastErrorCode` 为 `OPEN_PLATFORM_EVENT_RELAY_ERROR` → 租户解析器、租约端口或 outbox 访问异常。
- 建议同时记录 `relay.isRunning()` 与 `relay.isReady()`，前者反映循环状态，后者反映 publisher/outbox 依赖就绪情况。
- 事件级错误通过 relay 的 `onError` 回调获取，结构为 `{ scope, tenantId?, code, message, occurredAt }`；该回调可接入既有日志系统，但不要把 `message` 原样写入对外可访问的指标标签。

### 3.2 按租户的失败可见性

快照刻意不含租户维度数据。按租户排查请使用既有查询接口（见 4.2 / 4.3），或消费 `onError` 回调中的 `tenantId` 在日志系统内聚合；对外暴露时只应输出聚合计数。

## 4. 运维手册

### 4.1 outbox 积压排查

1. 看 relay 快照：`claimed` 是否在增长、`skipped` 是否异常偏高、`errors`/`lastErrorCode` 是否有异常。
2. 确认 relay 在运行：`running == true`；`mode` 与部署预期一致（`development`/`test` 需显式 `enabled: true` 才会自启）。
3. 按状态统计积压（既有查询接口，需要平台运维权限，作用域为单租户）：

   ```bash
   getbrick open-platform events:list --status failed --limit 100
   getbrick open-platform events:list --status dead_lettered --limit 100
   ```

   或直接使用 HTTP 接口 `GET /api/open/v1/domain-events?status=failed&limit=100`（可加 `sequence` 游标翻页，单页上限 100）。
4. 库内核对（需只读账号，遵守第 5 节的 RLS 约定）：

   ```sql
   SELECT status, count(*), min("next_attempt_at") FROM gb_open_domain_event
   GROUP BY status ORDER BY status;
   ```

5. 常见原因与处理：
   - `pending` 长期不动：relay 未运行/未启用，或租户解析器未覆盖该租户（`tenantIds`/自定义 `tenants` 覆盖范围）。
   - `delivering` 长期不动：claim 租约未过期，等待 `lease_expires_at` 到期后由下一轮接手；若持续存在，检查是否有实例持有领导者租约却卡在投递中。
   - `failed` 堆积：`next_attempt_at` 未到属正常退避；持续增长说明下游 webhook 不健康，先修下游再考虑重放。
   - `dead_lettered` 堆积：需要人工重放（4.2）。
6. 积压严重时的临时手段（按顺序使用，并注意副作用）：先扩 `batchSize` 与 `maxTenantsPerTick`；再缩短 `intervalMs`；最后才用 `events:retry` 定点重放。不要通过调大 `maxAttempts` 掩盖下游故障。

### 4.2 死信重放

死信重放必须走既有运维入口 `POST /api/open/v1/domain-events/retry`（CLI：`getbrick open-platform events:retry`），不要直接改库：

```bash
curl -X POST "$BASE_URL/api/open/v1/domain-events/retry" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"limit": 100}'
```

要点：

- 直接调用 HTTP 接口时 `Idempotency-Key` 必填；相同 key 与相同请求体会返回首次结果并带 `idempotency-replayed: true`，相同 key 换用不同请求体会被拒绝（`OPEN_PLATFORM_IDEMPOTENCY_KEY_REUSED`）。CLI/SDK 在未显式指定时自动生成 key，重放脚本若要自行控制幂等窗口，请显式传入新的 `--idempotency-key`。
- 请求体支持 `eventType` 与 `limit`（`limit` 上限 100），可只重放某类事件；不允许跨租户，租户由请求上下文决定。
- 该接口走与 relay 相同的发布路径，因此同样受认领条件约束：只处理 `pending`/`failed` 且已到 `next_attempt_at` 的事件；`published` 与 `dead_lettered` 会被跳过，对已进入死信的事件直接重放不会改变其状态，需要平台侧先显式恢复为可重试状态。响应中 `deadLettered: true` 表示该事件再次耗尽尝试。
- 权限要求高于只读：接口按租户校验 webhook 的 `record` 权限，纯只读的运维账号调用会返回禁止访问。
- 重放前务必先确认下游 webhook 已恢复，否则只是把死信快速再写一遍。
- 重放会产生真实外呼流量，请按与 webhook 投递相同的速率约束操作，必要时先小批量 `limit` 试跑。

CLI 走同一接口，`--base-url`、`--tenant` 与访问令牌可由 `OPEN_PLATFORM_BASE_URL`、`OPEN_PLATFORM_TENANT_ID`、`OPEN_PLATFORM_TOKEN` 等环境变量提供：

```bash
getbrick open-platform events:retry --event-type application.created --limit 20
```

### 4.3 租户维度排查

- 查询：`GET /api/open/v1/domain-events?tenantId=<id>&status=failed&limit=100`（`tenantId` 必须与请求上下文租户一致，否则返回租户不匹配错误）。
- 响应中的每条记录包含 `eventId`、`type`、`resource.type`、`resource.id`、`status`、`attempt`、`occurredAt`，以及失败时的 `errorCode` 与 `nextAttemptAt`——足以定位到具体事件而不暴露其他租户数据。
- 跨租户聚合视图（例如某段时间内失败最多的租户）应由平台侧离线作业或日志聚合生成，不要通过放宽接口作用域实现。
- webhook 侧的投递明细（响应码、重试次数、失败原因）通过 webhook 订阅与投递记录查询，签名密钥不在任何查询响应中出现。

### 4.4 发票争议审核与裁决

争议的提出、审核、裁决和撤回各自是独立写入口，`update` 权限不能推进审核或裁决。CLI 与 HTTP 走同一套路由、幂等键和审计口径；`decide` / `withdraw` 属于高风险写操作，必须显式给出裁决依据 `--reference`，`--idempotency-key` 可控重放窗口（未显式指定时由 SDK 生成）。

```bash
# 发起争议：SDK `billing.invoices.dispute(invoiceId, { reason })` → POST /api/open/v1/billing/invoices/{invoiceId}/disputes（CLI 暂无对应子命令）
# 查询某张账单的全部争议（路径参数是账单 ID，列表按状态过滤并支持游标分页）
getbrick open-platform billing:disputes:list <invoice-id> --status open --limit 50 --json

# 查看单条争议（争议 ID）
getbrick open-platform billing:disputes:get <dispute-id> --json

# 开始审核：已提出 -> 审核中
getbrick open-platform billing:disputes:review <dispute-id> --invoice-id <invoice-id> --idempotency-key review-2026-02-01 --json

# 裁决：审核中 -> 已接受 / 已驳回
getbrick open-platform billing:disputes:decide <dispute-id> --invoice-id <invoice-id> \
  --outcome accepted --reference resolution://case-0001 --note "已开具红字发票" --json

# 撤回：已提出 / 审核中 -> 已撤回
getbrick open-platform billing:disputes:withdraw <dispute-id> --invoice-id <invoice-id> \
  --reference withdrawal://case-0001 --json
```

要点：

- 对应 HTTP 路由：`GET /api/open/v1/billing/invoices/{invoiceId}/disputes`、`GET /api/open/v1/billing/disputes/{disputeId}`（别名 `GET /api/open/v1/billing/invoice-disputes/{disputeId}`）、`POST .../disputes/{disputeId}/review`、`POST .../disputes/{disputeId}/decisions`、`POST .../disputes/{disputeId}/withdrawal`。
- 三个写操作都要求 `Idempotency-Key`；相同 key 与相同请求体返回首次结果并带 `replayed: true`，相同 key 换用不同请求体会被拒绝（`OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED`）。
- 裁决与撤回是终态写入：对已裁决的争议再次推进会返回 `OPEN_PLATFORM_COMMERCE_INVALID_STATE_TRANSITION`（HTTP 409），不会覆盖既有裁决。
- 领域事件：审核与撤回发 `commerce_dispute.status_changed`，已接受 / 已驳回发 `commerce_dispute.decided`；重放不重复产生事件。争议终态不自动改写账单状态，账单回到待支付或作废仍走账单自身的状态迁移。
- 排障时不要直接改库推进状态：`gb_open_commerce_invoice_dispute` 只允许裁决列变化（见 `docs/database.md` 的 commerce v4），其余列由触发器保护，绕过服务层会同时丢失审计与事件。
- 审计动作 `invoice.dispute.review` / `invoice.dispute.decide` / `invoice.dispute.withdraw` 只记录账单与争议标识、原状态、目标状态、裁决结果与说明长度；争议原因、裁决依据与裁决说明正文不进入审计与事件负载。

## 5. 安全边界

### 5.1 出网（egress）必须由基础设施兜底

- 库内的 endpoint 校验（`assertOpenPlatformWebhookEndpoint` 与 `OpenPlatformWebhookEndpointPolicy`：`requireHttps`、`allowLoopbackHttp`、`allowPrivateNetwork`、`allowHosts`、`allowedPorts`、`requireResolution`）属于**应用层防御纵深**，用于在写入时拒绝明显不合法的 URL。
- 它**不是网络隔离的替代品**：DNS 重绑定、TOCTOU、代理与 IPv6/重定向等绕过面只能靠网络层阻断。因此 webhook 出网必须由基础设施 egress firewall / service mesh 出网策略兜底：仅允许访问已登记的外部目标、按需限制端口与解析路径、默认拒绝内网与元数据地址段（含 `169.254.0.0/16` 与云厂商 metadata 端点）、对重定向后的目标同样生效。
- 不要因为「库里已经校验过」而放开出网策略；也不要仅依赖 egress 策略而跳过库内校验。

### 5.2 凭证与签名密钥

- webhook 签名密钥由 `OpenPlatformWebhookSecretPort` 提供（`issue` / `rotate` / `resolve`），默认实现是进程内内存实现，`productionReady` 为 `false`；生产必须接入外部密钥管理（Vault/KMS 等），密钥仅以引用形式落库（形如 `vault://open-platform/webhook/<webhookId>/<version>`）。
- 密钥只在创建/轮换时向调用方返回一次，查询接口不返回密钥明文；日志与指标不得输出密钥、签名或完整请求头。
- 轮换产生新版本号，旧版本可用于过渡期验签；`secretVersion` 与 `signingSecretReference` 记录在 webhook 记录上。
- 签名算法固定为 `hmac-sha256`（版本 `v1`），接收方应校验 `X-Webhook-Timestamp` 的时间戳容差以防重放（服务端侧容差由 webhook 服务的 `timestampToleranceSeconds` 控制）。
- relay 自身的租约键、ownerId 与数据库凭证属于基础设施配置，不得写入对外可见的指标标签或错误消息。

### 5.3 RLS 与数据库角色

- 开放平台表默认启用并 `FORCE ROW LEVEL SECURITY`，策略以 `current_setting('app.tenant_id', true)` 比对租户列（`USING` 与 `WITH CHECK` 同时生效）；`OpenPlatformSqlRuntime` 在 `requireRls` 下于事务内 `set_config('app.tenant_id', ...)` 后再执行语句。
- 应用数据库角色必须是非超级用户且不具 `BYPASSRLS`：`OpenPlatformSqlRuntime.isReady()` 会查询 `pg_roles` 校验 `rolsuper`/`rolbypassrls`，命中即判定未就绪。禁止用超级用户连接运行 control-plane。
- 租户模式（`TenantMode`）共三种：`shared`（所有租户同表，隔离依赖 RLS 与应用层租户校验）、`dedicated`（每租户独立 schema/库）、`fixed`（单租户固定 `tenantId`）。开放平台 outbox 在这三种模式下都要求启用并 `FORCE ROW LEVEL SECURITY`。
- 运维只读账号应与 relay 运行账号分离：只读账号仅授予 `SELECT`，relay 账号需要 outbox 表的 `INSERT/UPDATE`（不允许 `DELETE`，迁移已用触发器禁止删除）。
- leader 租约是数据库全局对象，不区分租户：`gb_open_relay_lease` 不带租户列，同一数据库只应有一组 relay 使用同一个 `leaseKey`。

## 6. 事件来源与开关

`gb_open_domain_event` 目前有三个写入来源，全部经过同一个发布器与同一个租户上下文校验，因此共享同一个 outbox 与 relay：

1. **开放平台核心域**：`OpenPlatformService` 在应用、客户端、凭证、API 产品、订阅等生命周期写入成功时发布。
2. **商业化域**：`CommerceDomainService`，事件源 `commerce/events.ts`，覆盖上架商品、伙伴账户、佣金规则、发票与发票争议。
3. **合规域**：`ComplianceDomainService`，事件源 `compliance/outbox.ts`，覆盖数据资产、同意记录、隐私请求、留存策略、跨境评估与供应商。

事件名来自 `@getbrick/idaas-contracts` 的 `OPEN_PLATFORM_DOMAIN_EVENT_CATALOG`（core + commerce + compliance 共 22 个资源），动作取值受 `OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS` 约束；`resourceType` 必须是已注册实体类型（核心实体、commerce 的 `marketplaceListing`/`partnerAccount`/`commissionRule`/`invoice`/`invoiceDispute`、compliance 的 `dataAsset`/`consentRecord`/`privacyRequest`/`retentionPolicy`/`crossBorderAssessment`/`vendor`），否则写入被拒绝并抛校验错误。

开关语义（三个域不同，配置时不要混淆）：

- 核心域：由 `OpenPlatformService` 的事件配置决定。
- 商业化域：传入 `eventPublisher` 即默认开启，`eventsEnabled: false` 显式关闭。
- 合规域：必须同时传 `eventPublisher` 且 `eventsEnabled: true` 才开启（合规载荷涉及个人数据信息治理，默认关闭）。

`OpenPlatformModule` 不会隐式共享发布器：需要统一投递时，在组合模块配置里把核心发布器显式传给两个子模块，保证只有一个 outbox：

```ts
OpenPlatformModule.forRoot({
  platform: { service, contextIssuer, resolver },
  commerce: { eventPublisher: service.eventPublisher },
  compliance: { eventPublisher: service.eventPublisher, eventsEnabled: true },
});
```

载荷安全：三个域都只发布非敏感运营元数据，经 `sanitizeOpenPlatformDomainEventData` 与各域脱敏函数过滤；合规域额外禁止主体标识、证据、备注与自由文本。排障时不要为了「看清数据」而放宽过滤，必要时用 `outbox.list` 之外的离线作业与审计记录。

## 7. 已知限制

- **未做大规模并发压测**：批量、租户分页与租约逻辑只有单元测试覆盖，没有多实例、大数据量、长时间运行的压测数据；首次上线前建议在预发环境做积压与故障切换演练。
- **无内置多活 / 跨地域调度**：领导者租约是单活模型，没有跨地域的选主、就近投递或双活写入合并；跨地域部署会退化为「一个区域持有租约、其余区域 standby」，并受数据库单点延迟影响。
- **依赖数据库租约**：互斥完全依赖 `gb_open_relay_lease` 表（默认实现）。数据库不可用或连接被中间件代理时，所有实例都会退化为 standby，投递暂停但不丢事件。注意此时 `acquire` 抛异常会计入 `errors`；而「正常但没抢到」只累加 `skipped`，`errors` 不涨，仅凭 `errors = 0` 不能判断 relay 健康，必须同时看 `claimed` 与 `skipped` 的比值。
- **租约 TTL 无法续约到 tick 之外**：relay 只在 tick 边界获取与释放租约，不会在 tick 执行中途续租（`renew` 未被调用）。单轮投递超过 `leaseTtlMs` 时其他实例可接管，而本实例仍在投递；投递正确性由 outbox 的 `claim` 租约兜底，但会产生重复扫描，因此超长 tick（大量租户或慢下游）应调大 `leaseTtlMs`。
- **指标不含租户维度**：快照仅有聚合计数，租户级排查依赖既有查询接口与日志聚合。
- **无内置指标导出器**：需要部署方自行把 `snapshot()` 接入指标系统。
