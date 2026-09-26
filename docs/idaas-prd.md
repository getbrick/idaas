# Getbrick IDaaS — PRD v0.1

- **One-liner**: 全开源的嵌入式 Node.js 身份认证与权限平台，以 NestJS 库形态交付，随项目私有化，靠更新订阅和托管服务盈利
- **Target users**: 使用 Node/NestJS 交付项目的开发公司（及独立开发者）
- **Core promise**: 开箱正确、交付无痕（无黑盒/无外部依赖）、持续安全（可订阅更新）
- **Competitive gap**: Keycloak（重）、Casdoor（浅）、自写认证（乱）——卡位"轻量且深"

## 1. Key decisions（已锁定）

| 决策 | 结论 |
|------|------|
| 内核形态 | **嵌入式代码库**（非独立服务），随客户项目交付与私有化 |
| 内核基座 | **Better Auth（MIT）**：认证/会话/MFA/OTP/管理/组织由上游覆盖；预设层（getbrick/审计/策略/权限增强/表映射）为我们所有 |
| 技术栈 | TypeScript / Node，首个适配器 **NestJS** |
| 开源策略 | **全开源（MIT）+ 商业可用**；收入 = 更新订阅 + 托管服务 + 未来平台分润 |
| 组织/包名 | GitHub org `getbrick`，npm scope `@getbrick/*` |
| 数据归属 | 用户数据不搬家：在客户数据库生成标准表（迁移脚本），无黑盒 |
| 配置方式 | 统一根配置 `getbrick.config.ts`，按产品分节（`idaas: defineIdaasConfig({...})`），进 git 可 review，AI 友好 |
| 命名规范 | 统一 Getbrick 命名空间：配置 `getbrick.config.ts`、环境变量 `GETBRICK_*`、CLI `getbrick <product> <cmd>`、表前缀 `gb_<产品>_<实体>`（产品间隔离） |

## 2. Feature list

### P0（v1.0）
| 模块 | 功能 |
|------|------|
| 认证 | 账密登录/注册、手机验证码、邮箱验证、找回密码、JWT 签发/刷新/撤销、单点登出 |
| MFA | TOTP（可选开启） |
| 权限 | RBAC（用户/角色/权限点）、组织架构（树形）、接口级鉴权守卫、数据权限注解（预留接口） |
| 策略 | 密码强度、登录失败锁定、会话时长/并发策略（`getbrick.config.ts` 声明式配置） |
| 审计 | 登录/登出/授权变更/管理操作事件，可插拔存储（默认落项目库） |
| 集成 | NestJS Guard/装饰器、迁移脚本自动建表、`getbrick.config.ts` |
| 管理台 | 可插拔 NestJS 管理模块：用户/角色/组织/审计 API + 基础管理页（白标配置） |
| CLI | `getbrick idaas init` 向导（生成配置+迁移）、`getbrick idaas upgrade` 升级检查（CLI 单命名空间，产品做子命令，未来产品零新增成本） |
| 分发 | npm 发 + 文档站 + 3 个示例工程（NestJS 全功能 / 最小接入 / 管理台演示） |

### P1（生态化）
- 微信/企业微信/钉钉扫码；LDAP 只读同步（规避服务化短板）
- 管理台前端完整版、用户自助中心
- 多租户内核（SaaS 化开发公司直接可用）
- 风控：异地/IP 信誉登录提醒
- 数据权限实现（行级规则引擎）
- 补丁订阅体系（私源 + 付费通道）

### P2（终局衔接）
- sidecar 形态：跨应用 SSO 网关（弥补嵌入式短板）
- 多语言客户端（Java/Go 对接 sidecar）
- 能力目录官方发送器（短信/邮件）
- 平台托管形态

## 3. Kernel architecture（基于 Better Auth 的分层设计）

> **决策：内核不自研安全原语，以 [Better Auth](https://github.com/better-auth/better-auth)（MIT）为基础层**——它覆盖认证/会话/MFA/OTP/管理功能/组织与访问控制，且支持自定义表名映射。我们的产品价值在交付包装、审计、策略、白标管理台与订阅体系，全部为 Better Auth 射程之外的差异化层。

### 3.1 分层

```
┌────────────────────────────────────────────────────┐
│ @getbrick/idaas-nestjs   适配器层                    │
│   Guard/装饰器/管理模块（封装社区适配器并加固）           │
├────────────────────────────────────────────────────┤
│ @getbrick/idaas-core     预设层（我们的核心）         │
│   安全默认值：锁定/会话/密码策略（getbrick.config 映射） │
│   gb_idaas_* 表名/字段映射（better-auth modelName）   │
│   审计：databaseHooks → 统一审计事件 → Sink          │
│   权限增强插件：角色继承/菜单按钮权限点/数据范围        │
├────────────────────────────────────────────────────┤
│ better-auth（上游）+ 插件                              │
│   emailAndPassword/phoneNumber/emailOTP/2FA/         │
│   admin/organization + 社区 NestJS 适配器             │
└────────────────────────────────────────────────────┘
```

### 3.2 架构铁律

1. **预设层隔离上游**：客户代码只 import `@getbrick/*`，不直接接触 better-auth 原生 API——上游 2.0 破坏性变更时只改预设层，必要时 fork
2. **版本策略**：预设层锁定 better-auth 版本区间；每个安全补丁带回归用例（订阅价值证据链）
3. **表名映射不可黑盒**：客户库中所有表可审计、可自定义映射
4. **审计全量挂 hooks**：登录/授权变更/管理操作经统一事件模型脱敏后落 Sink（DB/文件/HTTP）

### 3.3 深度安全设计（v0.2）

#### 3.3.1 状态机与不变量

平台登录和 OIDC RP-initiated flow 都采用一次性、租户化、绑定化的事务模型：

```text
ISSUED
  -> RESERVED(lease_owner, lease_expires_at)
  -> CLAIMED
  -> EXCHANGING
  -> SUCCEEDED
       -> FAILED
ISSUED/RESERVED
  -> EXPIRED | REVOKED
```

必须保持以下不变量：

- `state`、`code`、`ticket` 只以 hash 或一次性 reference 存储；成功消费后不可恢复。
- claim/consume 必须原子校验 `tenantId + applicationId + platformId + clientKind + binding`。
- 任何序列化失败、未知 binding、未知 client audience 都 fail closed；禁止把任意 request 对象作为缓存 key。
- `returnTo` 只能由服务端事务恢复，callback 不得重新选择目标。
- 外部 provider code 只执行一次；超时或暂时失败不能把已消费事务恢复为可用状态。
- session refresh 使用 CAS/version 或分布式锁；旧 reference 只能重放为同一个幂等结果或被拒绝。

#### 3.3.2 OIDC 交互边界

```text
AUTHORIZATION_REQUESTED
  -> INTERACTION_ISSUED(route_uid + cookie_uid + request_hash)
  -> AUTH_REQUIRED
  -> AUTHENTICATED(auth_time, amr, acr)
  -> CONSENT_REQUIRED
  -> CONSENTED(exact scope/claim set)
  -> CODE_ISSUED
  -> CODE_CONSUMED
```

- URL interaction UID、interaction cookie UID、持久化 interaction UID 必须相同。
- `prompt=none` 不得触发交互或自动 consent；缺少认证返回 `login_required`，缺少授权返回 `consent_required`。
- `prompt=login`/`max_age` 必须经过宿主明确的重新认证，不得用旧 host session 直接完成。
- `prompt=consent` 必须经过显式 consent decision；生产宿主应把 resolver 绑定到 CSRF/Origin 校验的用户交互，库不把缺省值当作同意。
- RP 生产配置必须固定 `issuer`、HTTPS discovery/UserInfo endpoint，并校验 discovery metadata 的 issuer、签名算法、nonce、`iss/aud/azp/exp` 与 UserInfo `sub`。
- RP logout 只有在 provider 完成参数、hint、redirect 和用户确认后才清理 Better Auth 本地 session；无效 logout 请求不得产生副作用。

#### 3.3.3 UniApp BFF 通道协议

BFF 明确区分两个不可互换的结果：

| 通道 | exchange 结果 | 后续认证 |
|------|--------------|----------|
| H5/web | `204 + Set-Cookie(HttpOnly; Secure; SameSite)` | 只通过服务器 cookie |
| App/native/mp | JSON opaque session reference | 只通过 opaque reference |

- H5 不得把 bearer session 写入 `uni.storage`，也不得把 cookie 模式伪装成 JSON session。
- native 不得接收 provider token、Better Auth session secret 或 `session_key`。
- BFF state claim 一次性绑定 `clientId + clientType + redirectUri + bindingHash`；错误 binding 不得烧掉合法 state。
- 生产 BFF state store、host adapter、session service 必须持久化、跨实例共享并提供 readiness。
- H5 跨源部署需要精确 CORS allowlist、显式 `withCredentials`、CSRF/Origin 校验和受控 SameSite 策略；默认推荐同源反向代理。

#### 3.3.4 租户与持久化部署矩阵

| 模式 | 适用 | 必须具备 | 当前生产门槛 |
|------|------|----------|--------------|
| `fixed` | 单租户私有化 | 持久 repository、state/session/ticket store | 可生产 |
| `dedicated` | 每租户独立库 | 独立 DB、migration、secret boundary | 可生产 |
| `shared` | 多租户实验 | trusted tenant resolver、UnitOfWork、RLS、tenant-qualified OIDC namespace | 默认禁止生产；需显式 resolver/隔离验收 |

所有 tenant-owned repository 必须使用同一 request-scoped transaction/connection，并由 UnitOfWork 设置 `app.tenant_id`；禁止 repository 自行从裸 Pool 查询。

#### 3.3.5 微信 component 凭据协调器

component access token、authorized refresh token、binding version 必须由 tenant-scoped coordinator 管理：

- refresh token 轮换使用 version/CAS，提前刷新并保留短暂 grace。
- 多实例 singleflight/lock，避免重复轮换和旧 token 覆盖新 token。
- component binding 禁用/解绑后下一次授权立即失败，不依赖进程内缓存。
- provider response、access token、refresh token、app secret 只存在服务端存储；公共 DTO 只返回稳定错误码。

#### 3.3.6 生产启动门槛

以下任一条件不满足时，模块必须启动失败，而不是降级到内存实现：

- platform login state、opaque session、webview ticket 使用持久化实现并通过 readiness。
- OIDC 使用持久化 adapter、显式 cookie keys/JWKS、可信 proxy 配置。
- RP issuer/UserInfo/redirect 策略完整，ID Token 验证不可关闭。
- shared tenant 的 RLS、tenant resolver、UnitOfWork 和 OIDC client namespace 已验收。
- refresh/revoke/purge/retention 任务和审计 sink 已配置。

### 3.4 与纯自研方案的取舍（记录）

纯自研内核（原 v0.1 规划的 spi/auth/credential/token/rbac 独立实现）被否决：Better Auth 已实战覆盖其约 70%，自研的安全正确性风险与维护成本远大于差异价值。原自研设计保留在 git 历史中作为 Plan B 参考。

## 4. Data model（生成到客户库，统一 `gb_idaas_` 前缀，各表预留 `extra jsonb`）

| 表 | 关键字段 |
|----|---------|
| `gb_idaas_user` | id, username, email, phone, status, mfa_secret?, created_at |
| `gb_idaas_credential` | id, user_id, type(password/otp), hash, last_used_at |
| `gb_idaas_role` | id, code, name, parent_id |
| `gb_idaas_permission` | id, code, name, type(api/menu/button) |
| `gb_idaas_role_permission` | role_id, permission_id |
| `gb_idaas_user_role` | user_id, role_id, org_id? |
| `gb_idaas_org` | id, parent_id, path(物化路径), name, sort |
| `gb_idaas_org_user` | org_id, user_id, is_primary |
| `gb_idaas_session` | id, user_id, token_hash, device, ip, expires_at, revoked_at |
| `gb_idaas_audit_log` | id, user_id?, event, detail(jsonb), ip, ua, created_at |

## 5. Package structure

```
@getbrick/idaas-core        ①预设层：better-auth 深度预设 + 审计 + 策略 + 权限增强
@getbrick/idaas-nestjs      ②NestJS 适配器（封装社区适配器加固：守卫/装饰器/管理模块）
@getbrick/idaas-ui          ③登录页/管理页组件（白标可定制）
@getbrick/idaas-cli         getbrick idaas init / 迁移 / upgrade 检查（包装 better-auth CLI）
```

升级 = `npm update` + 迁移命令；**更新订阅 = 私源访问**（安全补丁 + 新版本 + LTS 通道，按公司/年收费）。

## 6. Business model

| 收入 | 说明 |
|------|------|
| 更新订阅（主力） | 私源：安全补丁/新版本/LTS，按公司按年 |
| 托管服务（P2） | 不想嵌入的客户买托管 |
| 平台分润（远期） | IDaaS 作为交付平台能力目录第一张牌 |

## 7. Roadmap

| 里程碑 | 周期 | 交付物 |
|--------|------|--------|
| M1 预设层 + 适配器 | 2-3 周 | W1: idaas-core 预设包（better-auth 集成 + getbrick.config 映射 + gb_idaas_* 表映射 + 审计 hooks）；W2: idaas-nestjs（适配器封装 + Guard/装饰器 + 权限增强：角色继承/数据范围）；W3: idaas-cli（getbrick idaas init）+ 示例工程 + 文档 → **v1.0 发布** |
| M2 发布打磨 | 1-2 周 | 文档站、npm 发版、社区渠道（掘金/GitHub）、3 个示例工程 |
| M3 反馈迭代 | 持续 | 种子开发公司真实交付 2-3 个案例 → 进 P1 |

质量门槛（原内核规划保留，作用于预设层与差异化代码）：
- 预设层/增强插件单测覆盖率 ≥90%（CI 红线）
- 每个安全相关修复必须配回归用例
- CI 矩阵：Node 20/22/24 × PostgreSQL
