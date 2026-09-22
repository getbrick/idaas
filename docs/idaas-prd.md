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

### 3.3 与纯自研方案的取舍（记录）

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
