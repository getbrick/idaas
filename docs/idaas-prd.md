# Getbrick IDaaS — PRD v0.1

- **One-liner**: 全开源的嵌入式 Node.js 身份认证与权限平台，以 NestJS 库形态交付，随项目私有化，靠更新订阅和托管服务盈利
- **Target users**: 使用 Node/NestJS 交付项目的开发公司（及独立开发者）
- **Core promise**: 开箱正确、交付无痕（无黑盒/无外部依赖）、持续安全（可订阅更新）
- **Competitive gap**: Keycloak（重）、Casdoor（浅）、自写认证（乱）——卡位"轻量且深"

## 1. Key decisions（已锁定）

| 决策 | 结论 |
|------|------|
| 内核形态 | **嵌入式代码库**（非独立服务），随客户项目交付与私有化 |
| 技术栈 | TypeScript / Node，首个适配器 **NestJS** |
| 开源策略 | **全开源（MIT）+ 商业可用**；收入 = 更新订阅 + 托管服务 + 未来平台分润 |
| 组织/包名 | GitHub org `getbrick`，npm scope `@getbrick/*` |
| 数据归属 | 用户数据不搬家：在客户数据库生成标准表（迁移脚本），无黑盒 |
| 配置方式 | 声明式配置 `idass.config.ts`，进 git 可 review，AI 友好 |

## 2. Feature list

### P0（v1.0）
| 模块 | 功能 |
|------|------|
| 认证 | 账密登录/注册、手机验证码、邮箱验证、找回密码、JWT 签发/刷新/撤销、单点登出 |
| MFA | TOTP（可选开启） |
| 权限 | RBAC（用户/角色/权限点）、组织架构（树形）、接口级鉴权守卫、数据权限注解（预留接口） |
| 策略 | 密码强度、登录失败锁定、会话时长/并发策略（声明式配置） |
| 审计 | 登录/登出/授权变更/管理操作事件，可插拔存储（默认落项目库） |
| 集成 | NestJS Guard/装饰器、迁移脚本自动建表、`idass.config.ts` |
| 管理台 | 可插拔 NestJS 管理模块：用户/角色/组织/审计 API + 基础管理页（白标配置） |
| CLI | `init` 向导（生成配置+迁移）、`upgrade` 升级检查 |
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

## 3. Kernel architecture

```
core/
├── auth/          认证流程编排（凭据校验→MFA→会话建立）
├── credential/    凭据存储（argon2 哈希、验证码生命周期）
├── token/         签发/验证/刷新/撤销（可插拔：本地JWT / 数据库会话）
├── rbac/          角色/权限点/继承/缓存失效
├── org/           组织架构树、用户归属
├── policy/        策略引擎（读 idass.config，运行时裁决）
├── audit/         事件模型 + Sink 接口（DB/文件/HTTP）
└── spi/           全部可插拔点定义（存储/发信/缓存/时钟）
```

设计铁律：
1. 内核**零框架依赖**（不 import NestJS），适配器做胶水
2. SPI 全接口化：测试内存实现 + 替换文档
3. 时序敏感逻辑注入 Clock（可测试性）

## 4. Data model（生成到客户库，`id_` 前缀，各表预留 `extra jsonb`）

| 表 | 关键字段 |
|----|---------|
| `id_user` | id, username, email, phone, status, mfa_secret?, created_at |
| `id_credential` | id, user_id, type(password/otp), hash, last_used_at |
| `id_role` | id, code, name, parent_id |
| `id_permission` | id, code, name, type(api/menu/button) |
| `id_role_permission` | role_id, permission_id |
| `id_user_role` | user_id, role_id, org_id? |
| `id_org` | id, parent_id, path(物化路径), name, sort |
| `id_org_user` | org_id, user_id, is_primary |
| `id_session` | id, user_id, token_hash, device, ip, expires_at, revoked_at |
| `id_audit_log` | id, user_id?, event, detail(jsonb), ip, ua, created_at |

## 5. Package structure

```
@getbrick/idaas-core        ①内核，零依赖
@getbrick/idaas-nestjs      ②NestJS 适配器（守卫/装饰器/管理模块）
@getbrick/idaas-ui          ③登录页/管理页组件（白标可定制）
@getbrick/idaas-cli         init 向导 / 迁移 / upgrade 检查
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
| M1 内核 | 4-6 周 | core 全模块 + 测试 + SPI 文档 |
| M2 NestJS 集成 | 2-3 周 | 适配器 + 管理模块 + CLI + 示例工程 |
| M3 发布 | 2 周 | 文档站、npm 发版、社区渠道（掘金/GitHub） |
| M4 反馈迭代 | 持续 | 种子开发公司真实交付 2-3 个案例 → 进 P1 |
