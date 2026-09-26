# UniApp/unibest opaque-session 客户端模板

这是一个可复制到客户项目的 UniApp + Vue 3 + TypeScript 骨架，入口沿用 unibest 的 `uni -p` 命令、`src/pages` 页面目录以及根目录 `pages.json`/`manifest.json` 结构。模板同时面向 `mp-weixin`、`h5` 和 `app`。

## 快速开始

```bash
pnpm install
cp .env.example .env
pnpm dev:h5
pnpm dev:mp-weixin
pnpm dev:app
```

验证命令：

```bash
pnpm check
pnpm typecheck
pnpm build:h5
```

`typecheck` 需要安装模板自身的 UniApp/Vue 类型依赖；`typecheck:core` 只检查认证、请求和平台适配层。

## 目录

```text
src/
├── manifest.json
├── pages.json
├── auth/
│   ├── callback.ts       OIDC query/web-view 消息解析与 flow 绑定
│   ├── client.ts         登录、回调、刷新、退出编排
│   ├── errors.ts         结构化认证错误
│   ├── handoff.ts        H5 location 与 App web-view handoff
│   ├── pkce.ts           S256 PKCE、按 flowId 存取的一次性事务
│   ├── platform.ts       MP-WEIXIN uni.login 分支
│   ├── session.ts        opaque session 校验与本地存储
│   └── session-coordinator.ts  session generation fence 与 single-flight
├── services/
│   ├── auth.ts           认证后端 API 契约与实际平台路由
│   └── request.ts        uni.request 封装、错误处理与 refresh
├── stores/auth.ts        Pinia 认证状态与结构化错误
├── pages/
│   ├── index/index.vue
│   └── auth/
│       ├── callback.vue
│       └── web-view.vue
├── config.ts
├── main.ts
└── App.vue
```

根目录和 `src` 中的 `manifest.json`/`pages.json` 保持相同配置；H5 使用 history 路由，根 manifest 与构建输入不能漂移。

## O5 认证边界

客户端只持久化 opaque `sessionReference`、`expiresAt`、可选的 `clientKind` 和公开用户资料。客户端不会把微信 `session_key`、微信 AppSecret、OIDC client secret、access token、refresh token 或 ID token 写入 `uni` storage。认证响应出现这些字段时，`src/auth/session.ts` 和 `src/services/request.ts` 会拒绝响应，且不会把原始响应写入日志或错误对象。

### H5 exact callback

H5 redirect URI 必须是精确的、无 hash 的 callback URL；默认是 `${origin}/pages/auth/callback`，manifest 使用 `history` 模式。授权 URL 中的 `redirect_uri` 必须与配置值逐字相等；默认页面路由是 `/pages/auth/callback`。`.env.example`、根 `manifest.json` 和 `src/manifest.json` 必须同步修改。

H5 OIDC start 使用 `POST /oidc/start`，请求体严格只包含 BFF contract 的 `redirectUri`、`clientType=web`、`clientId`、`scope`、`state`、`nonce`、PKCE challenge/method。callback exchange 使用 `POST /oidc/callback`，请求体严格只包含 `code`、`codeVerifier`、`redirectUri`、`state`、`clientId` 和 `clientType=web`；不发送本地 `flowId`、`flowBinding`、`origin`、`nonce` 或 challenge。callback 通过 `state` 映射本地 transaction，H5 exchange 必须是带 `withCredentials` 的 `204`，只接受服务器 cookie。

### App/webview platform route

App OIDC 登录是 webview flow，不把 provider 直接导航到返回 JSON 的 API callback。`VITE_OIDC_APP_REDIRECT_URI` 必须显式配置为受信任的本地 bridge 页面（模板提供 `public/oidc-bridge.html`）；未配置时 App OIDC fail fast。bridge 只向父 webview 发送白名单 callback 字段，父页面校验 bridge origin、state 以及可用的 flowId/nonce，再调用实际 application/platform API：

- `POST /applications/:applicationId/platforms/:platformId/login/webview/start`
- `POST /applications/:applicationId/platforms/:platformId/login/webview/callback`
- `POST /applications/:applicationId/platforms/:platformId/webview/ticket/exchange`

webview start 只发送 `{ redirectUri, client: "webview", flowBinding, scope }`，其中 `redirectUri` 是显式 bridge URI，`flowBinding` 是 storage-backed transaction 的本地 `flowId`；由平台服务端生成并返回 `state`，客户端不发送 `clientType`、本地 state、PKCE challenge、nonce、flowId 或 origin。callback exchange 只发送 `{ state, code, flowBinding }`，且 `flowBinding` 必须与 start 完全相同；它不会放入 bridge URL 或 provider 页面。ticket exchange 只发送 ticket、当前 session reference 和 client ID；消息桥只负责交接一次性结果，不传 provider token 或 session。native/mp-weixin/webview opaque session 的 refresh/logout 使用 platform session 路由，webview 请求省略 client alias；`me` 使用带 `X-Client-Session` 的 BFF me 路由。

### flow transaction binding

每次登录生成本地 `flowId`；H5 另生成 PKCE state/nonce/verifier/challenge，platform/webview state 使用服务端 start response。事务记录 `flowId + state + nonce + origin + exact redirectUri + startGeneration + attempt`，按 `getbrick.client.oidc-transaction.<flowId>` 存取，并保留 state→flow 映射；同一 storage 中的 `getbrick.client.oidc-transaction.fence` 持久化当前 generation/attempt，H5 整页重载后仍能验证同一 flow。H5 callback 不要求后端返回 `flowId`，通过 state 映射；webview callback 同样以服务端 state 绑定。错误 callback 没有可验证的 state/flow binding 时不能消耗 transaction。

`OidcTransactionStore.consume(flowId)` 先从 storage 删除原始记录，再解析并返回，重复 callback、并发 callback 和过期事务都会 fail closed；事务十分钟过期。start/handoff 失败只清理对应 flow，不影响其它登录尝试。

### refresh/logout generation fence

`SessionCoordinator` 为每次 session 接受、清理和登录切换维护 generation。refresh 捕获 `(generation, sessionReference)`，响应回来时只有 fence 仍匹配才允许提交；logout 在发起网络请求前立即使旧 generation 失效并清理本地 session。因此 logout 之后尚未返回的旧 refresh 不会把 session 复活。H5 cookie refresh 也经过同一 generation fence，native/webview refresh single-flight，logout 失败也不会保留本地凭证。

### 结构化错误

`AuthError`/`ApiError` 对外保留 `code`、`status`、`retryable`，不复制 provider 错误正文或 token。Pinia store 暴露 `error` 和安全的 `errorMessage`，调用方可以按结构化字段决定是否重试。

## 后端接口契约

默认认证基路径是 `VITE_AUTH_BASE_PATH`，示例值为 `/api/idaas/v1/client/auth`；平台基路径是 `VITE_PLATFORM_BASE_PATH`。模板只定义客户端请求，不实现服务端。

| 方法 | 路径 | 请求重点 | 响应 |
| --- | --- | --- | --- |
| `POST` | `/oidc/start` | exact BFF fields: `redirectUri`, `clientType=web`, `clientId`, `scope`, `state`, `nonce`, PKCE | `authorizationUrl`, server `state`, `expiresAt` |
| `POST` | `/oidc/callback` | exact BFF fields: H5 `code`, `codeVerifier`, `redirectUri`, `state`, `clientId`, `clientType=web` | `204` cookie |
| `POST` | `/applications/:applicationId/platforms/:platformId/login/webview/start` | `redirectUri`, `client=webview`, `flowBinding`, optional `scope` | server `authorizationUrl`, server `state`, `expiresAt` |
| `POST` | `/applications/:applicationId/platforms/:platformId/login/webview/callback` | `state`, `code`, same `flowBinding` | 新的 opaque session |
| `POST` | `/applications/:applicationId/platforms/:platformId/webview/ticket/exchange` | `ticket`, 当前 opaque session、`clientId` | 新的 opaque session |
| `POST` | `/refresh` | opaque `sessionReference` 与同一 header | 新的 opaque session 或 H5 cookie |
| `POST` | `/logout` | opaque `sessionReference` 与同一 header | `204` 或空对象 |
| `GET` | `/me` | opaque reference 通过 `X-Client-Session` 或 H5 cookie | 公开用户资料 |

opaque reference 不是 JWT，也不应被当作 provider token 使用。客户端不会自动保存或拼接 provider token。

## 平台配置

1. 复制 `.env.example` 为 `.env`，填写 API 地址、application/platform ID、公开 OIDC client ID、exact H5 callback、webview origin 和 HTTPS allowlist。
2. 在微信公众平台登记 `manifest.json` 中的小程序 AppID，并保证客户后端已完成微信平台配置；模板不包含任何微信 secret。
3. 在 OIDC 服务端登记 H5 exact callback 和显式 app bridge redirect；bridge URI 必须对应受信任的 `oidc-bridge.html`，platform start 由服务端生成 state，客户端按 clientKind 选择 session route。
4. 替换 `manifest.json` 中的示例 AppID、应用名称和版本信息。
5. 将 `src/services/auth.ts` 的平台路径与客户后端路由对齐后，再接入业务 API。

## 复制到客户项目

复制整个目录后，将 `src/auth`、`src/services`、`src/stores` 合并到客户现有目录。认证服务依赖可以通过构造函数注入，客户可以在测试中使用内存 storage 和 mock API，而不需要把真实环境凭证带入前端。客户复制模板时可以只复制 `examples/uniapp-unibest`，再按自身后端契约调整 `src/services/auth.ts`。
