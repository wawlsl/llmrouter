# OpenAI Responses API Pool Gateway

一个基于 `Node.js + Express + SQLite` 的可视化后台中转站，支持：

- API 账号池（可视化增删改）
- 账号级 Responses 强制兼容转换（`/v1/responses` -> `/v1/chat/completions`）
- 账号级额度（请求数 + 时间窗口）
- 模型级额度（每账号每模型的请求/Token/费用额度）
- 模型映射（客户端模型 -> 上游模型）
- 账号模型列表（拉取 `/v1/models` + 自定义模型）
- `models.dev` 一键同步模型价格
- 货币单位配置（默认 `USD`，可改为 `CNY/JPY` 等）
- Sticky 路由（同一请求窗口内尽量固定账号，提升缓存命中）

## 0) 仓库结构（单仓）

- 网关服务（Node.js）：`src/`、`views/`、`public/`
- 缓存服务（Go / PromptCache）：`services/prompt-cache/`
- 网关数据库：`data/gateway.db`
- 缓存数据目录（默认）：`data/promptcache/`

## 1) 运行

要求：`Node.js 20+`（SQLite 双兼容）

- 优先使用 `better-sqlite3`（Node 20 推荐）
- 若未安装 `better-sqlite3`，在 `Node.js 24+` 下自动回退到内置 `node:sqlite`

```bash
npm install
npm run start
```

后台常驻启动（推荐）：

```bash
npm run boot
npm run status
npm run logs
```

停止：

```bash
npm run stop
```

后台地址：`http://127.0.0.1:3000/admin/login`

### 启动缓存服务（PromptCache）

```bash
npm run cache:boot
npm run cache:status
npm run cache:logs
```

停止缓存服务：

```bash
npm run cache:stop
```

默认缓存监听和存储：

- 监听端口：`8080`
- 缓存存储目录：`data/promptcache`
- 启动脚本：`scripts/cache-server.sh`

可通过环境变量覆盖：

- `CACHE_PORT`
- `CACHE_STORAGE_PATH`
- `CACHE_AUTH_TOKEN`
- `CACHE_EMBEDDING_PROVIDER`
- `CACHE_OPENAI_BASE_URL`
- `CACHE_OPENAI_EMBED_MODEL`
- `CACHE_OPENAI_VERIFY_MODEL`

缓存服务上游密钥（按所选 provider）：

- `OPENAI_API_KEY`（`CACHE_EMBEDDING_PROVIDER=openai` 时必填）
- `MISTRAL_API_KEY`（`CACHE_EMBEDDING_PROVIDER=mistral` 时必填）
- `ANTHROPIC_API_KEY` + `VOYAGE_API_KEY`（`CACHE_EMBEDDING_PROVIDER=claude` 时必填）

默认管理员：

- `ADMIN_USER=admin`
- `ADMIN_PASS=admin123`

建议上线前务必通过环境变量覆盖。

## 2) 环境变量

- `PORT`：监听端口，默认 `3000`
- `DB_PATH`：SQLite 数据库路径，默认 `data/gateway.db`
- `CONFIG_PATH`：旧 JSON 配置路径，仅首次迁移时读取，默认 `data/config.json`
- `ADMIN_USER`：后台用户名
- `ADMIN_PASS`：后台密码
- `GATEWAY_KEYS`：网关调用 token（逗号分隔）；设置后调用 `/v1/*` 必须带 `Authorization: Bearer <token>`

## 3) 后台功能

后台已拆分为多页面导航，避免单页过载：

- `/admin/accounts`：账号池、模型列表、模型额度
- `/admin/groups`：账号池分组、分组 key、分组成员与权重
- `/admin/keys`：访问 key（自动生成安全 key，并绑定分组）
- `/admin/mappings`：模型映射
- `/admin/pricing`：模型价格同步与查看
- `/admin/logs`：实时请求日志（端点/状态码/Token/费用/错误详情，自动过滤 `/v1/models` 与 `count_tokens`）
- `/admin/settings`：全局配置

### 全局

- 默认上游 `Base URL`
- 默认货币单位（`USD/CNY/JPY`）
- 全局 Sticky 窗口
- 登录会话时长

### 模型能力

- 模型映射：`source_model -> target_model`
- 价格同步：从 `https://models.dev/api.json` 同步价格到本地 SQLite

### 账号

- 基础配置：名称、供应商（`openai/anthropic`）、API Key、Base URL、权重、账号总额度
- 可选开启“Responses 强制兼容转换”（按账号控制，适合仅支持 chat/completions 的 OpenAI 兼容上游）
- Base URL 支持带路径前缀（如 `https://your-provider.example.com/api/v1/llm`），网关会将 `/v1/*` 自动映射到该前缀下
- 创建时可选分组 + 分组权重
- 支持一键复制账号（复制基础配置 + 模型列表 + 模型额度配置）
- 创建账号时可直接：
  - 勾选“自动拉取 `/v1/models`”
  - 填写自定义模型列表（逗号或换行分隔）
- 模型列表：
  - 一键拉取该账号的 `/v1/models`
  - 手动添加自定义模型
- 模型额度（按账号+模型）：
  - 请求额度
  - Token额度
  - 费用额度（货币单位可选）
  - 时间窗口（分钟/小时/天/周）

## 4) 请求转发行为

- `POST /v1/responses`
  - 支持模型映射
  - 若账号开启“Responses 强制兼容转换”，网关会将请求转上游 `/v1/chat/completions`，并将返回转换回 Responses 格式（含 SSE）
  - 按访问 key 自动命中分组池
  - 支持 Sticky 账号选择（`previous_response_id` 链路固定同账号）
  - 限流/过载场景自动切换账号重试（最多 3 次，失败账号短暂冷却）
  - 校验账号和模型额度
- `POST /v1/messages`（Claude/Anthropic）
  - 支持模型映射
  - 转发 `anthropic-version` / `anthropic-beta`
  - 自动使用 `x-api-key` 上游鉴权
- `POST /v1/messages/count_tokens`（Claude/Anthropic）
  - 透传到上游，不消耗账号/模型请求额度
- 其他 `/v1/*`
  - 按权重 + 额度筛选账号（可按分组）

访问 key 使用方式：

- 在 `/admin/keys` 创建 key（自动生成安全 token）
- 可将 key 绑定到某个分组（或不绑定，走全局池）
- 客户端只需带 `Authorization: Bearer <token>`，网关自动根据该 token 决定路由分组

调试响应头：

- `x-gateway-account`：命中账号
- `x-gateway-sticky-hit`：是否命中 sticky
- `x-gateway-model-mapped`：若发生模型映射，展示 `source->target`

Sticky 路由优先级（参考 sub2api 思路）：

1. `POST /v1/responses` 且携带 `previous_response_id`：按响应链固定账号（最优先，保障 tool 调用链连续）
2. `session_id`（或 `x-session-id` / `session-id`）存在：按会话固定账号（`/v1/responses`、`/v1/messages`）
3. 其他 `responses` 请求：按请求体 canonical hash + 时间桶固定账号

负载选择实现：

- 在可用账号集合中使用加权一致性哈希（Weighted Rendezvous）选主账号；
- 账号不可用（额度不足/模型不匹配）时会自动降级尝试下一个候选；
- 上游限流/过载账号会进入短冷却窗口，后续请求优先避开；
- 配合 sticky 绑定后，同一链路和同一会话在窗口内会稳定命中同账号。

## 5) Claude Code 兼容

支持 Claude Code 网关模式（`/v1/messages`、`/v1/messages/count_tokens`、`/v1/models`）：

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:3000"
export ANTHROPIC_AUTH_TOKEN="<在 /admin/keys 创建的 token>"
```

说明：

- Claude 客户端可用 `Authorization: Bearer ...` 或 `x-api-key` 调用网关。
- 网关转发到上游 Claude 端点时会自动改用 `x-api-key`。
- 流式 `messages` 会保持 SSE 直通返回。
- `ANTHROPIC_BASE_URL` 应该填网关根地址（不要追加 `/v1`）。
- `count_tokens` 请求会透传，但不会消耗账号请求额度。
- Claude Code 通常只使用 `id` 以 `claude` / `anthropic` 开头的模型。

## 6) Codex 适配示例

```toml
[model_providers.gateway]
name = "Gateway"
base_url = "http://127.0.0.1:3000/v1"
env_key = "GATEWAY_TOKEN"
wire_api = "responses"
```

```bash
export GATEWAY_TOKEN="<GATEWAY_KEYS中的token>"
```

## 7) 数据库说明

- SQLite 文件自动创建：`data/gateway.db`
- 自动建表（settings/accounts/models/mappings/quotas/prices）
- 已启用 `WAL` 模式，适合“读多写少”的网关配置场景
