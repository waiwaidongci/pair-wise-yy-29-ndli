# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议，并实现**基于同意的一次性核验出示**。

## 代码分层

| 文件 | 职责 |
| --- | --- |
| `persistence.py` | 持久化：SQLite 连接、建表、审计、串行化写事务与共享工具 |
| `occupancy.py` | 占用状态：进程内登记表，同笔申请并发取用时只放一笔进入关键区 |
| `verification.py` | 请求处理：核验申请、持有人同意、一次性结果凭证、撤回与留痕 |
| `app.py` | HTTP 路由与凭证签发/撤销/争议业务 |

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder`、`verifier` 或 `regulator`。浏览器打开根路径即可在页面上登记申请、同意并查看核验结果与留痕。

## 一次性核验流程

1. **核验方登记申请**：说明用途与拟看字段，申请默认 7 天内待同意；
2. **持有人同意**：可在申请范围内缩减字段并设定结果凭证有效期（默认 600 秒），同意后生成一枚一次性令牌，原始令牌只在同意响应中返回一次，库里只存 SHA-256 哈希；
3. **核验方取用结果**：凭令牌取一次签名结果。过期、已用、撤回或实看字段超出同意范围均拒绝；字段超范围等拒绝**不消耗**凭证；首次成功取用在同一事务内把申请置为 `consumed` 并写入核验记录，原令牌立即失效；
4. **撤回同意**：未使用（含待同意、已同意未取用）的申请立即作废，令牌失效；已经产生的核验记录继续保留；
5. **并发取用**：进程内占用锁先挡住同申请并发，SQLite 条件更新（`WHERE status='approved' AND voucher_expires_at>?`）在共享写锁事务内兜底，多笔并发只有一笔成功。

### 核验相关接口

- `POST /api/verification/requests`：核验方登记申请（`credential_id`、`purpose`、`requested_fields`）。
- `POST /api/verification/requests/{id}/approve`：持有人同意（可选 `approved_fields`、`ttl_seconds`），返回 `voucher_token`。
- `POST /api/verification/requests/{id}/withdraw`：持有人撤回未使用的同意。
- `POST /api/verification/redeem`：核验方凭 `voucher_token` 取一次性结果，可带 `fields`（须在同意范围内）与 `at`（模拟核验时间）。
- `GET /api/verification/requests`、`GET /api/verification/requests/{id}`：按身份查看申请。
- `GET /api/verification/records`：核验留痕（持有人可见“谁、为何、何时、看过哪些字段”），支持 `?credential_id=` 过滤。
- `GET /api/state`：汇总状态，包含 `verification_requests`、`verification_records` 与当前占用中的申请。

## 凭证相关接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成可离线校验的令牌。
- `POST /api/verify`：验证离线令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖一次性语义、过期/已用/超范围拒绝、撤回与留痕保留、角色边界，以及同申请并发取用、撤回与取用竞争各只有一笔成功。

## 原型局限

私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；占用状态是进程内注册表，多实例部署时一次性语义由数据库条件更新保证，但细粒度排队需要外部存储；也未实现可验证凭证联盟标准或硬件密钥保护。
