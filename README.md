# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

在此之上还提供**核验申请与一次性出示**：核验方（`verifier` 角色）先登记用途与拟看字段，持有人同意后生成只能使用一次的结果凭证；凭证过期、已使用、被撤回或兑付字段超出同意范围都会被拒绝，第一次成功核验后立即失效。持有人撤回同意时未使用的申请与凭证作废，已产生的核验记录继续保留，供事后查看"谁在什么时间因为什么用途看了哪些字段"。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder`、`verifier` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `POST /api/verification/requests`：核验方登记核验申请（用途、拟看字段、有效期分钟数）。
- `POST /api/verification/requests/{id}/consent`：持有人同意，返回一次性结果凭证。
- `POST /api/verification/requests/{id}/withdraw`：持有人撤回同意，未使用申请与凭证作废。
- `POST /api/verification/redeem`：核验方兑付一次性凭证，可再缩小披露字段；同一申请并发取用只有一笔成功。
- `GET /api/verification/requests`、`GET /api/verification/records`：按身份查看申请与核验记录。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 代码结构

- `app.py`：HTTP 层、凭证签发/撤销/争议与装配。
- `verification_service.py`：核验申请与一次性出示的请求处理（业务编排）。
- `verification_state.py`：占用状态，按申请串行化并发取用。
- `verification_persistence.py`：核验申请、一次性授权、核验记录的持久化。
- `common.py`：时间、规范化编码与错误类型等共享原语。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
