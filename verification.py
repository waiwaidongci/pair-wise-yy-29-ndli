#!/usr/bin/env python3
"""请求处理层：核验申请、持有人同意与一次性结果凭证。

业务流程：
1. 核验方登记申请：说明用途与拟看字段（requested_fields）；
2. 持有人同意：可在申请范围内缩减字段（approved_fields）并设定凭证有效期，
   同意后生成一枚只能使用一次的结果凭证（voucher token），令牌只返回这一次；
3. 核验方凭令牌取结果：过期、已用、撤回或字段超出同意范围一律拒绝；
   第一次成功核验的同一事务里凭证立即失效，同笔申请并发取用只有一笔成功；
4. 持有人撤回同意：未使用的申请作废；已经产生的核验记录继续保留。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import timedelta
from typing import Iterable

from occupancy import OccupancyRegistry
from persistence import ApiError, canonical, iso, now, parse_time, token_digest

# 申请本身的有效期：登记后若一直未获同意，到此时间作废
REQUEST_TTL = timedelta(days=7)
# 同意后一次性结果凭证的默认有效期（秒），可由持有人在同意时覆盖
VOUCHER_TTL_SECONDS_DEFAULT = 600
VOUCHER_TTL_SECONDS_MIN = 30
VOUCHER_TTL_SECONDS_MAX = 86400

REQUEST_STATUSES = {"pending", "approved", "consumed", "withdrawn", "expired", "rejected"}


class VerificationService:
    def __init__(self, store, occupancy: OccupancyRegistry):
        self.store = store
        self.conn = store.conn
        self.occupancy = occupancy

    # ---------- 通用检查 ----------

    @staticmethod
    def _required_actor(actor: str | None, role: str | None, expected: str) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != expected:
            raise ApiError(403, f"需要角色 {expected}")
        return actor

    def _row(self, table: str, identity: int) -> sqlite3.Row:
        row = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    @staticmethod
    def _normalize_fields(fields: Iterable[str]) -> list[str]:
        names = [str(name).strip() for name in (fields or [])]
        if any(not name for name in names):
            raise ApiError(400, "字段名不能为空")
        if len(names) != len(set(names)):
            raise ApiError(400, "字段不能重复")
        return names

    def _credential_and_template(self, credential_id: int) -> tuple[sqlite3.Row, sqlite3.Row]:
        credential = self._row("credentials", credential_id)
        template = self._row("templates", credential["template_id"])
        return credential, template

    def _request_dict(self, row: sqlite3.Row, holder_id: str | None = None) -> dict:
        if holder_id is None:
            holder_id = self.conn.execute(
                "SELECT holder_id FROM credentials WHERE id=?", (row["credential_id"],)
            ).fetchone()["holder_id"]
        return {
            "id": row["id"],
            "request_id": row["id"],
            "credential_id": row["credential_id"],
            "verifier_id": row["verifier_id"],
            "holder_id": holder_id,
            "purpose": row["purpose"],
            "requested_fields": json.loads(row["requested_fields_json"]),
            "approved_fields": json.loads(row["approved_fields_json"]) if row["approved_fields_json"] else None,
            "status": row["status"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "decided_at": row["decided_at"],
            "voucher_expires_at": row["voucher_expires_at"],
            "consumed_at": row["consumed_at"],
            "withdrawn_at": row["withdrawn_at"],
        }

    # ---------- 1. 核验方登记申请 ----------

    def create_request(
        self,
        actor: str | None,
        role: str | None,
        credential_id: int,
        purpose: str,
        requested_fields: list[str],
    ) -> dict:
        actor = self._required_actor(actor, role, "verifier")
        purpose = (purpose or "").strip()
        if not purpose:
            raise ApiError(400, "核验用途不能为空")
        fields = self._normalize_fields(requested_fields)
        credential, template = self._credential_and_template(credential_id)
        allowed = {f["name"] for f in json.loads(template["fields_json"])}
        outside = [name for name in fields if name not in allowed]
        if outside:
            raise ApiError(400, f"字段不在凭证模板中：{outside}")
        created = now()
        expires = created + REQUEST_TTL
        with self.store.transaction():
            cur = self.conn.execute(
                """INSERT INTO verification_requests
                       (credential_id,verifier_id,purpose,requested_fields_json,status,created_at,expires_at)
                   VALUES(?,?,?,?,'pending',?,?)""",
                (credential_id, actor, purpose, json.dumps(fields, ensure_ascii=False), iso(created), iso(expires)),
            )
            request_id = cur.lastrowid
            self.store.audit(
                actor, "verify.request", "verification_request", request_id,
                {"credential_id": credential_id, "purpose": purpose, "requested_fields": fields},
            )
        return self._request_dict(self._row("verification_requests", request_id))

    # ---------- 2. 持有人同意，生成一次性凭证 ----------

    def approve_request(
        self,
        actor: str | None,
        role: str | None,
        request_id: int,
        approved_fields: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> dict:
        actor = self._required_actor(actor, role, "holder")
        req = self._row("verification_requests", request_id)
        credential = self._row("credentials", req["credential_id"])
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能同意针对自己凭证的核验申请")
        status = self._effective_status(req)
        if status != "pending":
            raise ApiError(409, f"申请当前状态为 {status}，不能同意")
        requested = json.loads(req["requested_fields_json"])
        if approved_fields is None:
            approved = requested
        else:
            approved = self._normalize_fields(approved_fields)
            requested_set, approved_set = set(requested), set(approved)
            if not approved_set <= requested_set:
                raise ApiError(
                    400, f"同意字段超出核验方申请范围，超出={sorted(approved_set - requested_set)}"
                )
        try:
            ttl = int(ttl_seconds) if ttl_seconds is not None else VOUCHER_TTL_SECONDS_DEFAULT
        except (TypeError, ValueError) as exc:
            raise ApiError(400, "凭证有效期必须是整数秒") from exc
        if not VOUCHER_TTL_SECONDS_MIN <= ttl <= VOUCHER_TTL_SECONDS_MAX:
            raise ApiError(
                400, f"凭证有效期需在 {VOUCHER_TTL_SECONDS_MIN}~{VOUCHER_TTL_SECONDS_MAX} 秒之间"
            )
        voucher_token = secrets.token_urlsafe(32)
        decided = now()
        voucher_expires = decided + timedelta(seconds=ttl)
        with self.store.transaction():
            cur = self.conn.execute(
                """UPDATE verification_requests
                      SET status='approved', decided_at=?, approved_fields_json=?,
                          voucher_expires_at=?, voucher_token_hash=?
                    WHERE id=? AND status='pending'""",
                (
                    iso(decided), json.dumps(approved, ensure_ascii=False),
                    iso(voucher_expires), token_digest(voucher_token), request_id,
                ),
            )
            if cur.rowcount != 1:
                # 并发同意 / 撤回竞争：以条件更新为准
                latest = self._row("verification_requests", request_id)
                raise ApiError(409, f"申请当前状态为 {self._effective_status(latest)}，不能同意")
            self.store.audit(
                actor, "verify.approve", "verification_request", request_id,
                {"approved_fields": approved, "voucher_expires_at": iso(voucher_expires)},
            )
        result = self._request_dict(self._row("verification_requests", request_id))
        # 原始令牌只在本次响应中出现，服务端只保存它的哈希
        result["voucher_token"] = voucher_token
        result["hint"] = "请把 voucher_token 安全转交核验方；令牌只能成功使用一次。"
        return result

    # ---------- 3. 持有人撤回同意 ----------

    def withdraw_consent(self, actor: str | None, role: str | None, request_id: int) -> dict:
        actor = self._required_actor(actor, role, "holder")
        req = self._row("verification_requests", request_id)
        credential = self._row("credentials", req["credential_id"])
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能撤回针对自己凭证的同意")
        status = self._effective_status(req)
        withdrawn_at = iso()
        with self.store.transaction():
            if status == "pending":
                # 尚未同意：申请直接作废
                cur = self.conn.execute(
                    "UPDATE verification_requests SET status='withdrawn', withdrawn_at=? WHERE id=? AND status='pending'",
                    (withdrawn_at, request_id),
                )
                if cur.rowcount != 1:
                    latest = self._row("verification_requests", request_id)
                    raise ApiError(409, f"申请当前状态为 {self._effective_status(latest)}，不能撤回")
            elif status == "approved":
                # 已同意但未使用：未使用申请失效；并发取用在同一事务里 CAS 会失败
                cur = self.conn.execute(
                    """UPDATE verification_requests
                          SET status='withdrawn', withdrawn_at=?
                        WHERE id=? AND status='approved'""",
                    (withdrawn_at, request_id),
                )
                if cur.rowcount != 1:
                    latest = self._row("verification_requests", request_id)
                    raise ApiError(409, f"申请当前状态为 {self._effective_status(latest)}，不能撤回")
            elif status == "consumed":
                raise ApiError(409, "核验结果已被取用，撤回不能删除已有核验记录")
            else:
                raise ApiError(409, f"申请当前状态为 {status}，不能撤回")
            self.store.audit(actor, "verify.withdraw", "verification_request", request_id, {"previous_status": status})
        return self._request_dict(self._row("verification_requests", request_id))

    # ---------- 4. 核验方凭一次性凭证取结果 ----------

    def redeem_voucher(
        self,
        actor: str | None,
        role: str | None,
        voucher_token: str,
        fields: list[str] | None = None,
        at: str | None = None,
    ) -> dict:
        actor = self._required_actor(actor, role, "verifier")
        if not voucher_token or not voucher_token.strip():
            raise ApiError(400, "缺少一次性凭证令牌")
        wanted = None
        if fields is not None:
            wanted = self._normalize_fields(fields)
        check_at = parse_time(at)

        req = self.conn.execute(
            "SELECT * FROM verification_requests WHERE voucher_token_hash=?",
            (token_digest(voucher_token.strip()),),
        ).fetchone()
        if not req:
            raise ApiError(404, "凭证不存在")
        if req["verifier_id"] != actor:
            # 不向无关方透露申请细节
            raise ApiError(403, "这枚凭证不属于当前核验方")

        status = self._effective_status(req, check_at)
        if status == "withdrawn":
            raise ApiError(410, "持有人已撤回同意，申请已失效")
        if status == "consumed":
            raise ApiError(410, "凭证已使用，一次性结果不能重复取用")
        if status == "expired":
            self._mark_expired(req)
            raise ApiError(410, "申请或凭证已过期")
        if status != "approved":
            raise ApiError(409, f"申请当前状态为 {status}，无法核验")

        approved = json.loads(req["approved_fields_json"])
        if wanted is not None and not set(wanted) <= set(approved):
            raise ApiError(
                403, f"请求字段超出持有人同意范围，超出={sorted(set(wanted) - set(approved))}"
            )
        disclosed = approved if wanted is None else [name for name in wanted if name in approved]

        # 第一道闸门：进程内占用，同笔申请并发取用只放一笔进来
        try:
            occupied = self.occupancy.occupy(req["id"])
            occupied.__enter__()
        except RuntimeError as exc:
            raise ApiError(409, str(exc)) from exc
        try:
            return self._redeem_locked(req, disclosed, check_at, actor)
        finally:
            occupied.__exit__(None, None, None)

    def _redeem_locked(self, req: sqlite3.Row, disclosed: list[str], check_at, actor: str) -> dict:
        credential, template = self._credential_and_template(req["credential_id"])
        claims = json.loads(credential["claims_json"])
        visible = {name: claims.get(name) for name in disclosed}

        validity = self._credential_validity(credential, check_at)
        payload = {
            "request_id": req["id"],
            "credential_id": credential["id"],
            "template_id": credential["template_id"],
            "issuer": credential["issuer"],
            "holder_id": credential["holder_id"],
            "verifier_id": req["verifier_id"],
            "purpose": req["purpose"],
            "claims": visible,
            "credential_valid_until": credential["valid_until"],
            "credential_status": validity["status"],
            "checked_at": iso(check_at),
            "key_version": credential["key_version"],
        }
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?",
            (credential["issuer"], credential["key_version"]),
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(
            canonical({"payload": payload, "signature": signature})
        ).decode().rstrip("=")

        result = {
            "valid": validity["valid"],
            "status": validity["status"],
            "reason": validity.get("reason"),
            "request_id": req["id"],
            "credential_id": credential["id"],
            "verifier_id": req["verifier_id"],
            "purpose": req["purpose"],
            "fields": disclosed,
            "claims": visible,
            "credential_valid_until": credential["valid_until"],
            "checked_at": iso(check_at),
            "payload": payload,
            "signature": signature,
            "signed_result_token": token,
        }

        with self.store.transaction():
            # 第二道闸门：条件更新。过期 / 已用 / 被撤回 / 并发取用都由这里兜底。
            cur = self.conn.execute(
                """UPDATE verification_requests
                      SET status='consumed', consumed_at=?
                    WHERE id=? AND status='approved' AND voucher_expires_at > ?""",
                (iso(check_at), req["id"], iso(check_at)),
            )
            if cur.rowcount != 1:
                latest = self._row("verification_requests", req["id"])
                latest_status = self._effective_status(latest, check_at)
                if latest_status == "withdrawn":
                    raise ApiError(410, "持有人已撤回同意，申请已失效")
                if latest_status == "consumed":
                    raise ApiError(410, "凭证已使用，一次性结果不能重复取用")
                if latest_status == "expired":
                    raise ApiError(410, "申请或凭证已过期")
                raise ApiError(409, f"申请当前状态为 {latest_status}，无法核验")
            self.conn.execute(
                """INSERT INTO verification_records
                       (request_id,credential_id,verifier_id,purpose,fields_json,result_json,at)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    req["id"], credential["id"], req["verifier_id"], req["purpose"],
                    json.dumps(disclosed, ensure_ascii=False),
                    json.dumps(result, ensure_ascii=False), iso(check_at),
                ),
            )
            self.store.audit(
                actor, "verify.redeem", "verification_request", req["id"],
                {"fields": disclosed, "credential_status": validity["status"], "valid": validity["valid"]},
            )
        return result

    @staticmethod
    def _credential_validity(credential: sqlite3.Row, check_at) -> dict:
        """核验当下凭证本身是否有效；凭证无效不影响一次性结果的交付。"""
        if check_at >= parse_time(credential["valid_until"]):
            return {"valid": False, "status": "expired", "reason": "凭证已过期"}
        if credential["status"] == "revoked":
            effective = parse_time(credential["revocation_effective_at"])
            if check_at >= effective:
                return {"valid": False, "status": "revoked", "reason": credential["revocation_reason"]}
            return {"valid": True, "status": "valid_until_revocation",
                    "revocation_starts_at": credential["revocation_effective_at"]}
        if credential["status"] == "disputed":
            return {"valid": False, "status": "disputed", "reason": "撤销决定正在争议复核"}
        return {"valid": True, "status": "valid"}

    # ---------- 5. 查询：申请、核验记录 ----------

    def list_requests(self, actor: str | None, role: str | None) -> list[dict]:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role == "verifier":
            rows = self.conn.execute(
                """SELECT vr.*, c.holder_id AS holder_id
                     FROM verification_requests vr
                     JOIN credentials c ON c.id=vr.credential_id
                    WHERE vr.verifier_id=? ORDER BY vr.id DESC""",
                (actor,),
            ).fetchall()
        elif role == "holder":
            rows = self.conn.execute(
                """SELECT vr.*, c.holder_id AS holder_id
                     FROM verification_requests vr
                     JOIN credentials c ON c.id=vr.credential_id
                    WHERE c.holder_id=? ORDER BY vr.id DESC""",
                (actor,),
            ).fetchall()
        elif role == "regulator":
            rows = self.conn.execute(
                """SELECT vr.*, c.holder_id AS holder_id
                     FROM verification_requests vr
                     JOIN credentials c ON c.id=vr.credential_id
                    ORDER BY vr.id DESC"""
            ).fetchall()
        else:
            raise ApiError(403, "当前角色不能查看核验申请")
        return [self._request_dict(row, row["holder_id"]) for row in rows]

    def get_request(self, actor: str | None, role: str | None, request_id: int) -> dict:
        if not actor:
            raise ApiError(401, "缺少身份")
        item = self._request_dict(self._row("verification_requests", request_id))
        if role == "verifier":
            if item["verifier_id"] != actor:
                raise ApiError(403, "只能查看自己的核验申请")
        elif role == "holder":
            if item["holder_id"] != actor:
                raise ApiError(403, "只能查看针对自己凭证的核验申请")
        elif role != "regulator":
            raise ApiError(403, "当前角色不能查看核验申请")
        return item

    def list_records(self, actor: str | None, role: str | None, credential_id: int | None = None) -> list[dict]:
        """核验留痕：持有人事后能看到“谁、为了什么用途、在什么时候、看过哪些字段”。"""
        if not actor:
            raise ApiError(401, "缺少身份")
        sql = "SELECT vr.* FROM verification_records vr JOIN credentials c ON c.id=vr.credential_id"
        params: list = []
        where = []
        if role == "holder":
            where.append("c.holder_id=?")
            params.append(actor)
        elif role == "verifier":
            where.append("vr.verifier_id=?")
            params.append(actor)
        elif role != "regulator":
            raise ApiError(403, "当前角色不能查看核验记录")
        if credential_id:
            where.append("vr.credential_id=?")
            params.append(int(credential_id))
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY vr.id DESC"
        rows = self.conn.execute(sql, params).fetchall()
        return [
            {
                "id": row["id"],
                "request_id": row["request_id"],
                "credential_id": row["credential_id"],
                "verifier_id": row["verifier_id"],
                "purpose": row["purpose"],
                "fields": json.loads(row["fields_json"]),
                "at": row["at"],
                "result": json.loads(row["result_json"]),
            }
            for row in rows
        ]

    # ---------- 状态推导 ----------

    def _effective_status(self, req: sqlite3.Row, at=None) -> str:
        """把时间因素折算进状态：pending 超过申请期限、approved 超过凭证期限 => expired。"""
        stored = req["status"]
        if stored not in {"pending", "approved"}:
            return stored
        check_at = at or now()
        if stored == "pending" and check_at >= parse_time(req["expires_at"]):
            return "expired"
        if stored == "approved" and req["voucher_expires_at"] and check_at >= parse_time(req["voucher_expires_at"]):
            return "expired"
        return stored

    def _mark_expired(self, req: sqlite3.Row) -> None:
        """惰性落盘过期状态，不覆盖期间发生的撤回 / 取用。"""
        with self.store.transaction():
            if req["status"] == "pending":
                self.conn.execute(
                    "UPDATE verification_requests SET status='expired' WHERE id=? AND status='pending'",
                    (req["id"],),
                )
            elif req["status"] == "approved":
                self.conn.execute(
                    "UPDATE verification_requests SET status='expired' WHERE id=? AND status='approved'",
                    (req["id"],),
                )
