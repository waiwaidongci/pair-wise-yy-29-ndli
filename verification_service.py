#!/usr/bin/env python3
"""核验申请与一次性出示的请求处理。

流程：核验方登记用途与拟看字段 -> 持有人同意后签发一次性结果凭证 ->
核验方兑付（过期、已用、撤回或字段超出同意范围即拒绝，成功后凭证立即失效）。

本文件只做业务编排：数据存取交给 ``verification_persistence``，
并发占用交给 ``verification_state``。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Callable

from common import ApiError, canonical, iso, now, parse_time
from verification_persistence import VerificationRepository
from verification_state import GrantOccupancy

MAX_TTL_MINUTES = 7 * 24 * 60


class VerificationService:
    """核验申请生命周期：登记 -> 同意 -> 一次性兑付 / 撤回。"""

    def __init__(
        self,
        repo: VerificationRepository,
        occupancy: GrantOccupancy,
        audit: Callable[[str, str, str, object, dict], None],
        clock: Callable[[], datetime] = now,
    ):
        self.repo = repo
        self.conn = repo.conn
        self.occupancy = occupancy
        self.audit = audit
        self.clock = clock

    # ---- 工具 -----------------------------------------------------------

    @staticmethod
    def _require(actor: str | None, role: str | None, expected: str) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != expected:
            raise ApiError(403, f"需要角色 {expected}")
        return actor

    def _request_or_404(self, request_id: int) -> sqlite3.Row:
        row = self.repo.get_request(request_id)
        if not row:
            raise ApiError(404, "核验申请不存在")
        return row

    def _expire_if_stale(self, request: sqlite3.Row) -> sqlite3.Row:
        """惰性过期：到期后第一次触碰时落库为 expired，并作废未用授权。"""
        if request["status"] in ("pending", "approved") and parse_time(request["expires_at"]) <= self.clock():
            self.repo.set_request_status(request["id"], "expired")
            grant = self.repo.get_grant_by_request(request["id"])
            if grant and grant["status"] == "available":
                self.repo.void_grant(grant["id"])
            request = self.repo.get_request(request["id"])
        return request

    def _template_fields(self, template_id: int) -> list[str]:
        row = self.conn.execute("SELECT fields_json FROM templates WHERE id=?", (template_id,)).fetchone()
        if not row:
            raise ApiError(404, "凭证模板不存在")
        return [field["name"] for field in json.loads(row["fields_json"])]

    def _credential_or_404(self, credential_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise ApiError(404, "凭证不存在")
        return row

    def _sign(self, payload: dict) -> str:
        key = self.conn.execute(
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?",
            (payload["issuer"], payload["key_version"]),
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        return hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()

    def _encode_token(self, payload: dict) -> str:
        envelope = {"payload": payload, "signature": self._sign(payload)}
        return base64.urlsafe_b64encode(canonical(envelope)).decode().rstrip("=")

    def _decode_token(self, token: str) -> dict:
        try:
            padded = token + "=" * (-len(token) % 4)
            envelope = json.loads(base64.urlsafe_b64decode(padded.encode()))
            payload = envelope["payload"]
            signature = str(envelope["signature"])
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(400, "结果凭证格式错误") from exc
        if payload.get("type") != "one_time_presentation":
            raise ApiError(400, "不是一次性出示凭证")
        if not hmac.compare_digest(self._sign(payload), signature):
            raise ApiError(400, "结果凭证签名无效")
        return payload

    # ---- 申请登记 -------------------------------------------------------

    def create_request(
        self,
        actor: str | None,
        role: str | None,
        credential_id: int,
        purpose: str,
        fields: list[str],
        ttl_minutes: int | None = None,
    ) -> dict:
        actor = self._require(actor, role, "verifier")
        purpose = (purpose or "").strip()
        if not purpose:
            raise ApiError(400, "核验用途不能为空")
        if not isinstance(fields, list) or not fields:
            raise ApiError(400, "拟查看字段不能为空")
        fields = [str(name).strip() for name in fields]
        if any(not name for name in fields) or len(fields) != len(set(fields)):
            raise ApiError(400, "拟查看字段为空或重复")
        minutes = 30 if ttl_minutes in (None, "") else int(ttl_minutes)
        if not 1 <= minutes <= MAX_TTL_MINUTES:
            raise ApiError(400, "有效期需在 1 分钟到 7 天之间")
        credential = self._credential_or_404(credential_id)
        allowed = self._template_fields(credential["template_id"])
        unknown = sorted(set(fields) - set(allowed))
        if unknown:
            raise ApiError(400, f"拟查看字段超出凭证模板范围：{unknown}")
        created = self.clock()
        expires = created + timedelta(minutes=minutes)
        with self.conn:
            request_id = self.repo.insert_request(
                credential_id, credential["holder_id"], actor, purpose, fields, iso(expires), iso(created)
            )
            self.audit(
                actor,
                "verification.request",
                "verification_request",
                request_id,
                {"credential_id": credential_id, "holder_id": credential["holder_id"], "purpose": purpose, "fields": fields},
            )
        return self._request_dict(self.repo.get_request(request_id))

    # ---- 持有人同意 -----------------------------------------------------

    def consent(self, actor: str | None, role: str | None, request_id: int) -> dict:
        actor = self._require(actor, role, "holder")
        with self.conn:
            request = self._expire_if_stale(self._request_or_404(request_id))
            if request["holder_id"] != actor:
                raise ApiError(403, "只能同意针对自己凭证的核验申请")
            if request["status"] == "withdrawn":
                raise ApiError(409, "申请已撤回")
            if request["status"] == "consumed":
                raise ApiError(409, "申请已完成核验")
            if request["status"] == "expired":
                raise ApiError(410, "申请已过期")
            if request["status"] != "pending":
                raise ApiError(409, "申请状态不允许同意")
            credential = self._credential_or_404(request["credential_id"])
            approved = json.loads(request["requested_fields_json"])
            claims = json.loads(credential["claims_json"])
            payload = {
                "type": "one_time_presentation",
                "request_id": request["id"],
                "credential_id": credential["id"],
                "issuer": credential["issuer"],
                "holder_id": credential["holder_id"],
                "verifier": request["verifier"],
                "purpose": request["purpose"],
                "claims": {name: claims[name] for name in approved},
                "key_version": credential["key_version"],
                "valid_until": credential["valid_until"],
                "expires_at": request["expires_at"],
            }
            token = self._encode_token(payload)
            try:
                grant_id = self.repo.insert_grant(request["id"], approved, token, iso(self.clock()))
            except sqlite3.IntegrityError as exc:
                raise ApiError(409, "该申请已被同意，请勿重复操作") from exc
            self.repo.set_request_status(request["id"], "approved", consented_at=iso(self.clock()))
            self.audit(
                actor,
                "verification.consent",
                "verification_request",
                request["id"],
                {"grant_id": grant_id, "approved_fields": approved, "verifier": request["verifier"]},
            )
        return {
            "request_id": request["id"],
            "status": "approved",
            "approved_fields": approved,
            "one_time_token": token,
            "expires_at": request["expires_at"],
        }

    # ---- 一次性兑付 -----------------------------------------------------

    def redeem(self, actor: str | None, role: str | None, token: str, fields: list[str] | None = None) -> dict:
        actor = self._require(actor, role, "verifier")
        if not token:
            raise ApiError(400, "缺少一次性结果凭证")
        payload = self._decode_token(token)
        request_id = int(payload.get("request_id", 0))
        with self.occupancy.occupy(request_id):
            with self.conn:
                request = self._expire_if_stale(self._request_or_404(request_id))
                if request["verifier"] != actor:
                    raise ApiError(403, "只有登记该申请的核验方可以使用结果凭证")
                grant = self.repo.get_grant_by_request(request_id)
                if not grant or not hmac.compare_digest(grant["token"], token):
                    raise ApiError(404, "结果凭证不存在")
                if request["status"] == "withdrawn":
                    raise ApiError(409, "同意已被持有人撤回，凭证不可用")
                if request["status"] == "expired":
                    raise ApiError(410, "结果凭证已过期")
                if request["status"] == "consumed" or grant["status"] == "consumed":
                    raise ApiError(409, "结果凭证已被使用，一次性出示不可重复核验")
                if grant["status"] != "available":
                    raise ApiError(409, "结果凭证已失效")
                approved = json.loads(grant["approved_fields_json"])
                disclosed = self._redeem_fields(approved, fields)
                consumed_at = iso(self.clock())
                if not self.repo.consume_grant_if_available(grant["id"], consumed_at, actor):
                    raise ApiError(409, "结果凭证已被并发取用，本次核验失败")
                self.repo.set_request_status(request_id, "consumed")
                claims = {name: payload["claims"][name] for name in disclosed}
                record_id = self.repo.insert_record(
                    request_id,
                    grant["id"],
                    request["credential_id"],
                    request["holder_id"],
                    actor,
                    request["purpose"],
                    disclosed,
                    claims,
                    consumed_at,
                )
                self.audit(
                    actor,
                    "verification.redeem",
                    "verification_request",
                    request_id,
                    {"grant_id": grant["id"], "record_id": record_id, "disclosed_fields": disclosed},
                )
        return {
            "valid": True,
            "request_id": request_id,
            "record_id": record_id,
            "verifier": actor,
            "purpose": request["purpose"],
            "disclosed_fields": disclosed,
            "claims": claims,
            "credential_status": self._credential_status(request["credential_id"]),
            "verified_at": consumed_at,
        }

    @staticmethod
    def _redeem_fields(approved: list[str], requested: list[str] | None) -> list[str]:
        if requested is None:
            return list(approved)
        if not isinstance(requested, list) or not requested:
            raise ApiError(400, "披露字段不能为空")
        deduped = list(dict.fromkeys(str(name) for name in requested))
        outside = sorted(set(deduped) - set(approved))
        if outside:
            raise ApiError(403, f"披露字段超出同意范围：{outside}")
        return deduped

    def _credential_status(self, credential_id: int) -> str:
        row = self.conn.execute("SELECT status, valid_until FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            return "unknown"
        if parse_time(row["valid_until"]) <= self.clock():
            return "expired"
        return row["status"]

    # ---- 撤回与查询 -----------------------------------------------------

    def withdraw(self, actor: str | None, role: str | None, request_id: int) -> dict:
        actor = self._require(actor, role, "holder")
        with self.conn:
            request = self._expire_if_stale(self._request_or_404(request_id))
            if request["holder_id"] != actor:
                raise ApiError(403, "只能撤回针对自己凭证的核验申请")
            if request["status"] == "consumed":
                raise ApiError(409, "申请已完成核验，核验记录继续保留，无法撤回")
            if request["status"] == "withdrawn":
                raise ApiError(409, "申请已撤回")
            if request["status"] == "expired":
                raise ApiError(410, "申请已过期失效，无需撤回")
            grant = self.repo.get_grant_by_request(request_id)
            if grant and grant["status"] == "available":
                self.repo.void_grant(grant["id"])
            self.repo.set_request_status(request_id, "withdrawn")
            self.audit(
                actor,
                "verification.withdraw",
                "verification_request",
                request_id,
                {"voided_grant": bool(grant and grant["status"] == "available")},
            )
        return {"request_id": request_id, "status": "withdrawn"}

    def list_requests(self, actor: str | None, role: str | None) -> list[dict]:
        if role == "holder":
            rows = self.repo.list_requests(holder_id=actor)
        elif role == "verifier":
            rows = self.repo.list_requests(verifier=actor)
        else:
            rows = self.repo.list_requests()
        return [self._request_dict(row) for row in rows]

    def list_records(self, actor: str | None, role: str | None) -> list[dict]:
        if role == "holder":
            rows = self.repo.list_records(holder_id=actor)
        elif role == "verifier":
            rows = self.repo.list_records(verifier=actor)
        else:
            rows = self.repo.list_records()
        return [self._record_dict(row) for row in rows]

    def public_state(self) -> dict:
        return {
            "verification_requests": [self._request_dict(row) for row in self.repo.list_requests()],
            "verification_records": [self._record_dict(row) for row in self.repo.list_records()],
            "verification_occupancy": self.occupancy.snapshot(),
        }

    # ---- 序列化 ---------------------------------------------------------

    def _request_dict(self, row: sqlite3.Row) -> dict:
        grant = self.repo.get_grant_by_request(row["id"])
        return {
            "id": row["id"],
            "credential_id": row["credential_id"],
            "holder_id": row["holder_id"],
            "verifier": row["verifier"],
            "purpose": row["purpose"],
            "requested_fields": json.loads(row["requested_fields_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "consented_at": row["consented_at"],
            "grant": None
            if not grant
            else {
                "status": grant["status"],
                "approved_fields": json.loads(grant["approved_fields_json"]),
                "one_time_token": grant["token"],
                "consumed_at": grant["consumed_at"],
                "consumed_by": grant["consumed_by"],
            },
        }

    @staticmethod
    def _record_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "request_id": row["request_id"],
            "grant_id": row["grant_id"],
            "credential_id": row["credential_id"],
            "holder_id": row["holder_id"],
            "verifier": row["verifier"],
            "purpose": row["purpose"],
            "disclosed_fields": json.loads(row["disclosed_fields_json"]),
            "disclosed_claims": json.loads(row["disclosed_claims_json"]),
            "verified_at": row["verified_at"],
        }
