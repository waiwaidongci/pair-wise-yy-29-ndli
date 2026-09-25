#!/usr/bin/env python3
"""一次性出示的持久化层。

只负责 SQL 与行存取，不做身份、时效或业务判断，业务编排在
``verification_service``，并发占用在 ``verification_state``。

三张表：

- ``verification_requests``：核验方登记的申请（用途、拟看字段、有效期、状态）。
- ``one_time_grants``：持有人同意后生成的一次性结果凭证（与申请一对一）。
- ``verification_records``：成功核验留痕，撤回同意也不删除，供持有人事后查看。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS verification_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id INTEGER NOT NULL REFERENCES credentials(id),
  holder_id TEXT NOT NULL,
  verifier TEXT NOT NULL,
  purpose TEXT NOT NULL,
  requested_fields_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','withdrawn','consumed','expired')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consented_at TEXT
);
CREATE TABLE IF NOT EXISTS one_time_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL UNIQUE REFERENCES verification_requests(id),
  approved_fields_json TEXT NOT NULL,
  token TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('available','voided','consumed')),
  created_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_by TEXT
);
CREATE TABLE IF NOT EXISTS verification_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL,
  grant_id INTEGER NOT NULL,
  credential_id INTEGER NOT NULL,
  holder_id TEXT NOT NULL,
  verifier TEXT NOT NULL,
  purpose TEXT NOT NULL,
  disclosed_fields_json TEXT NOT NULL,
  disclosed_claims_json TEXT NOT NULL,
  verified_at TEXT NOT NULL
);
"""


class VerificationRepository:
    """核验申请、一次性授权与核验记录的行存储。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- 核验申请 -------------------------------------------------------

    def insert_request(
        self,
        credential_id: int,
        holder_id: str,
        verifier: str,
        purpose: str,
        fields: list[str],
        expires_at: str,
        created_at: str,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO verification_requests(credential_id,holder_id,verifier,purpose,
                  requested_fields_json,status,created_at,expires_at)
               VALUES(?,?,?,?,?,'pending',?,?)""",
            (
                credential_id,
                holder_id,
                verifier,
                purpose,
                json.dumps(fields, ensure_ascii=False),
                created_at,
                expires_at,
            ),
        )
        return int(cur.lastrowid)

    def get_request(self, request_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM verification_requests WHERE id=?", (request_id,)
        ).fetchone()

    def list_requests(self, holder_id: str | None = None, verifier: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM verification_requests"
        clauses: list[str] = []
        params: list[Any] = []
        if holder_id is not None:
            clauses.append("holder_id=?")
            params.append(holder_id)
        if verifier is not None:
            clauses.append("verifier=?")
            params.append(verifier)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        return list(self.conn.execute(sql, params).fetchall())

    def set_request_status(self, request_id: int, status: str, consented_at: str | None = None) -> None:
        if consented_at is not None:
            self.conn.execute(
                "UPDATE verification_requests SET status=?,consented_at=? WHERE id=?",
                (status, consented_at, request_id),
            )
        else:
            self.conn.execute(
                "UPDATE verification_requests SET status=? WHERE id=?", (status, request_id)
            )

    # ---- 一次性授权 -----------------------------------------------------

    def insert_grant(self, request_id: int, fields: list[str], token: str, created_at: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO one_time_grants(request_id,approved_fields_json,token,status,created_at)
               VALUES(?,?,?,'available',?)""",
            (request_id, json.dumps(fields, ensure_ascii=False), token, created_at),
        )
        return int(cur.lastrowid)

    def get_grant_by_request(self, request_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM one_time_grants WHERE request_id=?", (request_id,)
        ).fetchone()

    def consume_grant_if_available(self, grant_id: int, consumed_at: str, consumed_by: str) -> bool:
        """条件更新：只有仍是 available 才能占用，返回是否抢到。

        这是一次性语义的持久化兜底：即便跨进程并发，数据库也只放行一笔。
        """
        cur = self.conn.execute(
            """UPDATE one_time_grants
                  SET status='consumed', consumed_at=?, consumed_by=?
                WHERE id=? AND status='available'""",
            (consumed_at, consumed_by, grant_id),
        )
        return cur.rowcount == 1

    def void_grant(self, grant_id: int) -> None:
        self.conn.execute(
            "UPDATE one_time_grants SET status='voided' WHERE id=? AND status='available'",
            (grant_id,),
        )

    # ---- 核验记录 -------------------------------------------------------

    def insert_record(
        self,
        request_id: int,
        grant_id: int,
        credential_id: int,
        holder_id: str,
        verifier: str,
        purpose: str,
        fields: list[str],
        claims: dict,
        verified_at: str,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO verification_records(request_id,grant_id,credential_id,holder_id,
                  verifier,purpose,disclosed_fields_json,disclosed_claims_json,verified_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                request_id,
                grant_id,
                credential_id,
                holder_id,
                verifier,
                purpose,
                json.dumps(fields, ensure_ascii=False),
                json.dumps(claims, ensure_ascii=False),
                verified_at,
            ),
        )
        return int(cur.lastrowid)

    def list_records(self, holder_id: str | None = None, verifier: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM verification_records"
        clauses: list[str] = []
        params: list[Any] = []
        if holder_id is not None:
            clauses.append("holder_id=?")
            params.append(holder_id)
        if verifier is not None:
            clauses.append("verifier=?")
            params.append(verifier)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        return list(self.conn.execute(sql, params).fetchall())
