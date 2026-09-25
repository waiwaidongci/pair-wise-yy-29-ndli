#!/usr/bin/env python3
"""持久化层：SQLite 连接、建表、审计与共享工具。

业务文件分层：
- persistence.py：本文件，只管落盘；
- occupancy.py  ：进程内占用状态（并发取用时的第一道闸门）；
- verification.py：核验申请、同意、一次性出示与撤回的请求处理。
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

DB_PATH = Path(__file__).with_name("data.db")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def token_digest(raw_token: str) -> str:
    """一次性凭证以哈希形式落盘，原始令牌只在同意响应中返回一次。"""
    return hashlib.sha256(raw_token.encode()).hexdigest()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        # check_same_thread=False：ThreadingHTTPServer 多线程共享。
        # 共享连接上的写事务必须串行，否则不同线程的语句会交错进同一个
        # sqlite3 隐式事务，破坏条件更新的原子性。
        self._write_lock = threading.RLock()
        self._txn_depth = 0
        # check_same_thread=False：ThreadingHTTPServer 多线程共享，写操作靠事务串行化。
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              secret_hex TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','retired')),
              created_at TEXT NOT NULL,
              retired_at TEXT,
              UNIQUE(issuer, version)
            );
            CREATE TABLE IF NOT EXISTS templates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              code TEXT NOT NULL,
              name TEXT NOT NULL,
              fields_json TEXT NOT NULL,
              validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
              status TEXT NOT NULL CHECK(status IN ('active','disabled')),
              created_at TEXT NOT NULL,
              UNIQUE(issuer, code)
            );
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              claims_json TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
              key_version INTEGER NOT NULL,
              idempotency_key TEXT NOT NULL,
              revocation_reason TEXT,
              revocation_effective_at TEXT,
              UNIQUE(template_id, holder_id, idempotency_key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
              ON credentials(template_id, holder_id)
              WHERE status IN ('active','disputed');
            CREATE TABLE IF NOT EXISTS disputes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              raised_by TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
              resolution TEXT,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verification_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              verifier_id TEXT NOT NULL,
              purpose TEXT NOT NULL,
              requested_fields_json TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN
                ('pending','approved','consumed','withdrawn','expired','rejected')),
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              decided_at TEXT,
              approved_fields_json TEXT,
              voucher_expires_at TEXT,
              voucher_token_hash TEXT,
              consumed_at TEXT,
              withdrawn_at TEXT
            );
            CREATE TABLE IF NOT EXISTS verification_records (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              request_id INTEGER NOT NULL REFERENCES verification_requests(id),
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              verifier_id TEXT NOT NULL,
              purpose TEXT NOT NULL,
              fields_json TEXT NOT NULL,
              result_json TEXT NOT NULL,
              at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """串行化的可重入写事务。

        最外层负责开启/提交 SQLite 事务，嵌套层只计数，避免内层上下文
        提前 commit 掉外层尚未完成的多条更新。
        """
        with self._write_lock:
            outer = self._txn_depth == 0
            self._txn_depth += 1
            try:
                if outer:
                    with self.conn:
                        yield
                else:
                    yield
            finally:
                self._txn_depth -= 1

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        with self.transaction():
            self.conn.execute(
                "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
                (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
            )

    def close(self) -> None:
        self.conn.close()
