#!/usr/bin/env python3
"""一次性出示的占用状态（进程内）。

同一核验申请可能被多个请求线程同时取用。这里按申请 ID 维护一把锁与
"在途占用"集合：进入临界区时登记占用，结束后释放。锁内由持久化层的
条件更新做最终裁决，保证同一申请只有一笔兑付成功。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator


class GrantOccupancy:
    """按核验申请串行化取用，并跟踪在途占用。"""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[int, threading.Lock] = {}
        self._in_flight: set[int] = set()

    def _lock_for(self, request_id: int) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(request_id, threading.Lock())

    @contextmanager
    def occupy(self, request_id: int) -> Iterator[None]:
        """占用某个申请的取用通道；退出时释放并清除在途标记。"""
        lock = self._lock_for(request_id)
        with lock:
            with self._guard:
                self._in_flight.add(request_id)
            try:
                yield
            finally:
                with self._guard:
                    self._in_flight.discard(request_id)

    def snapshot(self) -> dict:
        """当前在途占用与已分配的锁，供状态页展示。"""
        with self._guard:
            return {
                "in_flight": sorted(self._in_flight),
                "tracked_requests": sorted(self._locks),
            }
