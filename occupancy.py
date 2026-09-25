#!/usr/bin/env python3
"""占用状态层：进程内“正在取用”登记。

同一笔核验申请的一次性凭证被并发取用时，占用注册表只允许一个请求进入
关键区，其余立刻拿到 409。真正的一次性语义由持久化层的条件更新兜底
（多进程部署或进程重启后依然成立），本层负责把单进程内的并发挡在前面。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator


class OccupancyRegistry:
    def __init__(self) -> None:
        self._busy: set[int] = set()
        self._global = threading.Lock()
        self._per_key: dict[int, threading.Lock] = {}

    @contextmanager
    def occupy(self, request_id: int) -> Iterator[None]:
        """占用某笔申请；已被其他线程占用时抛出 RuntimeError。"""
        with self._global:
            lock = self._per_key.setdefault(request_id, threading.Lock())
            if request_id in self._busy:
                raise RuntimeError("该申请正在被取用，请等待当前核验完成")
            self._busy.add(request_id)
        try:
            with lock:
                yield
        finally:
            with self._global:
                self._busy.discard(request_id)
                self._per_key.pop(request_id, None)

    def busy_keys(self) -> list[int]:
        with self._global:
            return sorted(self._busy)
