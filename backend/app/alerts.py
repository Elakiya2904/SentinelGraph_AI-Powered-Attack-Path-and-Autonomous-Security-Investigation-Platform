from __future__ import annotations

import asyncio
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class AlertIn(BaseModel):
    timestamp: datetime | None = None
    source_host: str = Field(min_length=1, max_length=120)
    rule: str = Field(min_length=1, max_length=160)
    severity: int = Field(ge=0, le=10)
    raw_log_reference: str = Field(min_length=1, max_length=500)
    detector: str = "sentinelgraph-edr-agent"
    source: str = "production-enclave"
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    def normalized(self) -> dict[str, Any]:
        timestamp = self.timestamp or datetime.now(timezone.utc)
        return {
            "alert_id": f"alert-{uuid.uuid4().hex[:10]}",
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "source_host": self.source_host,
            "rule": self.rule,
            "severity": self.severity,
            "raw_log_reference": self.raw_log_reference,
            "detector": self.detector,
            "source": self.source,
            "raw_payload": self.raw_payload,
            "status": "queued",
        }


class AlertQueue:
    """In-memory queue plus replayable history for the isolated demo.

    The queue is intentionally process-local for portability. Phase 3 can replace the
    consumer with the investigation worker without changing the webhook contract.
    """

    def __init__(self, history_size: int = 200) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.lock = asyncio.Lock()

    async def publish(self, alert: dict[str, Any]) -> None:
        async with self.lock:
            self.history.appendleft(alert)
            await self.queue.put(alert)
            for subscriber in tuple(self.subscribers):
                await subscriber.put(alert)

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self.history)

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        subscriber: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        async with self.lock:
            self.subscribers.add(subscriber)
        return subscriber

    async def unsubscribe(self, subscriber: asyncio.Queue[dict[str, Any]]) -> None:
        async with self.lock:
            self.subscribers.discard(subscriber)

    def pending_count(self) -> int:
        return self.queue.qsize()
