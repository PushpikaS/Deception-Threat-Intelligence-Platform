"""WebSocket live feed — Redis pub/sub bridge."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.deps import get_redis

router = APIRouter()
log = logging.getLogger(__name__)

LIVE_CHANNEL = "tip:live"


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await websocket.accept()
    redis = get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe(LIVE_CHANNEL)

    async def reader():
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    data = msg["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    await websocket.send_text(data)
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            pass

    task = asyncio.create_task(reader())
    try:
        while True:
            try:
                await websocket.receive_text()
            except WebSocketDisconnect:
                break
    finally:
        task.cancel()
        await pubsub.unsubscribe(LIVE_CHANNEL)
        await pubsub.close()