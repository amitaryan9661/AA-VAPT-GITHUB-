"""
WebSocket connection manager — broadcasts real-time SOAR events to all clients.
"""
import json, logging
from fastapi import WebSocket

log = logging.getLogger("aavapt.ws")


class WSManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        log.info(f"WS client connected. Total: {len(self._connections)}")
        # Send welcome
        await self._send_one(ws, {"event": "connected",
                                   "data": {"clients": len(self._connections)}})

    def disconnect(self, ws: WebSocket):
        self._connections = [c for c in self._connections if c != ws]
        log.info(f"WS client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        dead = []
        payload = json.dumps(message)
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def _send_one(self, ws: WebSocket, message: dict):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


ws_manager = WSManager()
