"""
WebSocket connection manager — broadcasts real-time SOAR events to all clients.
ENH-09: Max connection limit added to prevent resource exhaustion.
"""
import json, logging
from fastapi import WebSocket

log = logging.getLogger("aavapt.ws")

# ENH-09: Maximum concurrent WebSocket connections
MAX_WS_CONNECTIONS = 50


class WSManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        # ENH-09: Reject if max connections reached
        if len(self._connections) >= MAX_WS_CONNECTIONS:
            await ws.accept()
            await ws.send_text(json.dumps({
                "event": "error",
                "data": {"message": f"Max WebSocket connections ({MAX_WS_CONNECTIONS}) reached. Try again later."}
            }))
            await ws.close(code=1008)
            log.warning(f"WS connection rejected — max {MAX_WS_CONNECTIONS} reached")
            return
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
        """Send message to all connected clients.
        FIX BUG-06: Iterate over snapshot copy to prevent crash during concurrent disconnect."""
        dead = []
        payload = json.dumps(message)
        for ws in list(self._connections):   # snapshot prevents RuntimeError on size change
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
