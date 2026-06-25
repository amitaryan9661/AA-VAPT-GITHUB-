# -*- coding: utf-8 -*-
"""
Interactive PTY terminal over WebSocket — a REAL WSL bash inside the browser.

Client (xterm.js)  ⇄  /ws/terminal  ⇄  pty.fork() → bash

Protocol (client → server, JSON text frames):
    {"type":"input","data":"<keystrokes>"}
    {"type":"resize","cols":N,"rows":N}
Server → client: raw terminal output (text frames).

SECURITY: localhost-only. This is remote code execution by design — it must
NEVER be exposed on a network interface. The handler rejects non-local clients.

Design notes:
  • Output is funneled through a single asyncio.Queue + one sender task, so we
    never issue concurrent ws.send_text() calls (which can corrupt frames).
  • An incremental UTF-8 decoder handles multi-byte chars split across reads.
"""
import os
import json
import codecs
import signal
import struct
import asyncio
import logging

from fastapi import WebSocket, WebSocketDisconnect

# Platform-specific modules (Linux/WSL only). Guard so that importing this
# module NEVER crashes the backend on a platform without them (e.g. native
# Windows Python). If unavailable, the terminal endpoint degrades gracefully.
try:
    import pty
    import fcntl
    import termios
    _PTY_OK = True
    _PTY_ERR = ""
except Exception as _e:          # pragma: no cover - platform dependent
    pty = fcntl = termios = None
    _PTY_OK = False
    _PTY_ERR = str(_e)

log = logging.getLogger("aavapt.terminal")

_SHELL = os.environ.get("AAVAPT_SHELL", "/bin/bash")
_LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1")


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


async def terminal_session(ws: WebSocket):
    # ── Security: localhost only ──
    host = (ws.client.host if ws.client else "") or ""
    if host not in _LOCAL_HOSTS:
        log.warning("terminal: rejected non-local client %s", host)
        try:
            await ws.close(code=1008)
        except Exception:
            pass
        return

    await ws.accept()

    # ── Platform guard: PTY needs Linux/WSL ──
    if not _PTY_OK:
        try:
            await ws.send_text(
                "\r\n[!] Interactive terminal needs a Linux/WSL backend "
                "(pty/fcntl/termios unavailable here).\r\n"
                "    Run the AA-VAPT backend inside WSL Ubuntu to use this.\r\n"
                + (("    (%s)\r\n" % _PTY_ERR) if _PTY_ERR else "")
            )
            await ws.close()
        except Exception:
            pass
        return

    # ── Spawn a real bash with a controlling pty ──
    try:
        pid, master = pty.fork()
    except Exception as e:
        try:
            await ws.send_text("\r\n[!] PTY unavailable (need WSL/Linux): %s\r\n" % e)
            await ws.close()
        except Exception:
            pass
        return

    if pid == 0:
        # ── child process — becomes bash, never returns ──
        try:
            os.environ["TERM"] = "xterm-256color"
            try:
                os.chdir(os.path.expanduser("~"))
            except Exception:
                pass
            os.execvp(_SHELL, [_SHELL, "-l"])
        except Exception:
            os._exit(1)

    # ── parent: bridge pty <-> websocket ──
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    loop = asyncio.get_running_loop()
    out_q: asyncio.Queue = asyncio.Queue()

    def _on_readable():
        try:
            data = os.read(master, 65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""          # treat as EOF
        try:
            out_q.put_nowait(data)  # b"" signals EOF
        except Exception:
            pass

    try:
        loop.add_reader(master, _on_readable)
    except Exception as e:
        log.warning("terminal: add_reader failed: %s", e)

    # single sender: serialize all output, decode incrementally
    async def _pump():
        dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            data = await out_q.get()
            if not data:                     # EOF from pty (shell exited)
                return
            try:
                await ws.send_text(dec.decode(data))
            except Exception:
                return

    # receiver: keystrokes / resize -> pty
    async def _recv():
        while True:
            msg = await ws.receive_text()
            try:
                obj = json.loads(msg)
            except Exception:
                obj = {"type": "input", "data": msg}
            if obj.get("type") == "resize":
                _set_winsize(master,
                             int(obj.get("rows", 24) or 24),
                             int(obj.get("cols", 80) or 80))
            else:
                try:
                    os.write(master, (obj.get("data", "") or "").encode())
                except OSError:
                    return

    pump_task = asyncio.ensure_future(_pump())
    recv_task = asyncio.ensure_future(_recv())
    try:
        # finish as soon as EITHER side ends (shell exit or client disconnect)
        await asyncio.wait({pump_task, recv_task}, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning("terminal: %s", e)
    finally:
        for t in (pump_task, recv_task):
            if not t.done():
                t.cancel()
            else:
                # retrieve any exception so asyncio doesn't log "never retrieved"
                try:
                    t.exception()
                except Exception:
                    pass
        try:
            loop.remove_reader(master)
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            # blocking reap — immediate after SIGKILL; prevents zombies
            os.waitpid(pid, 0)
        except Exception:
            pass
        try:
            os.close(master)
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass
        log.info("terminal session closed")
