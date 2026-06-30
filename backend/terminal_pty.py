# -*- coding: utf-8 -*-
"""
Interactive PTY terminal over WebSocket — Real Kali Linux shell in the browser.

Supports two modes (auto-detected, configurable via env vars):

  MODE 1 — LOCAL (default if running directly on Kali/Linux):
    Backend runs ON Kali Linux. Opens a real /bin/zsh (or /bin/bash) PTY.
    Client (xterm.js) ⇄ /ws/terminal ⇄ pty.fork() → zsh

  MODE 2 — REMOTE SSH (if KALI_SSH_HOST is set):
    Backend runs anywhere. Connects to a remote Kali machine via SSH.
    Client (xterm.js) ⇄ /ws/terminal ⇄ paramiko SSH → Kali Linux

Environment Variables:
  AAVAPT_SHELL         Override shell path (default: auto-detect zsh/bash)
  KALI_SSH_HOST        Remote Kali IP/hostname (enables SSH mode)
  KALI_SSH_PORT        SSH port (default: 22)
  KALI_SSH_USER        SSH username (default: kali)
  KALI_SSH_PASS        SSH password (mutually exclusive with key)
  KALI_SSH_KEY         Path to private key file (preferred over password)
  KALI_SSH_TIMEOUT     SSH connect timeout seconds (default: 10)

Protocol (client → server, JSON text frames):
    {"type":"input","data":"<keystrokes>"}
    {"type":"resize","cols":N,"rows":N}
Server → client: raw terminal output (text frames).

SECURITY: localhost-only for local mode. Remote mode requires valid SSH creds.
          This is remote code execution by design — never expose on public network.
"""
import os
import json
import codecs
import signal
import struct
import asyncio
import logging

from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger("aavapt.terminal")

# ─────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────

_LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1")

# SSH / Remote Kali config
_KALI_SSH_HOST    = os.environ.get("KALI_SSH_HOST", "").strip()
_KALI_SSH_PORT    = int(os.environ.get("KALI_SSH_PORT", "22"))
_KALI_SSH_USER    = os.environ.get("KALI_SSH_USER", "kali").strip()
_KALI_SSH_PASS    = os.environ.get("KALI_SSH_PASS", "").strip()
_KALI_SSH_KEY     = os.environ.get("KALI_SSH_KEY", "").strip()
_KALI_SSH_TIMEOUT = int(os.environ.get("KALI_SSH_TIMEOUT", "10"))

_SSH_MODE = bool(_KALI_SSH_HOST)

# Shell auto-detection for local mode
def _detect_shell() -> str:
    override = os.environ.get("AAVAPT_SHELL", "").strip()
    if override and os.path.isfile(override):
        return override
    # Kali default is zsh, fall back to bash
    for sh in ("/bin/zsh", "/usr/bin/zsh", "/bin/bash", "/usr/bin/bash"):
        if os.path.isfile(sh):
            return sh
    return "/bin/bash"

_SHELL = _detect_shell()

# ─────────────────────────────────────────────────────────────
#  PTY support (local Linux/Kali only)
# ─────────────────────────────────────────────────────────────
try:
    import pty
    import fcntl
    import termios
    _PTY_OK = True
    _PTY_ERR = ""
except Exception as _e:
    pty = fcntl = termios = None
    _PTY_OK = False
    _PTY_ERR = str(_e)

# ─────────────────────────────────────────────────────────────
#  Paramiko SSH support (remote Kali mode)
# ─────────────────────────────────────────────────────────────
try:
    import paramiko
    _PARAMIKO_OK = True
    _PARAMIKO_ERR = ""
except ImportError:
    paramiko = None
    _PARAMIKO_OK = False
    _PARAMIKO_ERR = "paramiko not installed. Run: pip install paramiko --break-system-packages"


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  Kali Linux environment banner
# ─────────────────────────────────────────────────────────────

def _kali_banner(mode: str) -> str:
    return (
        "\r\n"
        "\033[1;32m"
        "  ╔══════════════════════════════════════════╗\r\n"
        "  ║   AA-VAPT — Kali Linux Terminal          ║\r\n"
        f"  ║   Mode : {mode:<32}║\r\n"
        f"  ║   Shell: {_SHELL:<32}║\r\n"
        "  ╚══════════════════════════════════════════╝"
        "\033[0m\r\n\r\n"
    )


# ─────────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────────

async def terminal_session(ws: WebSocket):
    """Main WebSocket terminal handler — routes to SSH or local PTY."""
    # Security: local-only for non-SSH mode
    host = (ws.client.host if ws.client else "") or ""
    if not _SSH_MODE and host not in _LOCAL_HOSTS:
        log.warning("terminal: rejected non-local client %s (local PTY mode)", host)
        try:
            await ws.close(code=1008)
        except Exception:
            pass
        return

    await ws.accept()

    if _SSH_MODE:
        await _ssh_terminal(ws)
    else:
        await _local_terminal(ws)


# ─────────────────────────────────────────────────────────────
#  MODE 1 — Local PTY (Kali running on same host as backend)
# ─────────────────────────────────────────────────────────────

async def _local_terminal(ws: WebSocket):
    """Open a real Kali Linux shell via PTY on the local machine."""
    if not _PTY_OK:
        try:
            await ws.send_text(
                "\r\n\033[1;31m[!] PTY unavailable on this platform.\033[0m\r\n"
                "    Run the AA-VAPT backend directly on Kali Linux, or set\r\n"
                "    KALI_SSH_HOST to connect to a remote Kali machine.\r\n"
                + (f"    Error: {_PTY_ERR}\r\n" if _PTY_ERR else "")
            )
            await ws.close()
        except Exception:
            pass
        return

    try:
        pid, master = pty.fork()
    except Exception as e:
        try:
            await ws.send_text(f"\r\n\033[1;31m[!] PTY fork failed: {e}\033[0m\r\n")
            await ws.close()
        except Exception:
            pass
        return

    if pid == 0:
        # ── child: become Kali shell ──
        try:
            os.environ["TERM"]      = "xterm-256color"
            os.environ["SHELL"]     = _SHELL
            os.environ["COLORTERM"] = "truecolor"
            # Kali-specific environment
            os.environ.setdefault("PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                "/sbin:/bin:/usr/games:/usr/local/games:/snap/bin")
            try:
                os.chdir(os.path.expanduser("~"))
            except Exception:
                pass
            os.execvp(_SHELL, [_SHELL, "-l"])
        except Exception:
            os._exit(1)

    # ── parent: bridge pty ↔ websocket ──
    try:
        await ws.send_text(_kali_banner(f"Local PTY ({_SHELL})"))
    except Exception:
        pass

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
            data = b""
        try:
            out_q.put_nowait(data)
        except Exception:
            pass

    try:
        loop.add_reader(master, _on_readable)
    except Exception as e:
        log.warning("terminal: add_reader failed: %s", e)

    async def _pump():
        dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            data = await out_q.get()
            if not data:
                return
            try:
                await ws.send_text(dec.decode(data))
            except Exception:
                return

    async def _recv():
        while True:
            try:
                msg = await ws.receive_text()
            except Exception:
                return
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
        await asyncio.wait({pump_task, recv_task}, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning("terminal(local): %s", e)
    finally:
        for t in (pump_task, recv_task):
            if not t.done():
                t.cancel()
            else:
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
        log.info("terminal(local): session closed")


# ─────────────────────────────────────────────────────────────
#  MODE 2 — Remote SSH to Kali Linux machine
# ─────────────────────────────────────────────────────────────

async def _ssh_terminal(ws: WebSocket):
    """Connect to a remote Kali Linux machine via SSH and bridge to WebSocket."""
    if not _PARAMIKO_OK:
        try:
            await ws.send_text(
                f"\r\n\033[1;31m[!] SSH mode requires paramiko.\033[0m\r\n"
                f"    {_PARAMIKO_ERR}\r\n"
            )
            await ws.close()
        except Exception:
            pass
        return

    try:
        await ws.send_text(
            f"\r\n\033[1;33m[*] Connecting to Kali Linux at "
            f"{_KALI_SSH_USER}@{_KALI_SSH_HOST}:{_KALI_SSH_PORT} ...\033[0m\r\n"
        )
    except Exception:
        return

    loop = asyncio.get_running_loop()

    def _connect_ssh():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = dict(
            hostname=_KALI_SSH_HOST,
            port=_KALI_SSH_PORT,
            username=_KALI_SSH_USER,
            timeout=_KALI_SSH_TIMEOUT,
            banner_timeout=_KALI_SSH_TIMEOUT,
        )
        if _KALI_SSH_KEY and os.path.isfile(_KALI_SSH_KEY):
            connect_kwargs["key_filename"] = _KALI_SSH_KEY
        elif _KALI_SSH_PASS:
            connect_kwargs["password"] = _KALI_SSH_PASS
            connect_kwargs["look_for_keys"] = False
        else:
            raise ValueError(
                "Set KALI_SSH_PASS or KALI_SSH_KEY to authenticate with the Kali machine."
            )
        ssh.connect(**connect_kwargs)
        return ssh

    try:
        ssh = await loop.run_in_executor(None, _connect_ssh)
    except Exception as e:
        log.error("SSH connect failed: %s", e)
        try:
            await ws.send_text(
                f"\r\n\033[1;31m[!] SSH connection FAILED: {e}\033[0m\r\n"
                f"    Check KALI_SSH_HOST / KALI_SSH_USER / KALI_SSH_PASS env vars.\r\n"
            )
            await ws.close()
        except Exception:
            pass
        return

    try:
        await ws.send_text(_kali_banner(f"SSH → {_KALI_SSH_USER}@{_KALI_SSH_HOST}"))
    except Exception:
        pass

    # Open interactive shell channel
    chan = ssh.invoke_shell(term="xterm-256color", width=220, height=50)
    chan.setblocking(False)
    log.info("SSH terminal connected: %s@%s", _KALI_SSH_USER, _KALI_SSH_HOST)

    out_q: asyncio.Queue = asyncio.Queue()

    def _ssh_reader():
        """Read from SSH channel in a background thread."""
        import time
        while True:
            try:
                if chan.recv_ready():
                    data = chan.recv(65536)
                    if not data:
                        out_q.put_nowait(b"")
                        break
                    out_q.put_nowait(data)
                elif chan.closed or chan.exit_status_ready():
                    out_q.put_nowait(b"")
                    break
                else:
                    time.sleep(0.01)
            except Exception:
                out_q.put_nowait(b"")
                break

    reader_thread = loop.run_in_executor(None, _ssh_reader)

    async def _pump():
        dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            data = await out_q.get()
            if not data:
                return
            try:
                await ws.send_text(dec.decode(data))
            except Exception:
                return

    async def _recv():
        while True:
            try:
                msg = await ws.receive_text()
            except Exception:
                return
            try:
                obj = json.loads(msg)
            except Exception:
                obj = {"type": "input", "data": msg}
            t = obj.get("type", "input")
            if t == "resize":
                rows = int(obj.get("rows", 24) or 24)
                cols = int(obj.get("cols", 80) or 80)
                try:
                    chan.resize_pty(width=cols, height=rows)
                except Exception:
                    pass
            else:
                data = (obj.get("data", "") or "").encode()
                if data:
                    try:
                        chan.sendall(data)
                    except Exception:
                        return

    pump_task = asyncio.ensure_future(_pump())
    recv_task = asyncio.ensure_future(_recv())
    try:
        await asyncio.wait({pump_task, recv_task}, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning("terminal(ssh): %s", e)
    finally:
        for t in (pump_task, recv_task):
            if not t.done():
                t.cancel()
            else:
                try:
                    t.exception()
                except Exception:
                    pass
        try:
            chan.close()
        except Exception:
            pass
        try:
            ssh.close()
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass
        log.info("terminal(ssh): session closed — %s@%s", _KALI_SSH_USER, _KALI_SSH_HOST)


# ─────────────────────────────────────────────────────────────
#  Status API helper
# ─────────────────────────────────────────────────────────────

def terminal_status() -> dict:
    """Return terminal configuration for /api/status."""
    if _SSH_MODE:
        return {
            "mode": "ssh",
            "kali_host": _KALI_SSH_HOST,
            "kali_port": _KALI_SSH_PORT,
            "kali_user": _KALI_SSH_USER,
            "auth": "key" if _KALI_SSH_KEY else ("password" if _KALI_SSH_PASS else "none"),
            "paramiko_available": _PARAMIKO_OK,
            "ready": _PARAMIKO_OK and bool(_KALI_SSH_HOST),
        }
    else:
        return {
            "mode": "local",
            "shell": _SHELL,
            "pty_available": _PTY_OK,
            "ready": _PTY_OK,
            "note": "Running on local Kali Linux" if _PTY_OK else _PTY_ERR,
        }
