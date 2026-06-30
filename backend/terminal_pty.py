# -*- coding: utf-8 -*-
"""
Interactive Terminal over WebSocket — Real Kali Linux shell in the browser.

Auto-detects environment and picks the best available mode:

  MODE 1 — Local PTY (Kali/Linux backend):
    Opens a real /bin/zsh (or /bin/bash) PTY.
    xterm.js ⇄ /ws/terminal ⇄ pty.fork() → zsh

  MODE 2 — Windows WSL Bridge (Windows backend + WSL installed):
    Bridges commands through wsl.exe to a real Kali shell.
    xterm.js/Lite ⇄ /ws/terminal ⇄ wsl.exe bash → Kali

  MODE 3 — Remote SSH (KALI_SSH_HOST env var set):
    Connects to a remote Kali machine via SSH paramiko.
    xterm.js ⇄ /ws/terminal ⇄ paramiko SSH → Kali

Environment Variables:
  AAVAPT_SHELL         Override shell path (default: auto-detect zsh/bash)
  KALI_SSH_HOST        Remote Kali IP/hostname (enables SSH mode)
  KALI_SSH_PORT        SSH port (default: 22)
  KALI_SSH_USER        SSH username (default: kali)
  KALI_SSH_PASS        SSH password
  KALI_SSH_KEY         Path to private key file (preferred over password)
  KALI_SSH_TIMEOUT     SSH connect timeout seconds (default: 10)
  KALI_WSL_DISTRO      WSL distro name to use (default: auto-detect Kali)

Protocol (client → server, JSON text frames):
    {"type":"input","data":"<keystrokes or full line>"}
    {"type":"resize","cols":N,"rows":N}
Server → client: raw terminal output (text frames).

SECURITY: localhost-only for local/WSL modes.
"""
import os
import sys
import json
import codecs
import signal
import struct
import shutil
import asyncio
import logging

from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger("aavapt.terminal")

# ─────────────────────────────────────────────────────────────
#  Platform detection
# ─────────────────────────────────────────────────────────────

_IS_WINDOWS = sys.platform.startswith("win")
_LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1", "0:0:0:0:0:0:0:1")

# ─────────────────────────────────────────────────────────────
#  SSH / Remote config
# ─────────────────────────────────────────────────────────────

_KALI_SSH_HOST    = os.environ.get("KALI_SSH_HOST", "").strip()
_KALI_SSH_PORT    = int(os.environ.get("KALI_SSH_PORT", "22"))
_KALI_SSH_USER    = os.environ.get("KALI_SSH_USER", "kali").strip()
_KALI_SSH_PASS    = os.environ.get("KALI_SSH_PASS", "").strip()
_KALI_SSH_KEY     = os.environ.get("KALI_SSH_KEY", "").strip()
_KALI_SSH_TIMEOUT = int(os.environ.get("KALI_SSH_TIMEOUT", "10"))
_KALI_WSL_DISTRO  = os.environ.get("KALI_WSL_DISTRO", "").strip()

_SSH_MODE = bool(_KALI_SSH_HOST)

# ─────────────────────────────────────────────────────────────
#  PTY support (local Linux/Kali only)
# ─────────────────────────────────────────────────────────────
try:
    import pty
    import fcntl
    import termios
    _PTY_OK  = True
    _PTY_ERR = ""
except Exception as _e:
    pty = fcntl = termios = None
    _PTY_OK  = False
    _PTY_ERR = str(_e)

# ─────────────────────────────────────────────────────────────
#  WSL bridge support (Windows only)
# ─────────────────────────────────────────────────────────────
_WSL_BIN = shutil.which("wsl") if _IS_WINDOWS else None
_WSL_OK  = bool(_WSL_BIN)

def _detect_wsl_distro() -> str:
    """Return best Kali distro name for -d flag, or '' for default."""
    if not _KALI_WSL_DISTRO and _WSL_BIN:
        try:
            import subprocess
            r = subprocess.run(
                ["wsl", "--list", "--quiet"],
                capture_output=True, timeout=5,
            )
            lines = r.stdout.decode("utf-16-le", errors="replace").splitlines()
            for line in lines:
                l = line.strip().lower()
                if "kali" in l:
                    return line.strip()
        except Exception:
            pass
    return _KALI_WSL_DISTRO

_WSL_DISTRO = _detect_wsl_distro()

def _wsl_cmd_prefix() -> list:
    """Build wsl.exe prefix args (with optional -d distro)."""
    args = ["wsl"]
    if _WSL_DISTRO:
        args += ["-d", _WSL_DISTRO]
    return args

# ─────────────────────────────────────────────────────────────
#  Paramiko SSH support
# ─────────────────────────────────────────────────────────────
try:
    import paramiko
    _PARAMIKO_OK  = True
    _PARAMIKO_ERR = ""
except ImportError:
    paramiko       = None
    _PARAMIKO_OK  = False
    _PARAMIKO_ERR = "paramiko not installed. Run: pip install paramiko --break-system-packages"

# ─────────────────────────────────────────────────────────────
#  Shell auto-detection (local mode)
# ─────────────────────────────────────────────────────────────

def _detect_shell() -> str:
    override = os.environ.get("AAVAPT_SHELL", "").strip()
    if override and os.path.isfile(override):
        return override
    for sh in ("/bin/zsh", "/usr/bin/zsh", "/bin/bash", "/usr/bin/bash"):
        if os.path.isfile(sh):
            return sh
    return "/bin/bash"

_SHELL = _detect_shell()


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  Kali banner
# ─────────────────────────────────────────────────────────────

def _kali_banner(mode: str) -> str:
    return (
        "\r\n"
        "\033[1;32m"
        "  ╔══════════════════════════════════════════╗\r\n"
        "  ║   AA-VAPT — Kali Linux Terminal          ║\r\n"
        f"  ║   Mode : {mode:<32}║\r\n"
        "  ╚══════════════════════════════════════════╝"
        "\033[0m\r\n\r\n"
    )


# ─────────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────────

async def terminal_session(ws: WebSocket):
    """
    Main WebSocket handler — auto-selects SSH / local PTY / WSL bridge.
    Priority: SSH > local PTY > WSL bridge > error.
    """
    # Security: local-only for non-SSH modes
    host = (ws.client.host if ws.client else "") or ""
    if not _SSH_MODE and host not in _LOCAL_HOSTS:
        log.warning("terminal: rejected non-local client %s", host)
        await ws.accept()  # MUST accept before close (HTTP upgrade must complete)
        await ws.send_text(
            "\r\n\033[1;31m[!] Terminal access denied.\033[0m\r\n"
            "    Only localhost connections are permitted.\r\n"
        )
        await ws.close(code=1008)
        return

    await ws.accept()

    if _SSH_MODE:
        await _ssh_terminal(ws)
    elif _PTY_OK:
        await _local_terminal(ws)
    elif _WSL_OK:
        await _wsl_bridge_terminal(ws)
    else:
        await ws.send_text(
            "\r\n\033[1;31m[!] No terminal backend available.\033[0m\r\n"
            "    Options:\r\n"
            "    1. Run AA-VAPT directly on Kali Linux (local PTY)\r\n"
            "    2. Install WSL + Kali: wsl --install -d kali-linux\r\n"
            "    3. Set KALI_SSH_HOST to use remote SSH to Kali\r\n"
        )
        await ws.close()


# ─────────────────────────────────────────────────────────────
#  MODE 1 — Local PTY (Kali on same host)
# ─────────────────────────────────────────────────────────────

async def _local_terminal(ws: WebSocket):
    """Open a real Kali Linux shell via PTY on the local machine."""
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
        # child: become Kali shell
        try:
            os.environ["TERM"]      = "xterm-256color"
            os.environ["SHELL"]     = _SHELL
            os.environ["COLORTERM"] = "truecolor"
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

    # parent: bridge pty ↔ websocket
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

    pump_task = asyncio.create_task(_pump())
    recv_task = asyncio.create_task(_recv())
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
#  MODE 2 — Windows WSL Bridge
# ─────────────────────────────────────────────────────────────

async def _wsl_bridge_terminal(ws: WebSocket):
    """
    Windows WSL Bridge — runs commands through wsl.exe, streams output in real-time.

    Protocol (lite-mode compatible):
      Client sends {"type":"input","data":"<line>\\n"} for each command.
      Server echoes characters and streams output.
      Ctrl+C (\\x03) kills the running subprocess.
    """
    wsl_prefix = _wsl_cmd_prefix()
    distro_info = f" [{_WSL_DISTRO}]" if _WSL_DISTRO else ""
    await ws.send_text(_kali_banner(f"Windows → WSL{distro_info}"))
    await ws.send_text(
        "\033[1;33m⚡ WSL Bridge mode — commands run inside Kali Linux via WSL\033[0m\r\n"
        "   Tip: Type 'install-kali-tools' to install all pentest tools\r\n\r\n"
    )

    # Detect home directory in WSL
    try:
        _r = await asyncio.create_subprocess_exec(
            *wsl_prefix, "-e", "bash", "-c", "echo $HOME",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        _out, _ = await asyncio.wait_for(_r.communicate(), timeout=5)
        cwd = _out.decode("utf-8", errors="replace").strip() or "/root"
    except Exception:
        cwd = "/root"

    # Shared state
    current_proc = [None]  # list so closure can mutate it

    # Input queue — receives parsed WS messages
    input_q: asyncio.Queue = asyncio.Queue()

    async def _recv_loop():
        """Continuously read WebSocket messages into input_q."""
        while True:
            try:
                msg = await ws.receive_text()
                try:
                    obj = json.loads(msg)
                except Exception:
                    obj = {"type": "input", "data": msg}
                await input_q.put(obj)
            except Exception:
                await input_q.put(None)  # EOF sentinel
                return

    recv_task = asyncio.create_task(_recv_loop())

    async def _show_prompt():
        try:
            await ws.send_text(
                f"\033[1;32mroot@kali\033[0m:\033[1;34m{cwd}\033[0m\033[1;37m$\033[0m "
            )
        except Exception:
            pass

    async def _wsl_resolve_path(path: str, base: str) -> str:
        """Resolve a path inside WSL relative to base."""
        try:
            r = await asyncio.create_subprocess_exec(
                *wsl_prefix, "-e", "bash", "-c",
                f'cd "{base}" 2>/dev/null; cd "{path}" 2>/dev/null && pwd',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(r.communicate(), timeout=5)
            result = out.decode("utf-8", errors="replace").strip()
            return result if result else base
        except Exception:
            return base

    try:
        while True:
            await _show_prompt()

            # ── Accumulate a complete line from the input queue ──
            line_buf = ""
            while True:
                obj = await input_q.get()
                if obj is None:
                    return  # WebSocket disconnected

                t   = obj.get("type", "input")
                dat = obj.get("data", "")

                if t == "resize":
                    continue

                # Ctrl+C while at prompt — clear line
                if dat == "\x03":
                    line_buf = ""
                    await ws.send_text("^C\r\n")
                    break

                # Backspace
                if dat in ("\x7f", "\x08"):
                    if line_buf:
                        line_buf = line_buf[:-1]
                        await ws.send_text("\b \b")
                    continue

                # Line ending or multi-line block → execute
                if "\r" in dat or "\n" in dat:
                    cleaned = dat.replace("\r\n", "\n").replace("\r", "\n")
                    parts   = cleaned.split("\n")
                    non_empty = [p for p in parts if p.strip()]
                    if len(non_empty) > 1:
                        # Multi-line block (heredoc, script) — run entire thing as script
                        line_buf = cleaned.rstrip("\n")
                    else:
                        # Single line — take text before the newline
                        line_buf += parts[0]
                    await ws.send_text("\r\n")
                    break

                # Regular character — echo and accumulate (xterm keystroke mode)
                line_buf += dat
                await ws.send_text(dat)

            cmd = line_buf.strip()
            if not cmd:
                continue

            # ── Built-in: clear ──
            if cmd in ("clear", "reset"):
                await ws.send_text("\033[2J\033[H")
                continue

            # ── Built-in: exit / logout ──
            if cmd in ("exit", "logout", "quit"):
                await ws.send_text("\r\n\033[1;33mBye! Reconnect to open a new session.\033[0m\r\n")
                return

            # ── Built-in: cd ──
            if cmd == "cd" or cmd.startswith("cd "):
                new_dir = cmd[3:].strip() if cmd.startswith("cd ") else ""
                if not new_dir or new_dir == "~":
                    new_dir = "/root"
                # Handle relative paths correctly
                resolved = await _wsl_resolve_path(new_dir, cwd)
                if resolved and resolved != cwd:
                    cwd = resolved
                else:
                    # Try to get error from WSL
                    try:
                        r2 = await asyncio.create_subprocess_exec(
                            *wsl_prefix, "-e", "bash", "-c",
                            f'cd "{cwd}" && cd "{new_dir}"',
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        _, err = await asyncio.wait_for(r2.communicate(), timeout=5)
                        if err:
                            await ws.send_text(
                                "\033[1;31m" + err.decode("utf-8", errors="replace")
                                .replace("\n", "\r\n") + "\033[0m"
                            )
                    except Exception:
                        pass
                continue

            # ── Run command in WSL ──
            bash_cmd = f'cd "{cwd}" 2>/dev/null; {cmd}'
            try:
                # Use CREATE_NO_WINDOW on Windows to avoid a flash
                kwargs = {}
                if _IS_WINDOWS:
                    import subprocess as _sp
                    kwargs["creationflags"] = getattr(_sp, "CREATE_NO_WINDOW", 0)

                proc = await asyncio.create_subprocess_exec(
                    *wsl_prefix, "-e", "bash", "-c", bash_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    **kwargs,
                )
                current_proc[0] = proc

                # Stream output + watch for Ctrl+C
                output_done = asyncio.Event()

                async def _stream():
                    try:
                        dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
                        while True:
                            try:
                                chunk = await asyncio.wait_for(
                                    proc.stdout.read(2048), timeout=0.1
                                )
                                if not chunk:
                                    break
                                text = dec.decode(chunk).replace("\n", "\r\n")
                                await ws.send_text(text)
                            except asyncio.TimeoutError:
                                if proc.returncode is not None:
                                    break
                    finally:
                        output_done.set()

                stream_task = asyncio.create_task(_stream())

                # While command runs, watch for Ctrl+C from WebSocket
                while not output_done.is_set():
                    try:
                        incoming = await asyncio.wait_for(input_q.get(), timeout=0.1)
                        if incoming is None:
                            # Disconnected — kill proc and return
                            try:
                                proc.kill()
                            except Exception:
                                pass
                            await stream_task
                            return
                        if incoming.get("data") == "\x03":
                            # Ctrl+C — kill running command
                            try:
                                proc.kill()
                            except Exception:
                                pass
                            await ws.send_text("\r\n\033[1;33m^C\033[0m\r\n")
                        elif incoming.get("type") == "resize":
                            pass  # can't resize in bridge mode
                        # else: buffer the input for next command
                        # (unlikely to have extra input while a command runs)
                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        pass

                await stream_task
                await proc.wait()
                current_proc[0] = None

                # If command was 'cd' embedded (e.g. user typed 'cd /tmp && pwd')
                # update cwd by querying WSL
                if "cd " in cmd:
                    try:
                        r3 = await asyncio.create_subprocess_exec(
                            *wsl_prefix, "-e", "bash", "-c",
                            f'cd "{cwd}" 2>/dev/null; {cmd}; pwd',
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        o3, _ = await asyncio.wait_for(r3.communicate(), timeout=5)
                        lines3 = o3.decode("utf-8", errors="replace").strip().splitlines()
                        if lines3:
                            cwd = lines3[-1].strip() or cwd
                    except Exception:
                        pass

            except Exception as e:
                await ws.send_text(f"\r\n\033[1;31m[!] Error running command: {e}\033[0m\r\n")
                current_proc[0] = None

    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning("terminal(wsl_bridge): %s", e)
    finally:
        recv_task.cancel()
        if current_proc[0]:
            try:
                current_proc[0].kill()
            except Exception:
                pass
        try:
            await ws.close()
        except Exception:
            pass
        log.info("terminal(wsl_bridge): session closed")


# ─────────────────────────────────────────────────────────────
#  MODE 3 — Remote SSH to Kali Linux
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
        await ws.send_text(_kali_banner(f"SSH \u2192 {_KALI_SSH_USER}@{_KALI_SSH_HOST}"))
    except Exception:
        pass

    chan = ssh.invoke_shell(term="xterm-256color", width=220, height=50)
    chan.setblocking(False)
    log.info("SSH terminal connected: %s@%s", _KALI_SSH_USER, _KALI_SSH_HOST)

    out_q: asyncio.Queue = asyncio.Queue()

    def _ssh_reader():
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

    loop.run_in_executor(None, _ssh_reader)

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

    pump_task = asyncio.create_task(_pump())
    recv_task = asyncio.create_task(_recv())
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
        log.info("terminal(ssh): session closed \u2014 %s@%s", _KALI_SSH_USER, _KALI_SSH_HOST)


# ─────────────────────────────────────────────────────────────
#  Status helper
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
    elif _PTY_OK:
        return {
            "mode": "local_pty",
            "shell": _SHELL,
            "pty_available": True,
            "ready": True,
            "note": "Running on local Kali Linux",
        }
    elif _WSL_OK:
        return {
            "mode": "wsl_bridge",
            "wsl_bin": _WSL_BIN,
            "wsl_distro": _WSL_DISTRO or "default",
            "ready": True,
            "note": f"Windows + WSL bridge ({_WSL_DISTRO or 'default distro'})",
        }
    else:
        return {
            "mode": "unavailable",
            "pty_available": False,
            "wsl_available": False,
            "ready": False,
            "note": (
                "No terminal backend available. "
                "Install WSL (wsl --install -d kali-linux) or run on Kali Linux."
            ),
        }
