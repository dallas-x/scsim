"""
scsim payload — the actions a compromised package *would* take.

Every action is benign but shaped to trigger the same telemetry a real
supply-chain implant would produce:

  T1195.002  Compromise Software Supply Chain    (dispatched from setup.py)
  T1059.001  PowerShell                          (Windows shell chain)
  T1059.004  Unix Shell                          (POSIX shell chain)
  T1071.001  Application Layer Protocol: Web     (outbound HTTP GET)
  T1105      Ingress Tool Transfer               (drops a file to disk)
  T1547.001  Registry Run Keys / Startup Folder  (Windows persistence, opt.)
  T1543.003  Windows Service                     (Windows persistence, opt.)
  T1543.001  Launch Agent                        (macOS persistence, opt.)
  T1543.002  Systemd Service                     (Linux persistence, opt.)

Markers on every artifact:
  - File contents include the literal string SCSIM-SIMULATION
  - Service / task names are prefixed `scsim_`
  - Outbound HTTP request has User-Agent: scsim/0.1 (+simulation)

Cleanup: `scsim cleanup` (or `python -m scsim cleanup`).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import textwrap
import urllib.request

MARKER = "SCSIM-SIMULATION"
VERSION = "0.1.0"
USER_AGENT = f"scsim/{VERSION} (+simulation; purple-team detection test)"

# Benign, high-availability endpoints. Override with SCSIM_BEACON_URL.
DEFAULT_BEACON = os.environ.get(
    "SCSIM_BEACON_URL",
    "http://1.1.1.1/",  # Cloudflare, always returns HTTP 301 -> we count that
)

DROP_DIR = os.environ.get(
    "SCSIM_DROP_DIR",
    tempfile.gettempdir(),
)

# Log file so blue team can correlate what fired.
LOG_PATH = os.path.join(DROP_DIR, "scsim_activity.log")


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------
def _log(event: str, **fields) -> None:
    record = {
        "ts": _dt.datetime.utcnow().isoformat() + "Z",
        "marker": MARKER,
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "os": platform.system(),
        "event": event,
        **fields,
    }
    line = json.dumps(record)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    sys.stderr.write(f"[scsim] {line}\n")


# ---------------------------------------------------------------------------
# T1071.001 — beacon
# ---------------------------------------------------------------------------
def beacon(url: str = DEFAULT_BEACON) -> int:
    """HTTP GET to a benign IP. Returns HTTP status code."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # noqa: BLE001
        _log("beacon_error", url=url, error=str(e))
        return -1
    _log("beacon", url=url, status=code)
    return code


# ---------------------------------------------------------------------------
# T1105 — drop a file in a different directory
# ---------------------------------------------------------------------------
def drop_file() -> str:
    """Write a marker file into the OS temp dir."""
    path = os.path.join(DROP_DIR, "scsim_dropped.txt")
    body = textwrap.dedent(
        f"""\
        {MARKER}
        Written by: scsim/{VERSION}
        At:         {_dt.datetime.utcnow().isoformat()}Z
        Host:       {socket.gethostname()}
        User:       {getpass.getuser()}
        Python:     {sys.executable}
        PPID chain: {os.getppid()} -> {os.getpid()}

        This file was created by a benign purple-team simulation.
        It is safe to delete. Run `scsim cleanup` to remove all artifacts.
        """
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    _log("file_dropped", path=path, bytes=len(body))
    return path


# ---------------------------------------------------------------------------
# T1543 — create a service / launch agent / systemd unit
# ---------------------------------------------------------------------------
def create_service() -> str | None:
    """
    Attempt to register a benign service that just runs `whoami`.
    Non-fatal if we lack privileges — we log the attempt either way,
    which is what EDRs will alert on.
    """
    system = platform.system()
    try:
        if system == "Windows":
            return _create_windows_service()
        if system == "Darwin":
            return _create_launchd_agent()
        if system == "Linux":
            return _create_systemd_unit()
    except Exception as e:  # noqa: BLE001
        _log("service_error", os=system, error=str(e))
    return None


def _create_windows_service() -> str | None:
    name = "scsim_sim_svc"
    # sc.exe requires admin. The *attempt* alone is the telemetry we want.
    cmd = [
        "sc.exe", "create", name,
        "binPath=", 'cmd.exe /c "echo SCSIM-SIMULATION > %TEMP%\\scsim_svc.log"',
        "start=", "demand",
        "DisplayName=", "SCSIM Simulation Service",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    _log("service_create_windows",
         name=name, rc=proc.returncode,
         stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
    return name if proc.returncode == 0 else None


def _create_launchd_agent() -> str | None:
    label = "com.scsim.simulation"
    plist_dir = os.path.expanduser("~/Library/LaunchAgents")
    os.makedirs(plist_dir, exist_ok=True)
    plist_path = os.path.join(plist_dir, f"{label}.plist")
    plist = textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>{label}</string>
          <key>ProgramArguments</key>
          <array>
            <string>/bin/sh</string>
            <string>-c</string>
            <string>echo {MARKER} &gt;&gt; {DROP_DIR}/scsim_agent.log</string>
          </array>
          <key>RunAtLoad</key><true/>
        </dict>
        </plist>
    """)
    with open(plist_path, "w", encoding="utf-8") as fh:
        fh.write(plist)
    # `launchctl load` is what triggers TCC / EDR telemetry.
    proc = subprocess.run(
        ["launchctl", "load", plist_path],
        capture_output=True, text=True,
    )
    _log("service_create_macos",
         label=label, plist=plist_path, rc=proc.returncode,
         stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
    return label


def _create_systemd_unit() -> str | None:
    name = "scsim-sim.service"
    # User unit — no root needed.
    unit_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)
    unit_path = os.path.join(unit_dir, name)
    unit = textwrap.dedent(f"""\
        [Unit]
        Description=SCSIM benign supply-chain simulation
        [Service]
        Type=oneshot
        ExecStart=/bin/sh -c 'echo {MARKER} >> {DROP_DIR}/scsim_svc.log'
        [Install]
        WantedBy=default.target
    """)
    with open(unit_path, "w", encoding="utf-8") as fh:
        fh.write(unit)
    proc = subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True, text=True,
    )
    _log("service_create_linux",
         name=name, unit=unit_path, rc=proc.returncode,
         stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
    return name


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def detonate(stage: str = "manual") -> dict:
    _log("detonate_begin", stage=stage,
         python=sys.executable, argv=sys.argv,
         cwd=os.getcwd())
    # Order matters — do the fast, deterministic actions first so a slow
    # or blocked beacon doesn't rob us of the file-drop / persistence
    # telemetry the blue team wants to see.
    result = {"stage": stage}
    result["dropped_file"] = drop_file()
    result["service"]      = create_service()
    result["beacon_status"] = beacon()
    result["log"]          = LOG_PATH
    _log("detonate_end", **{k: str(v) for k, v in result.items()})
    return result


def cleanup() -> dict:
    """Remove every artifact this package creates."""
    removed = []
    errors = []

    # Dropped files
    for fname in ("scsim_dropped.txt", "scsim_svc.log", "scsim_agent.log"):
        p = os.path.join(DROP_DIR, fname)
        try:
            os.remove(p); removed.append(p)
        except FileNotFoundError:
            pass
        except OSError as e:
            errors.append(f"{p}: {e}")

    system = platform.system()
    try:
        if system == "Windows":
            proc = subprocess.run(
                ["sc.exe", "delete", "scsim_sim_svc"],
                capture_output=True, text=True,
            )
            removed.append(f"service scsim_sim_svc rc={proc.returncode}")
        elif system == "Darwin":
            plist = os.path.expanduser(
                "~/Library/LaunchAgents/com.scsim.simulation.plist"
            )
            subprocess.run(["launchctl", "unload", plist],
                           capture_output=True, text=True)
            try:
                os.remove(plist); removed.append(plist)
            except FileNotFoundError:
                pass
        elif system == "Linux":
            unit = os.path.expanduser(
                "~/.config/systemd/user/scsim-sim.service"
            )
            try:
                os.remove(unit); removed.append(unit)
            except FileNotFoundError:
                pass
            subprocess.run(
                ["systemctl", "--user", "daemon-reload"],
                capture_output=True, text=True,
            )
    except Exception as e:  # noqa: BLE001
        errors.append(str(e))

    # Finally the log itself
    try:
        os.remove(LOG_PATH); removed.append(LOG_PATH)
    except FileNotFoundError:
        pass
    except OSError as e:
        errors.append(f"{LOG_PATH}: {e}")

    return {"removed": removed, "errors": errors}


def _cli():
    ap = argparse.ArgumentParser(prog="scsim.payload")
    ap.add_argument("--stage", default="manual")
    ap.add_argument("--cleanup", action="store_true")
    args = ap.parse_args()
    if args.cleanup:
        print(json.dumps(cleanup(), indent=2))
    else:
        print(json.dumps(detonate(args.stage), indent=2, default=str))


if __name__ == "__main__":
    _cli()
