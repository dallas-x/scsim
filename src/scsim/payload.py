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

Design notes:
  * Everything prints to stdout AND to the JSON log at $SCSIM_DROP_DIR
  * Each step is followed by a configurable sleep (SCSIM_STEP_DELAY,
    default 3s) so Defender / EDR real-time monitoring has time to
    ingest and correlate the process-create + file-create + network
    events before the next one fires. Real-time telemetry commonly
    drops events for children that live < ~200ms.
  * Every artifact carries the SCSIM-SIMULATION marker so blue-team
    analysts can tell it apart from a real incident at a glance.

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
import time
import urllib.request
import urllib.error

MARKER     = "SCSIM-SIMULATION"
VERSION    = "0.1.1"
USER_AGENT = f"scsim/{VERSION} (+simulation; purple-team detection test)"
BANNER     = "=" * 68

# --- configurable knobs ----------------------------------------------------
DEFAULT_BEACON = os.environ.get("SCSIM_BEACON_URL", "http://1.1.1.1/")
DROP_DIR       = os.environ.get("SCSIM_DROP_DIR", tempfile.gettempdir())
STEP_DELAY     = float(os.environ.get("SCSIM_STEP_DELAY", "3"))

# --- artifact paths (single source of truth for docs + cleanup) -----------
LOG_PATH        = os.path.join(DROP_DIR, "scsim_activity.log")
DROP_PATH       = os.path.join(DROP_DIR, "scsim_dropped.txt")
WIN_SVC_NAME    = "scsim_sim_svc"
WIN_SVC_LOG     = os.path.join(DROP_DIR, "scsim_svc.log")
MAC_PLIST_LABEL = "com.scsim.simulation"
MAC_PLIST_PATH  = os.path.expanduser(f"~/Library/LaunchAgents/{MAC_PLIST_LABEL}.plist")
MAC_AGENT_LOG   = os.path.join(DROP_DIR, "scsim_agent.log")
LNX_UNIT_NAME   = "scsim-sim.service"
LNX_UNIT_PATH   = os.path.expanduser(f"~/.config/systemd/user/{LNX_UNIT_NAME}")
LNX_SVC_LOG     = os.path.join(DROP_DIR, "scsim_svc.log")


# ---------------------------------------------------------------------------
# I/O helpers — everything goes to stdout AND the JSON log
# ---------------------------------------------------------------------------
def _tee(msg: str) -> None:
    """Single-stream loud logging. stdout is inherited by pip when the
    payload runs via `subprocess.call`, so this appears in the pip
    terminal in real time under `--verbose`."""
    print(f"[scsim] {msg}", flush=True)


def _log(event: str, **fields) -> None:
    record = {
        "ts":     _dt.datetime.utcnow().isoformat() + "Z",
        "marker": MARKER,
        "host":   socket.gethostname(),
        "user":   getpass.getuser(),
        "pid":    os.getpid(),
        "ppid":   os.getppid(),
        "os":     platform.system(),
        "event":  event,
        **fields,
    }
    line = json.dumps(record)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as e:
        _tee(f"WARN: could not write to log {LOG_PATH}: {e}")
    _tee(line)


def _step(name: str) -> None:
    _tee(BANNER)
    _tee(f"STEP: {name}")
    _tee(BANNER)


def _sleep(reason: str = "letting EDR ingest the last event") -> None:
    if STEP_DELAY <= 0:
        return
    _tee(f"sleeping {STEP_DELAY}s — {reason}")
    time.sleep(STEP_DELAY)


def _preamble() -> None:
    """Print every path we're about to touch so the analyst can go look
    for the artifacts even before they land."""
    system = platform.system()
    _tee(BANNER)
    _tee(f"scsim v{VERSION} — benign supply-chain simulation")
    _tee(BANNER)
    _tee(f"host       : {socket.gethostname()}")
    _tee(f"user       : {getpass.getuser()}")
    _tee(f"os         : {system} {platform.release()}")
    _tee(f"python     : {sys.executable}")
    _tee(f"pid / ppid : {os.getpid()} / {os.getppid()}")
    _tee(f"cwd        : {os.getcwd()}")
    _tee(BANNER)
    _tee("artifacts this run will produce:")
    _tee(f"  activity log     -> {LOG_PATH}")
    _tee(f"  dropped file     -> {DROP_PATH}")
    _tee(f"  beacon target    -> {DEFAULT_BEACON}")
    if system == "Windows":
        _tee(f"  windows service  -> name={WIN_SVC_NAME}   log={WIN_SVC_LOG}")
    elif system == "Darwin":
        _tee(f"  launchd plist    -> {MAC_PLIST_PATH}")
        _tee(f"  launchd agent log-> {MAC_AGENT_LOG}")
    elif system == "Linux":
        _tee(f"  systemd unit     -> {LNX_UNIT_PATH}")
        _tee(f"  systemd svc log  -> {LNX_SVC_LOG}")
    _tee(f"step delay between actions: {STEP_DELAY}s "
         f"(override with SCSIM_STEP_DELAY)")
    _tee(BANNER)


# ---------------------------------------------------------------------------
# T1071.001 — beacon
# ---------------------------------------------------------------------------
def beacon(url: str = DEFAULT_BEACON) -> int:
    _step(f"T1071.001 outbound HTTP GET  ->  {url}")
    _tee(f"user-agent: {USER_AGENT}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # noqa: BLE001
        _log("beacon_error", url=url, error=str(e))
        _tee(f"beacon FAILED: {e!r}")
        return -1
    _log("beacon", url=url, status=code)
    _tee(f"beacon returned HTTP {code}")
    return code


# ---------------------------------------------------------------------------
# T1105 — drop a file in a different directory
# ---------------------------------------------------------------------------
def drop_file() -> str:
    _step(f"T1105 file drop  ->  {DROP_PATH}")
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
    with open(DROP_PATH, "w", encoding="utf-8") as fh:
        fh.write(body)
    _log("file_dropped", path=DROP_PATH, bytes=len(body))
    _tee(f"wrote {len(body)} bytes to {DROP_PATH}")
    return DROP_PATH


# ---------------------------------------------------------------------------
# T1543 — create a service / launch agent / systemd unit
# ---------------------------------------------------------------------------
def create_service() -> str | None:
    system = platform.system()
    _step(f"T1543 persistence attempt on {system}")
    try:
        if system == "Windows":
            return _create_windows_service()
        if system == "Darwin":
            return _create_launchd_agent()
        if system == "Linux":
            return _create_systemd_unit()
        _tee(f"unsupported OS: {system} — skipping persistence")
    except Exception as e:  # noqa: BLE001
        _log("service_error", os=system, error=str(e))
        _tee(f"service creation FAILED: {e!r}")
    return None


def _create_windows_service() -> str | None:
    cmd = [
        "sc.exe", "create", WIN_SVC_NAME,
        "binPath=", f'cmd.exe /c "echo {MARKER} > {WIN_SVC_LOG}"',
        "start=", "demand",
        "DisplayName=", "SCSIM Simulation Service",
    ]
    _tee(f"invoking: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    _log("service_create_windows",
         name=WIN_SVC_NAME, rc=proc.returncode,
         stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
    _tee(f"sc.exe rc={proc.returncode}")
    if proc.stdout.strip(): _tee(f"sc.exe stdout: {proc.stdout.strip()}")
    if proc.stderr.strip(): _tee(f"sc.exe stderr: {proc.stderr.strip()}")
    if proc.returncode == 5:
        _tee("(rc=5 is ACCESS_DENIED — needs admin. The *attempt* is "
             "still the telemetry Defender should flag.)")
    return WIN_SVC_NAME if proc.returncode == 0 else None


def _create_launchd_agent() -> str | None:
    os.makedirs(os.path.dirname(MAC_PLIST_PATH), exist_ok=True)
    plist = textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>{MAC_PLIST_LABEL}</string>
          <key>ProgramArguments</key>
          <array>
            <string>/bin/sh</string>
            <string>-c</string>
            <string>echo {MARKER} &gt;&gt; {MAC_AGENT_LOG}</string>
          </array>
          <key>RunAtLoad</key><true/>
        </dict>
        </plist>
    """)
    with open(MAC_PLIST_PATH, "w", encoding="utf-8") as fh:
        fh.write(plist)
    _tee(f"wrote plist: {MAC_PLIST_PATH}")
    _tee(f"invoking: launchctl load {MAC_PLIST_PATH}")
    proc = subprocess.run(
        ["launchctl", "load", MAC_PLIST_PATH],
        capture_output=True, text=True,
    )
    _log("service_create_macos",
         label=MAC_PLIST_LABEL, plist=MAC_PLIST_PATH, rc=proc.returncode,
         stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
    _tee(f"launchctl rc={proc.returncode}")
    if proc.stdout.strip(): _tee(f"launchctl stdout: {proc.stdout.strip()}")
    if proc.stderr.strip(): _tee(f"launchctl stderr: {proc.stderr.strip()}")
    return MAC_PLIST_LABEL


def _create_systemd_unit() -> str | None:
    os.makedirs(os.path.dirname(LNX_UNIT_PATH), exist_ok=True)
    unit = textwrap.dedent(f"""\
        [Unit]
        Description=SCSIM benign supply-chain simulation
        [Service]
        Type=oneshot
        ExecStart=/bin/sh -c 'echo {MARKER} >> {LNX_SVC_LOG}'
        [Install]
        WantedBy=default.target
    """)
    with open(LNX_UNIT_PATH, "w", encoding="utf-8") as fh:
        fh.write(unit)
    _tee(f"wrote unit: {LNX_UNIT_PATH}")
    _tee("invoking: systemctl --user daemon-reload")
    proc = subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True, text=True,
    )
    _log("service_create_linux",
         name=LNX_UNIT_NAME, unit=LNX_UNIT_PATH, rc=proc.returncode,
         stdout=proc.stdout.strip(), stderr=proc.stderr.strip())
    _tee(f"systemctl rc={proc.returncode}")
    if proc.stdout.strip(): _tee(f"systemctl stdout: {proc.stdout.strip()}")
    if proc.stderr.strip(): _tee(f"systemctl stderr: {proc.stderr.strip()}")
    return LNX_UNIT_NAME


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def detonate(stage: str = "manual") -> dict:
    _preamble()
    _log("detonate_begin",
         stage=stage, python=sys.executable, argv=sys.argv, cwd=os.getcwd())

    _sleep("giving EDR a stable python parent to log first")

    result = {"stage": stage}

    result["dropped_file"] = drop_file()
    _sleep()

    result["service"] = create_service()
    _sleep()

    result["beacon_status"] = beacon()
    _sleep("final pause so the beacon network event completes on the wire")

    result["log"] = LOG_PATH
    _log("detonate_end", **{k: str(v) for k, v in result.items()})

    _tee(BANNER)
    _tee("DONE. Summary:")
    for k, v in result.items():
        _tee(f"  {k:15s} = {v}")
    _tee(BANNER)
    _tee(f"to remove every artifact this run created: `scsim cleanup`")
    _tee(BANNER)
    return result


def cleanup() -> dict:
    _tee(BANNER)
    _tee("scsim cleanup — removing all simulation artifacts")
    _tee(BANNER)
    removed, errors = [], []

    for p in (DROP_PATH, WIN_SVC_LOG, MAC_AGENT_LOG, LNX_SVC_LOG):
        try:
            os.remove(p); removed.append(p); _tee(f"removed {p}")
        except FileNotFoundError:
            pass
        except OSError as e:
            errors.append(f"{p}: {e}"); _tee(f"could not remove {p}: {e}")

    system = platform.system()
    try:
        if system == "Windows":
            proc = subprocess.run(
                ["sc.exe", "delete", WIN_SVC_NAME],
                capture_output=True, text=True,
            )
            removed.append(f"service {WIN_SVC_NAME} rc={proc.returncode}")
            _tee(f"sc.exe delete {WIN_SVC_NAME} rc={proc.returncode}")
        elif system == "Darwin":
            subprocess.run(["launchctl", "unload", MAC_PLIST_PATH],
                           capture_output=True, text=True)
            try:
                os.remove(MAC_PLIST_PATH); removed.append(MAC_PLIST_PATH)
                _tee(f"removed {MAC_PLIST_PATH}")
            except FileNotFoundError:
                pass
        elif system == "Linux":
            try:
                os.remove(LNX_UNIT_PATH); removed.append(LNX_UNIT_PATH)
                _tee(f"removed {LNX_UNIT_PATH}")
            except FileNotFoundError:
                pass
            subprocess.run(["systemctl", "--user", "daemon-reload"],
                           capture_output=True, text=True)
    except Exception as e:  # noqa: BLE001
        errors.append(str(e))

    try:
        os.remove(LOG_PATH); removed.append(LOG_PATH); _tee(f"removed {LOG_PATH}")
    except FileNotFoundError:
        pass
    except OSError as e:
        errors.append(f"{LOG_PATH}: {e}")

    _tee(BANNER)
    _tee(f"cleanup done: {len(removed)} removed, {len(errors)} errors")
    _tee(BANNER)
    return {"removed": removed, "errors": errors}


def paths() -> dict:
    """Return every path this simulation can touch on this OS."""
    system = platform.system()
    d = {
        "os":         system,
        "drop_dir":   DROP_DIR,
        "log_path":   LOG_PATH,
        "drop_path":  DROP_PATH,
        "beacon_url": DEFAULT_BEACON,
        "step_delay": STEP_DELAY,
    }
    if system == "Windows":
        d.update(win_service=WIN_SVC_NAME, win_service_log=WIN_SVC_LOG)
    elif system == "Darwin":
        d.update(macos_plist=MAC_PLIST_PATH, macos_agent_log=MAC_AGENT_LOG)
    elif system == "Linux":
        d.update(linux_unit=LNX_UNIT_PATH, linux_service_log=LNX_SVC_LOG)
    return d


def _cli():
    ap = argparse.ArgumentParser(prog="scsim.payload")
    ap.add_argument("--stage", default="manual")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--paths", action="store_true")
    args = ap.parse_args()
    if args.paths:
        print(json.dumps(paths(), indent=2))
    elif args.cleanup:
        cleanup()
    else:
        detonate(args.stage)


if __name__ == "__main__":
    _cli()
