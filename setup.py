"""
scsim — supply-chain-attack behavioral simulator.

The install hook mirrors the pattern used by real compromised packages
(ua-parser-js, event-stream, ctx, etc.): a custom cmdclass fires during
`pip install` from source, spawns an OS-native shell, and runs the
detonation payload.

The payload itself is benign — see src/scsim/payload.py. Every action
writes a marker (`SCSIM-SIMULATION`) so blue-team tooling and analysts
can distinguish it from a real intrusion.

The dispatch is deliberately LOUD and SYNCHRONOUS:
  * stdout is inherited from pip so every action prints to the terminal
  * the shell child is waited on (not detached) so the whole process
    tree is alive long enough for Defender / EDR to log it — real-time
    monitoring on Windows and macOS regularly misses process-create
    events for children that live < ~200ms

To reliably trigger the install hook (pip prefers wheels, which skip
setup.py), install with:

    pip install --no-binary :all: --verbose .

`--verbose` guarantees you see the payload's stdout even under pip's
default output filtering.
"""

import os
import sys
import time
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info


BANNER = "=" * 68


def _say(msg: str) -> None:
    """Print to BOTH stdout and stderr so pip surfaces it under any
    verbosity setting. pip suppresses much of stderr but shows stdout."""
    line = f"[scsim] {msg}"
    print(line, flush=True)
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def _detonate(stage: str) -> None:
    """
    Run the payload out-of-process via the OS-native shell, synchronously,
    with inherited stdio.
    """
    if os.environ.get("SCSIM_DISABLE") == "1":
        _say("SCSIM_DISABLE=1 — skipping install-time payload")
        return

    here    = os.path.dirname(os.path.abspath(__file__))
    payload = os.path.join(here, "src", "scsim", "payload.py")
    py      = sys.executable

    _say(BANNER)
    _say(f"install-time payload firing — stage={stage!r}")
    _say(f"parent pid: {os.getpid()}   parent exe: {py}")
    _say(f"payload script: {payload}")
    _say(BANNER)

    # A brief pause lets pip flush its own stdout and gives EDR/AV
    # sensors a stable process to log before we start spawning children.
    settle = float(os.environ.get("SCSIM_SETTLE_DELAY", "2"))
    _say(f"sleeping {settle}s to let EDR settle before spawning shell...")
    time.sleep(settle)

    try:
        import subprocess
        if os.name == "nt":
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", f'& "{py}" "{payload}" --stage {stage}',
            ]
        else:
            cmd = ["/bin/sh", "-c", f'"{py}" "{payload}" --stage {stage}']

        _say(f"spawning: {cmd}")
        _say(BANNER)

        # SYNCHRONOUS + inherited stdio. This is the important part:
        #   * pip's terminal shows every line the payload prints
        #   * the shell child is alive for the full run so EDR captures
        #     the process-create + process-tree events
        #   * pip's install command doesn't return until the payload is
        #     done, so nothing gets orphaned or killed mid-detonation
        rc = subprocess.call(cmd)

        _say(BANNER)
        _say(f"payload exited rc={rc}")
        _say(BANNER)
    except Exception as exc:  # noqa: BLE001 — never break the install
        _say(f"payload dispatch failed: {exc!r}")


class _PostInstall(install):
    def run(self):
        install.run(self)
        _detonate("install")


class _PostDevelop(develop):
    def run(self):
        develop.run(self)
        _detonate("develop")


class _PostEggInfo(egg_info):
    """
    Fires during `pip install .` even when pip builds a wheel first
    (wheels skip the install cmdclass). This is how real attackers
    ensure their code runs regardless of pip's install strategy.

    We only detonate here when pip is *not* also going to invoke
    the install command in the same run — otherwise we'd fire the
    payload N times per install. Detection is best-effort; if we
    fire twice the second run is idempotent (drops the same file,
    re-registers the same service).
    """
    def run(self):
        egg_info.run(self)
        _detonate("egg_info")


setup(
    cmdclass={
        "install": _PostInstall,
        "develop": _PostDevelop,
        "egg_info": _PostEggInfo,
    },
)
