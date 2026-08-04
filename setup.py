"""
scsim — supply-chain-attack behavioral simulator.

The install hook mirrors the pattern used by real compromised packages
(ua-parser-js, event-stream, ctx, etc.): a custom cmdclass fires during
`pip install` from source, spawns an OS-native shell, and runs the
detonation payload.

The payload itself is benign — see src/scsim/payload.py. Every action
writes a marker (`SCSIM-SIMULATION`) so blue-team tooling and analysts
can distinguish it from a real intrusion.

To reliably trigger the install hook (pip prefers wheels, which skip
setup.py), install with:

    pip install --no-binary :all: .

or just:

    python setup.py install
"""

import os
import sys
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info


def _detonate(stage: str) -> None:
    """
    Run the payload out-of-process via the OS-native shell.

    Doing this via cmd.exe / powershell.exe / /bin/sh — instead of just
    importing the module — is what causes the parent process chain to
    look like a real supply-chain attack (python.exe -> cmd.exe -> ...)
    which is what Defender / EDR rules typically hunt on.
    """
    # Fail-safe: honor an opt-out env var so CI systems that pull the
    # package for inspection don't accidentally trip alerts.
    if os.environ.get("SCSIM_DISABLE") == "1":
        sys.stderr.write("[scsim] SCSIM_DISABLE=1 — skipping install-time payload\n")
        return

    here = os.path.dirname(os.path.abspath(__file__))
    payload = os.path.join(here, "src", "scsim", "payload.py")
    py = sys.executable

    try:
        import subprocess
        if os.name == "nt":
            # powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "python payload.py"
            # This is the exact pattern many compromised packages use.
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", f'& "{py}" "{payload}" --stage {stage}',
            ]
        else:
            # /bin/sh -c 'python payload.py --stage install'
            cmd = ["/bin/sh", "-c", f'"{py}" "{payload}" --stage {stage}']

        # Detach so pip's install completes even if payload is slow.
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=(os.name != "nt"),
        )
        sys.stderr.write(f"[scsim] install-time payload dispatched via {cmd[0]}\n")
    except Exception as exc:  # noqa: BLE001 - never break the install
        sys.stderr.write(f"[scsim] payload dispatch failed: {exc}\n")


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
