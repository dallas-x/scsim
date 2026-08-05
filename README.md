# scsim — supply-chain-attack behavioral simulator

A **benign** Python package that mimics the telemetry of a compromised
dependency for the purpose of validating EDR / AV / SIEM detections.
It fires the same behavior chain used by real supply-chain incidents
(ua-parser-js, event-stream, ctx, pytosquatting, colors/faker) — but
does nothing malicious.

## What it does

| Stage | MITRE ATT&CK | Behavior |
|-------|--------------|----------|
| 1. Install-time hook | T1195.002 | `setup.py` cmdclass fires during `pip install` |
| 2. Shell chain      | T1059.001 / T1059.004 | Spawns `powershell.exe` on Windows, `/bin/sh` elsewhere |
| 3. Beacon           | T1071.001 | HTTP GET to `1.1.1.1` (configurable) with UA `scsim/0.1` |
| 4. File drop        | T1105     | Writes `scsim_dropped.txt` to `%TEMP%` / `/tmp` |
| 5. Persistence      | T1543 / T1547 | Registers a benign Windows service / launchd agent / systemd user unit |

Every artifact is stamped with the literal marker string `SCSIM-SIMULATION`
and services are named `scsim_*` so blue-team analysts can trivially
distinguish it from a real intrusion.

## Install (the loud way — triggers install-time hook)

Direct from GitHub:
```bash
pip install --no-binary :all: git+https://github.com/dallas-x/scsim@main
```

From a published GitHub Release sdist (see the `release` workflow):
```bash
pip install --no-binary :all: https://github.com/dallas-x/scsim/releases/download/v0.1.0/scsim-0.1.0.tar.gz
```

Or from a local checkout:
```bash
pip install --no-binary :all: .
# or
python setup.py install
```

The `--no-binary` flag forces pip to build from sdist, which is what
runs `setup.py`. When pip installs from a pre-built wheel, `setup.py`
is skipped — that's a limitation of the packaging system, not this
tool. To exercise the wheel-install path anyway, we hook `egg_info`
(runs during wheel build too).

## Install (silent — for inspection)

```bash
SCSIM_DISABLE=1 pip install .
```

## Manual detonation

If you don't want to trigger via install (e.g. Picus box already has
the package), run it explicitly:

```bash
scsim detonate
# or
python -m scsim detonate
```

## Cleanup

```bash
scsim cleanup
```

Removes the dropped file, the service/agent/unit, and the log.

## Where every artifact lands

Ask on any box: `scsim paths` (prints JSON of every path scsim will touch).

| Artifact | Windows | macOS | Linux |
|---|---|---|---|
| Activity log (JSONL) | `%TEMP%\scsim_activity.log` | `$TMPDIR/scsim_activity.log` (usually `/var/folders/…/T/`) | `/tmp/scsim_activity.log` |
| Dropped file (T1105) | `%TEMP%\scsim_dropped.txt` | `$TMPDIR/scsim_dropped.txt` | `/tmp/scsim_dropped.txt` |
| Persistence artifact (T1543) | Service `scsim_sim_svc` in SCM (registered via `sc.exe create`) | `~/Library/LaunchAgents/com.scsim.simulation.plist` (loaded via `launchctl load`) | `~/.config/systemd/user/scsim-sim.service` (registered via `systemctl --user daemon-reload`) |
| Persistence exec log | `%TEMP%\scsim_svc.log` | `$TMPDIR/scsim_agent.log` | `/tmp/scsim_svc.log` |
| Outbound beacon (T1071) | HTTP GET `http://1.1.1.1/` (configurable) | same | same |

Override any location with `SCSIM_DROP_DIR=/some/path`.

## Timing — why you might have seen "nothing"

Windows Defender and many EDRs drop process-create events for children
that live < ~200ms. The v0.1.0 install-time hook detached the payload and
exited immediately, which is why you saw only the `pip install` command in
your telemetry.

From v0.1.1 on, the install hook is:
  * **Synchronous** — pip waits for the payload; nothing gets orphaned or killed
  * **Loud** — every step is printed to stdout so it appears in the pip terminal
  * **Slow on purpose** — a configurable `SCSIM_STEP_DELAY` (default 3s) sits
    between each MITRE technique so Defender can ingest and correlate the
    process-create, file-create, and network events before the next one fires

If Defender still misses events, dial the sleep up:

```bash
SCSIM_STEP_DELAY=8 pip install --no-binary :all: --verbose git+https://github.com/dallas-x/scsim@main
```

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `SCSIM_DISABLE`      | unset             | Set to `1` to skip the install-time payload entirely |
| `SCSIM_BEACON_URL`   | `http://1.1.1.1/` | Where to send the HTTP GET |
| `SCSIM_DROP_DIR`     | OS temp dir       | Where to write the dropped file and log |
| `SCSIM_STEP_DELAY`   | `3`               | Seconds to sleep between MITRE steps — raise if EDR misses events |
| `SCSIM_SETTLE_DELAY` | `2`               | Seconds pip pauses before spawning the shell (setup.py only) |

## Log format

JSON-lines at `$SCSIM_DROP_DIR/scsim_activity.log`, one record per event:

```json
{"ts":"2026-08-04T14:32:11Z","marker":"SCSIM-SIMULATION","host":"picus01","user":"svc_picus","pid":8412,"ppid":8188,"os":"Windows","event":"beacon","url":"http://1.1.1.1/","status":301}
```

Use this to correlate what fired with what Defender/EDR alerted on.

## Detections this exercises

- Python spawning `powershell.exe` or `cmd.exe`
- `python.exe` / `pip.exe` making outbound HTTP from `%TEMP%` / site-packages
- `sc.exe create` invoked by a non-admin process tree
- `launchctl load` from a Python child
- `systemctl --user daemon-reload` from a pip install
- Suspicious `setup.py` post-install command execution
- New service/agent/unit with a suspicious (unsigned, tempdir) binary target

## Safety guarantees

- No network destinations other than the configurable beacon URL
- No file writes outside `SCSIM_DROP_DIR` and the OS-specific service dir
- No code execution beyond `echo` / `whoami`
- No credential access, no persistence beyond what `cleanup` removes
- `SCSIM_DISABLE=1` is honored everywhere
