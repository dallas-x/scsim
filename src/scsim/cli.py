"""Console entry point: `scsim detonate|cleanup|paths|status`."""

from __future__ import annotations

import argparse
import json
import sys

from . import payload


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="scsim",
        description="Benign supply-chain-attack behavioral simulator.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_det = sub.add_parser(
        "detonate",
        help="Run the simulation payload now (loud, synchronous, sleeps between steps).",
    )
    p_det.add_argument("--stage", default="manual")

    sub.add_parser("cleanup", help="Remove every artifact this tool creates.")
    sub.add_parser(
        "paths",
        help="Print every path this simulation touches on this OS.",
    )
    sub.add_parser("status", help="Show config: log, drop dir, beacon, delay.")

    args = ap.parse_args(argv)

    if args.cmd == "detonate":
        payload.detonate(args.stage)
    elif args.cmd == "cleanup":
        payload.cleanup()
    elif args.cmd == "paths":
        print(json.dumps(payload.paths(), indent=2))
    elif args.cmd == "status":
        print(json.dumps({
            "log":        payload.LOG_PATH,
            "drop_dir":   payload.DROP_DIR,
            "beacon":     payload.DEFAULT_BEACON,
            "step_delay": payload.STEP_DELAY,
        }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
