"""Console entry point: `scsim detonate|cleanup|status`."""

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

    p_det = sub.add_parser("detonate", help="Run the simulation payload now.")
    p_det.add_argument("--stage", default="manual")

    sub.add_parser("cleanup", help="Remove every artifact this tool creates.")
    sub.add_parser("status", help="Show marker log path and drop directory.")

    args = ap.parse_args(argv)

    if args.cmd == "detonate":
        print(json.dumps(payload.detonate(args.stage), indent=2, default=str))
    elif args.cmd == "cleanup":
        print(json.dumps(payload.cleanup(), indent=2))
    elif args.cmd == "status":
        print(json.dumps({
            "log":       payload.LOG_PATH,
            "drop_dir":  payload.DROP_DIR,
            "beacon":    payload.DEFAULT_BEACON,
        }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
