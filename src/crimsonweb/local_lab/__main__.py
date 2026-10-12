"""python -m crimsonweb.local_lab [verify|serve] --output DIR"""

import argparse
import asyncio
import json
import threading
from pathlib import Path

from .bridge import verify_laboratory
from .server import LocalLaboratory


def main(argv=None):
    parser = argparse.ArgumentParser(description="Owned loopback vulnerability laboratory")
    parser.add_argument("action", choices=["verify", "serve"], nargs="?", default="verify")
    parser.add_argument("--output", type=Path, default=Path("reports/local_lab"))
    args = parser.parse_args(argv)
    with LocalLaboratory(args.output / "ground_truth.json") as lab:
        print(json.dumps({"http": lab.http_origin, "https": lab.https_origin,
                          "certificate": str(lab.cert_path),
                          "ground_truth": str(lab.truth.path.resolve())}))
        if args.action == "verify":
            result = asyncio.run(verify_laboratory(lab, args.output / "comparison.json"))
            print(json.dumps({"all_matched": result["all_matched"],
                              "comparison": str((args.output / "comparison.json").resolve())}))
            return 0 if result["all_matched"] else 1
        print("Loopback fixtures active; Ctrl+C stops both servers. HTTPS certificate is per-run.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
