"""Contour CLI. contour analyze session.har -o model.json --openapi openapi.json"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from contour import __version__
from contour.analyze import analyze_path
from contour.redact import looks_live_secret
from contour.sdkgen import generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="contour", description="Compile a HAR/PCAP you are allowed to read into OpenAPI + SDKs")
    parser.add_argument("--version", action="version", version=f"contour {__version__}")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="HAR, PCAP or PCAPNG -> model.json (+ openapi.json)")
    analyze.add_argument("file", help="Capture file")
    analyze.add_argument("--output", "-o", default="model.json", help="Output model path (default: model.json)")
    analyze.add_argument("--openapi", metavar="PATH", help="Also write the bare OpenAPI 3.1 spec to PATH")
    analyze.add_argument("--host", help="Keep only this host and its subdomains (drops analytics, CDNs...)")

    sdk = sub.add_parser("sdk", help="openapi.json or model.json -> client.py + client.ts")
    sdk.add_argument("file", help="openapi.json or model.json")
    sdk.add_argument("--out", "-o", default="sdk_out", help="Output directory (default: sdk_out)")

    args = parser.parse_args(argv)
    if args.command == "analyze":
        src = Path(args.file)
        if not src.exists():
            print(f"File not found: {src}", file=sys.stderr)
            return 1
        try:
            model = analyze_path(src, host=args.host)
        except (ValueError, ImportError) as err:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        text = json.dumps(model, indent=2, ensure_ascii=False)
        if looks_live_secret(text):
            print("Refused: a secret-looking string is still in the model. Nothing was written.", file=sys.stderr)
            return 2
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"Model written to {args.output}")
        if args.openapi:
            Path(args.openapi).write_text(json.dumps(model["openapi"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"OpenAPI written to {args.openapi}")
        stats = model["stats"]
        print(
            f"{stats['endpoints']} operations from {stats['httpRequests']} requests"
            f" ({stats['skippedStatic']} static skipped), {stats['tlsFlows']} TLS flows,"
            f" {stats['secretsSeenInSource']} secret-looking strings in the source (none copied)"
        )
        for ep in model["endpoints"]:
            print(f"  {ep['method']:<7}{ep['path']:<40} seen {ep['count']:>3}x  confidence {ep['confidence']:.2f}")
        for gap in model["gaps"]:
            print(f"Gap: {gap}")
        return 0
    if args.command == "sdk":
        spec_path = Path(args.file)
        if not spec_path.exists():
            print(f"File not found: {spec_path}", file=sys.stderr)
            return 1
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        if isinstance(spec, dict) and "paths" not in spec and isinstance(spec.get("openapi"), dict):
            spec = spec["openapi"]
        if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
            print("Error: not an OpenAPI spec (no paths).", file=sys.stderr)
            return 1
        if looks_live_secret(json.dumps(spec)):
            print("Refused: a secret-looking string is still in the spec. Nothing was written.", file=sys.stderr)
            return 2
        py, ts, n = generate(spec)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "client.py").write_text(py, encoding="utf-8")
        (out / "client.ts").write_text(ts, encoding="utf-8")
        print(f"{n} operations")
        print(out / "client.py")
        print(out / "client.ts")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
