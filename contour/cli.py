"""Contour CLI. python -m contour.cli analyze capture.pcap -o model.json"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from contour.analyze import analyze_path
from contour.redact import looks_live_secret
from contour.sdkgen import generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Contour — compile a capture you are allowed to read")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="PCAP, PCAPNG, or HAR -> model.json")
    analyze.add_argument("file", help="Capture file")
    analyze.add_argument("--output", "-o", default="model.json", help="Output JSON path")

    sdk = sub.add_parser("sdk", help="OpenAPI or model.json -> client.py and client.ts")
    sdk.add_argument("file", help="openapi.json or model.json")
    sdk.add_argument("--out", "-o", default="sdk_out", help="Output directory")

    args = parser.parse_args(argv)
    if args.command == "analyze":
        src = Path(args.file)
        if not src.exists():
            print(f"File not found: {src}", file=sys.stderr)
            return 1
        model = analyze_path(src)
        text = json.dumps(model, indent=2, ensure_ascii=False)
        if looks_live_secret(text):
            print("Refused: a secret is still in the model.", file=sys.stderr)
            return 2
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"Analysis written to {args.output}")
        print(f"Endpoints: {model['stats']['endpoints']}  TLS flows: {model['stats']['tlsFlows']}")
        for gap in model["gaps"]:
            print(f"Gap: {gap}")
        return 0
    if args.command == "sdk":
        spec_path = Path(args.file)
        if not spec_path.exists():
            print(f"File not found: {spec_path}", file=sys.stderr)
            return 1
        loaded = json.loads(spec_path.read_text(encoding="utf-8"))
        spec = loaded
        if isinstance(loaded, dict) and "paths" not in loaded and isinstance(loaded.get("openapi"), dict):
            spec = loaded["openapi"]
        if looks_live_secret(json.dumps(spec)):
            print("Refused: a secret is still in the spec.", file=sys.stderr)
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
