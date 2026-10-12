"""
Contour CLI — Signal analyzer for reverse engineering.
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
except ImportError:
    print("Error: scapy is required. Run: pip install scapy")
    sys.exit(1)


def analyze_pcap(path: str) -> dict:
    """Extract basic flow information from a PCAP file."""
    packets = rdpcap(path)
    flows = {}

    for pkt in packets:
        if not (IP in pkt and (TCP in pkt or UDP in pkt)):
            continue

        proto = "TCP" if TCP in pkt else "UDP"
        sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        key = f"{pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport} ({proto})"

        if key not in flows:
            flows[key] = {"count": 0, "samples": [], "has_payload": False}

        flows[key]["count"] += 1

        if Raw in pkt and len(flows[key]["samples"]) < 5:
            payload = bytes(pkt[Raw].load)[:256]
            flows[key]["samples"].append({
                "hex": payload.hex(),
                "ascii_preview": payload.decode("utf-8", errors="replace")[:80]
            })
            flows[key]["has_payload"] = True

    model = {
        "meta": {
            "source": "pcap",
            "tool": "contour-cli",
            "version": "0.1.0",
            "packet_count": len(packets)
        },
        "flows": [
            {
                "flow": k,
                "packet_count": v["count"],
                "sample_payloads": v["samples"]
            }
            for k, v in sorted(flows.items(), key=lambda x: -x[1]["count"])[:30]
        ],
        "summary": {
            "unique_flows": len(flows),
            "flows_with_payload": sum(1 for v in flows.values() if v["has_payload"])
        },
        "next_steps": [
            "Feed this model + context to an LLM with the Contour skill",
            "Collect more targeted traces if gaps remain",
            "Export as Contour Signal Format for sharing"
        ]
    }
    return model


def main():
    parser = argparse.ArgumentParser(description="Contour — Signal-based reverse engineering analyzer")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Analyze a capture file")
    analyze.add_argument("file", help="PCAP or PCAPNG file")
    analyze.add_argument("--output", "-o", default="model.json", help="Output JSON path")

    args = parser.parse_args()

    if args.command == "analyze":
        if not Path(args.file).exists():
            print(f"File not found: {args.file}")
            sys.exit(1)
        result = analyze_pcap(args.file)
        Path(args.output).write_text(json.dumps(result, indent=2))
        print(f"Analysis written to {args.output}")
        print(f"Flows found: {result['summary']['unique_flows']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
