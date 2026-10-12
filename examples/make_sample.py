"""Write examples/sample.pcap — a fake HTTP request, no live secret."""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

RAW = (
    "GET /v1/customers/cus_123?expand=card HTTP/1.1\r\n"
    "Host: api.vellum.test\r\n"
    "Accept: application/json\r\n\r\n"
).encode()


def main() -> None:
    dest = Path(__file__).resolve().parent / "sample.pcap"
    wrpcap(str(dest), [Ether() / IP(src="10.0.0.8", dst="10.0.0.1") / TCP(sport=4444, dport=80) / Raw(load=RAW)])
    print(dest)


if __name__ == "__main__":
    main()
