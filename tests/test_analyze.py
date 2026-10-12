import json
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from contour.analyze import analyze_path
from contour.cli import main


def _hello(host: str) -> bytes:
    name = host.encode("ascii")
    sni_list = (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    body = b"\x03\x03" + (b"\x11" * 32) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
    body += len(ext).to_bytes(2, "big") + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_http_strips_the_token(tmp_path: Path):
    token = "sk_" + "live_" + "FAKEKEY123456"
    raw = (
        "GET /v1/customers/cus_123?expand=card HTTP/1.1\r\n"
        "Host: api.vellum.test\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
    ).encode()
    pcap = tmp_path / "one.pcap"
    wrpcap(str(pcap), [Ether() / IP(src="10.0.0.8", dst="10.0.0.1") / TCP(sport=4444, dport=80) / Raw(load=raw)])
    model = analyze_path(pcap)
    blob = json.dumps(model)
    assert token not in blob
    assert "Bearer" not in blob
    assert model["endpoints"][0]["path"] == "/v1/customers/{id}"
    assert model["endpoints"][0]["auth"] == "bearer"
    assert model["endpoints"][0]["query"] == ["expand"]
    out = tmp_path / "model.json"
    assert main(["analyze", str(pcap), "-o", str(out)]) == 0
    assert token not in out.read_text()


def test_tls_is_named_not_opened(tmp_path: Path):
    pcap = tmp_path / "tls.pcap"
    wrpcap(
        str(pcap),
        [Ether() / IP(src="10.0.0.8", dst="1.1.1.1") / TCP(sport=4444, dport=443) / Raw(load=_hello("api.private.test"))],
    )
    model = analyze_path(pcap)
    assert model["tls"] == [{"sni": "api.private.test", "port": 443, "count": 1}]
    assert model["stats"]["httpRequests"] == 0
    assert model["gaps"]
    assert "sk_" not in json.dumps(model)


def test_har_and_sdk(tmp_path: Path):
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.demo.app/v1/orders",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                    "response": {"status": 201},
                }
            ]
        }
    }
    path = tmp_path / "c.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    model_path = tmp_path / "model.json"
    assert main(["analyze", str(path), "-o", str(model_path)]) == 0
    model = json.loads(model_path.read_text())
    assert model["endpoints"][0]["method"] == "POST"
    assert model["endpoints"][0]["statuses"] == [201]
    sdk = tmp_path / "sdk"
    assert main(["sdk", str(model_path), "-o", str(sdk)]) == 0
    assert "def post_v1_orders" in (sdk / "client.py").read_text()
    assert "postV1Orders" in (sdk / "client.ts").read_text()
