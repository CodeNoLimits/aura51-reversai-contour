"""Write the fictional example captures. No real data, no live secret.

    python examples/make_sample.py          # examples/sample.har (stdlib only)
    python examples/make_sample.py --pcap   # also examples/sample.pcap (needs scapy)
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
API = "https://api.shop.example"
# Fake on purpose: shaped like secrets so you can watch Contour refuse to copy them.
AUTH = [{"name": "Authorization", "value": "Bearer demo-not-a-real-token-0123456789"}]
COOKIE = [{"name": "Cookie", "value": "session=demo-session-not-real"}]


def order(oid, status="pending", coupon=None, items=None):
    items = items or [{"sku": "BX-12", "qty": 2, "unit_price": 2100}]
    return {
        "id": oid,
        "status": status,
        "customer_id": "cus_77",
        "currency": "usd",
        "total": sum(i["qty"] * i["unit_price"] for i in items),
        "items": items,
        "coupon": coupon,
        "created_at": "2026-10-01T09:12:00Z",
    }


def entry(i, method, url, status, res=None, req=None, headers=AUTH):
    request = {"method": method, "url": url, "httpVersion": "HTTP/1.1", "headers": headers, "queryString": [], "cookies": [], "headersSize": -1, "bodySize": -1}
    if req is not None:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps(req)}
    text = json.dumps(res) if res is not None else ""
    mime = "application/json" if res is not None else "text/plain"
    return {
        "startedDateTime": f"2026-10-12T10:00:{i:02d}.000Z",
        "time": 42,
        "request": request,
        "response": {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": mime}],
            "cookies": [],
            "content": {"size": len(text), "mimeType": mime, "text": text},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        },
        "cache": {},
        "timings": {"send": 1, "wait": 40, "receive": 1},
    }


def har() -> dict:
    e = [
        ("GET", f"{API}/v1/orders?limit=2", 200, {"data": [order("ord_1001"), order("ord_1002", "paid", "SPRING10")], "has_more": True, "next_cursor": "c_2"}),
        ("GET", f"{API}/v1/orders?limit=2&cursor=c_2", 200, {"data": [order("ord_1003", "shipped")], "has_more": False, "next_cursor": None}),
        ("GET", f"{API}/v1/orders/ord_1001", 200, order("ord_1001")),
        ("GET", f"{API}/v1/orders/ord_1002", 200, order("ord_1002", "paid", "SPRING10")),
        ("GET", f"{API}/v1/orders/ord_9999", 404, {"error": {"code": "not_found", "message": "No such order"}}),
        ("POST", f"{API}/v1/orders", 201, order("ord_1004"), {"customer_id": "cus_77", "items": [{"sku": "BX-12", "qty": 2}], "coupon": None}),
        ("POST", f"{API}/v1/orders", 201, order("ord_1005", coupon="SPRING10"), {"customer_id": "cus_78", "items": [{"sku": "TS-03", "qty": 1}], "coupon": "SPRING10"}),
        ("POST", f"{API}/v1/orders", 201, order("ord_1006"), {"customer_id": "cus_80", "items": [{"sku": "BX-12", "qty": 1}]}),
        ("POST", f"{API}/v1/orders", 422, {"error": {"code": "invalid_items", "message": "items must not be empty", "field": "items"}}, {"customer_id": "cus_79", "items": []}),
        ("PATCH", f"{API}/v1/orders/ord_1001", 200, order("ord_1001", "paid"), {"status": "paid"}),
        ("GET", f"{API}/v1/customers/cus_77", 200, {"id": "cus_77", "email": "alice@example.com", "name": "Alice Martin", "created_at": "2026-09-01T10:00:00Z"}),
    ]
    entries = [entry(i, m, u, s, res, *rest) for i, (m, u, s, res, *rest) in enumerate(e)]
    entries[-1]["request"]["headers"] = AUTH + COOKIE
    # Noise every real HAR has: Contour skips both.
    entries.append(entry(len(entries), "GET", "https://cdn.shop.example/assets/app.3f9a1c.js", 200, headers=[]))
    entries.append(entry(len(entries), "GET", "data:image/png;base64,iVBORw0KGgo=", 200, headers=[]))
    return {"log": {"version": "1.2", "creator": {"name": "contour-example", "version": "1"}, "pages": [], "entries": entries}}


def pcap(dest: Path) -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    raw = b"GET /v1/customers/cus_123?expand=card HTTP/1.1\r\nHost: api.vellum.test\r\nAccept: application/json\r\n\r\n"
    wrpcap(str(dest), [Ether() / IP(src="10.0.0.8", dst="10.0.0.1") / TCP(sport=4444, dport=80) / Raw(load=raw)])


def main() -> None:
    dest = HERE / "sample.har"
    dest.write_text(json.dumps(har(), indent=1) + "\n", encoding="utf-8")
    print(dest)
    if "--pcap" in sys.argv:
        pcap(HERE / "sample.pcap")
        print(HERE / "sample.pcap")


if __name__ == "__main__":
    main()
