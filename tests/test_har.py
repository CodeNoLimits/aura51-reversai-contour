import json
from pathlib import Path

from contour.analyze import analyze_har, analyze_path, confidence
from contour.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample.har"


def _e(method, url, status=200, res=None, req=None, headers=()):
    request = {"method": method, "url": url, "headers": list(headers)}
    if req is not None:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps(req)}
    content = {"mimeType": "application/json", "text": json.dumps(res)} if res is not None else {}
    return {"request": request, "response": {"status": status, "content": content}}


def _har(*entries):
    return {"log": {"entries": list(entries)}}


def test_har_and_sdk(tmp_path: Path):
    path = tmp_path / "c.har"
    path.write_text(json.dumps(_har(_e("POST", "https://api.demo.app/v1/orders", 201))), encoding="utf-8")
    model_path = tmp_path / "model.json"
    assert main(["analyze", str(path), "-o", str(model_path)]) == 0
    model = json.loads(model_path.read_text())
    assert model["endpoints"][0]["method"] == "POST"
    assert model["endpoints"][0]["statuses"] == [201]
    sdk = tmp_path / "sdk"
    assert main(["sdk", str(model_path), "-o", str(sdk)]) == 0
    assert "def post_v1_orders" in (sdk / "client.py").read_text()
    assert "postV1Orders" in (sdk / "client.ts").read_text()


def test_sample_har_structure_without_values():
    model = analyze_path(SAMPLE)
    ops = {(e["method"], e["path"]): e for e in model["endpoints"]}
    assert set(ops) == {
        ("GET", "/v1/customers/{id}"),
        ("GET", "/v1/orders"),
        ("POST", "/v1/orders"),
        ("GET", "/v1/orders/{id}"),
        ("PATCH", "/v1/orders/{id}"),
    }
    assert model["stats"]["skippedStatic"] == 1
    assert ops[("GET", "/v1/orders/{id}")]["statuses"] == [200, 404]
    assert ops[("POST", "/v1/orders")]["statuses"] == [201, 422]
    assert ops[("GET", "/v1/orders")]["query"] == ["cursor", "limit"]
    assert ops[("PATCH", "/v1/orders/{id}")]["confidence"] == 0.5
    body = ops[("POST", "/v1/orders")]["requestSchema"]
    assert body["required"] == ["customer_id", "items"]
    assert body["properties"]["coupon"]["type"] == ["string", "null"]
    assert any(g.startswith("PATCH /v1/orders/{id} was seen once") for g in model["gaps"])
    spec = model["openapi"]
    assert spec["paths"]["/v1/orders/{id}"]["get"]["parameters"][0] == {
        "name": "id", "in": "path", "required": True, "schema": {"type": "string"}
    }
    assert spec["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"

    source, blob = SAMPLE.read_text(), json.dumps(model)
    for value in ("demo-not-a-real-token", "demo-session", "alice@example.com", "Alice Martin", "SPRING10", "BX-12", "cus_77", "ord_1001"):
        assert value in source
        assert value not in blob
    assert model["stats"]["secretsSeenInSource"] > 0


def test_path_templating():
    har = _har(
        _e("GET", "https://a.test/v1/customers/cus_123/payment_methods/pm_456"),
        _e("GET", "https://a.test/api_v2/users/550e8400-e29b-41d4-a716-446655440000"),
        _e("GET", "https://a.test/v1/orders/42/line_items"),
        _e("GET", "https://a.test/v1/users/alice%40example.com"),
    )
    paths = {e["path"] for e in analyze_har(har)["endpoints"]}
    assert paths == {
        "/v1/customers/{id}/payment_methods/{id2}",
        "/api_v2/users/{id}",
        "/v1/orders/{id}/line_items",
        "/«redacted»",
    }


def test_noise_and_host_filter():
    har = _har(
        _e("GET", "https://api.a.test/v1/me", res={"ok": True}),
        _e("POST", "https://www.analytics.test/collect"),
        _e("GET", "https://cdn.a.test/app.9f8e.js"),
        _e("GET", "data:image/png;base64,AAAA"),
    )
    merged = analyze_har(har)
    assert {e["host"] for e in merged["endpoints"]} == {"api.a.test", "www.analytics.test"}
    assert any("Calls to 2 hosts" in g for g in merged["gaps"])
    only = analyze_har(har, host="a.test")
    assert [(e["host"], e["path"]) for e in only["endpoints"]] == [("api.a.test", "/v1/me")]
    assert only["stats"]["skippedStatic"] == 1


def test_secret_keys_and_id_maps_stay_out():
    har = _har(
        _e("GET", "https://a.test/v1/team", res={"alice@example.com": {"role": "admin"}, "name": "x"}),
        _e("GET", "https://a.test/v1/prices", res={"price_1Ab": {"amount": 100}, "price_2Cd": {"amount": 250}}),
    )
    model = analyze_har(har)
    assert "alice@example.com" not in json.dumps(model)
    assert any("looked like a secret" in g for g in model["gaps"])
    prices = next(e for e in model["endpoints"] if e["path"] == "/v1/prices")["responseSchemas"]["200"]
    assert prices == {"type": "object", "additionalProperties": {"type": "object", "properties": {"amount": {"type": "integer"}}, "required": ["amount"]}}


def test_bad_inputs(tmp_path: Path, capsys):
    bom = tmp_path / "bom.har"
    bom.write_text("﻿" + json.dumps(_har(_e("GET", "https://a.test/v1/x"))), encoding="utf-8")
    assert analyze_path(bom)["stats"]["endpoints"] == 1
    not_har = tmp_path / "x.json"
    not_har.write_text('{"foo": 1}', encoding="utf-8")
    assert main(["analyze", str(not_har), "-o", str(tmp_path / "m.json")]) == 1
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x00\x01binary")
    assert main(["analyze", str(junk), "-o", str(tmp_path / "m.json")]) == 1
    assert "not a HAR" in capsys.readouterr().err
    assert not (tmp_path / "m.json").exists()


def test_confidence_curve():
    assert [confidence(n) for n in (1, 2, 3, 5, 20)] == [0.5, 0.75, 0.88, 0.97, 0.99]
