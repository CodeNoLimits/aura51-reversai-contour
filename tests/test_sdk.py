import importlib.util
import json
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from contour.analyze import analyze_har, analyze_path
from contour.cli import main
from contour.sdkgen import generate

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample.har"


def test_names_never_collide_and_identifiers_are_safe():
    entries = [
        {"request": {"method": "GET", "url": u, "headers": []}, "response": {"status": 200}}
        for u in ("https://a.test/v1/orders?from=1&page[size]=2&class=x", "https://a.test/v1/orders/ord_1")
    ]
    spec = analyze_har({"log": {"entries": entries}})["openapi"]
    spec["paths"]["/v1/orders"]["post"] = {"operationId": "getV1Orders", "responses": {"200": {"description": "x"}}}
    py, ts, n = generate(spec)
    assert n == 3
    compile(py, "client.py", "exec")
    assert re.findall(r"def (get_v1_orders\w*)\(", py) == ["get_v1_orders", "get_v1_orders_2", "get_v1_orders_by_id"]
    assert "'page[size]': page_size_" in py and "'from': from_" in py and "'class': class_" in py
    assert '"page[size]": page_size_' in ts


def test_sdk_refuses_a_spec_with_a_secret(tmp_path: Path):
    spec = {"openapi": "3.1.0", "info": {"description": "Authorization: Bearer abcdefghijklmnop"}, "paths": {}}
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    assert main(["sdk", str(path), "-o", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out").exists()


class _Echo(BaseHTTPRequestHandler):
    def _reply(self):
        if "missing" in self.path:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "not found"}')
            return
        size = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(size)) if size else None
        out = {"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"), "body": body}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = _reply

    def log_message(self, *args):
        pass


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture()
def sample_sdk(tmp_path: Path) -> Path:
    py, ts, _ = generate(analyze_path(SAMPLE)["openapi"])
    (tmp_path / "client.py").write_text(py, encoding="utf-8")
    (tmp_path / "client.ts").write_text(ts, encoding="utf-8")
    return tmp_path


def test_python_client_talks_http(server, sample_sdk: Path):
    spec = importlib.util.spec_from_file_location("generated_client", sample_sdk / "client.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = mod.Client(base_url=server, token="t0k")
    got = client.get_v1_orders_by_id("ord/1 x")
    assert got["path"] == "/v1/orders/ord%2F1%20x"
    assert got["auth"] == "Bearer t0k"
    assert client.get_v1_orders(limit="2")["path"] == "/v1/orders?limit=2"
    assert client.post_v1_orders(body={"customer_id": "c", "items": []})["body"] == {"customer_id": "c", "items": []}
    with pytest.raises(mod.ApiError) as err:
        client.get_v1_customers_by_id("missing")
    assert err.value.status == 404


def _node_strips_types() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    major, minor = (int(x) for x in subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip("v\n").split(".")[:2])
    return (major, minor) >= (22, 6)


@pytest.mark.skipif(not _node_strips_types(), reason="needs Node >= 22.6 (built-in TypeScript type stripping)")
def test_typescript_client_talks_http(server, sample_sdk: Path):
    (sample_sdk / "package.json").write_text('{"type": "module"}', encoding="utf-8")
    (sample_sdk / "run.mjs").write_text(
        """
import { Client, ApiError } from "./client.ts";
const c = new Client({ baseUrl: process.argv[2], token: "t0k" });
const out = [await c.getV1OrdersById("ord/1 x"), await c.getV1Orders(undefined, "2"), await c.postV1Orders({ customer_id: "c", items: [] })];
try { await c.getV1CustomersById("missing"); } catch (e) { out.push({ apiError: e instanceof ApiError, status: e.status }); }
console.log(JSON.stringify(out));
""",
        encoding="utf-8",
    )
    run = subprocess.run(
        ["node", "--experimental-strip-types", "--no-warnings", "run.mjs", server],
        cwd=sample_sdk, capture_output=True, text=True, timeout=60,
    )
    assert run.returncode == 0, run.stderr
    one, two, three, four = json.loads(run.stdout)
    assert one["path"] == "/v1/orders/ord%2F1%20x" and one["auth"] == "Bearer t0k"
    assert two["path"] == "/v1/orders?limit=2"
    assert three["body"] == {"customer_id": "c", "items": []}
    assert four == {"apiError": True, "status": 404}
