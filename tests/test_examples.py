from pathlib import Path

from contour.cli import main

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "examples" / "output"


def test_committed_example_output_is_fresh(tmp_path: Path):
    """examples/output/ is what the README links to. It must match the code."""
    assert main(["analyze", str(ROOT / "examples" / "sample.har"), "-o", str(tmp_path / "model.json"), "--openapi", str(tmp_path / "openapi.json")]) == 0
    assert main(["sdk", str(tmp_path / "openapi.json"), "-o", str(tmp_path)]) == 0
    for name in ("model.json", "openapi.json", "client.py", "client.ts"):
        assert (tmp_path / name).read_text(encoding="utf-8") == (OUTPUT / name).read_text(encoding="utf-8"), (
            f"examples/output/{name} is stale. Regenerate it with the commands in examples/README.md"
        )
