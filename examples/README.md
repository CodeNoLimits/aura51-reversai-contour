# Examples

Everything here is fictional. The "secrets" are fake on purpose: they are shaped like real ones so you can watch Contour refuse to copy them.

| File | What it is |
|---|---|
| `sample.har` | 13 entries from a fictional orders API: bearer token, session cookie, a customer's email, a JS bundle, a `data:` URL, a 404 and a 422. |
| `sample.pcap` | One plaintext HTTP request (needs scapy to read). |
| `output/` | What Contour produces from `sample.har`. A test fails if it drifts from the code. |
| `make_sample.py` | Regenerates `sample.har` (and `sample.pcap` with `--pcap`). |

```bash
python3 -m contour analyze examples/sample.har --openapi openapi.json
python3 -m contour sdk openapi.json -o sdk_out
python3 -m contour analyze examples/sample.pcap        # pip install scapy first
```

Regenerate the committed output after changing the analyzer or the generator:

```bash
python3 -m contour analyze examples/sample.har -o examples/output/model.json --openapi examples/output/openapi.json
python3 -m contour sdk examples/output/openapi.json -o examples/output
```

`model.json` can be handed to an agent along with `skills/contour/SKILL.md`. The agent never receives raw bodies, because there are none in the model.
