# Contour — Signal-Based Reverse Engineering

**by Aura 51 / ReversAi**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/CodeNoLimits/aura51-reversai-contour)](https://github.com/CodeNoLimits/aura51-reversai-contour/stargazers)

> Capture the signals an application emits. Let AI connect the dots. Reconstruct its behavior — legally.

Contour is an open-source platform and agent skill for **legal reverse engineering via signals**.  
It normalizes network traffic and local observations, then uses an LLM to approximate protocols, state machines, and functional models without needing (or touching) the binary.

Designed for interoperability research, clean-room reimplementation, security analysis of software you own, and collaborative signal sharing on GitHub.

## Why Contour?

Most reverse engineering focuses on binaries (Ghidra, IDA, REA, etc.).  
Many valuable systems today are **SaaS, Electron apps, or subscription software** where the interesting part is the protocol and runtime behavior.

Contour specializes in the **signal layer**:
- Network flows (PCAP, HAR, mitmproxy)
- Local interactions (when authorized)
- AI-powered “connect the dots” reasoning

It is complementary to binary tools like [REA](https://github.com/morluto/rea).

## Quick Start

```bash
git clone https://github.com/CodeNoLimits/aura51-reversai-contour
cd aura51-reversai-contour

python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Analyze a PCAP
python -m contour.cli analyze examples/sample.pcap --output model.json

# Or use the skill with your agent (Claude, Grok, Cursor, Codex...)
# See skills/contour/SKILL.md
```

## Architecture

```
Signals (PCAP / HAR / mitm / local traces)
        ↓
Contour Normalizer → Contour Signal Format (JSON)
        ↓
LLM Reasoning Layer (pluggable: local or cloud)
        ↓
Model (protocol description, state machine, clean-room notes, OpenAPI sketch)
        ↓
Optional: share anonymized packs on GitHub
```

## Legal Guardrails

Contour is built for **lawful use only**:
- Software you own or are authorized to analyze
- Interoperability (DMCA §1201(f), EU Software Directive Art. 6)
- Clean-room methods
- Security research with proper authorization
- No circumvention of technical protection measures
- No copying of protected expression

See [LEGAL.md](LEGAL.md) for details.

## Project Structure

- `contour/` — Core analyzer and CLI
- `skills/contour/` — Agent skill definition
- `docs/` — Format specs and architecture
- `examples/` — Sample traces and expected outputs
- `CONTRIBUTING.md` — How to add signal packs and models

## Roadmap

- [x] Contour Signal Format v0.1
- [x] Basic PCAP analyzer
- [ ] HAR / mitmproxy importers
- [ ] LLM prompt templates & structured output
- [ ] Agent skill packaging (Claude Skills / Cursor / Grok)
- [ ] Example public protocol reconstructions
- [ ] Partner contribution templates
- [ ] Enterprise features (audit trails, on-prem)

## Contributing

We welcome signal packs, protocol models, importers, and documentation.  
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

**Aura 51** — Contour of Potential.  
Built for the signal layer of reverse engineering.
