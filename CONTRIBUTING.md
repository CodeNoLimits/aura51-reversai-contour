# Contributing to Contour

Thank you for helping build the signal layer of reverse engineering.

## Ways to Contribute
- **Signal packs**: Anonymized, consented traces + metadata (preferred format: Contour Signal Format)
- **Protocol models**: Inferred state machines or field descriptions from public protocols
- **Importers**: HAR, mitmproxy, Frida, etc.
- **LLM prompts**: Better “connect the dots” templates
- **Documentation and examples**
- **Bug fixes and tests**

## Signal Pack Guidelines
1. Only contribute data you have the right to share
2. Remove personal data, secrets, and authentication tokens
3. Include provenance and legal basis in metadata
4. Prefer passive observation over active probing

## Development Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Pull Request Process
1. Fork the repo
2. Create a feature branch
3. Add tests if applicable
4. Ensure the code runs cleanly
5. Open a PR with a clear description

By contributing, you agree that your contributions are licensed under the MIT License.
