# Exemple

```bash
python -m contour.cli analyze examples/sample.pcap -o model.json
python -m contour.cli analyze ton_fichier.pcap -o model.json
python -m contour.cli analyze ton_fichier.har -o model.json
python -m contour.cli sdk model.json -o sdk_out
```

`examples/sample.pcap` est une requête HTTP fictive, sans secret. Pour la régénérer : `python examples/make_sample.py`.

Le fichier `model.json` se donne ensuite à un agent avec `skills/contour/SKILL.md`. L'agent ne reçoit pas les corps bruts.
