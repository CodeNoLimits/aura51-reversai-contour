# Example: Running Contour

```bash
# After installing dependencies
python -m contour.cli analyze path/to/your.pcap -o model.json

# Then open model.json and feed it to your agent with the Contour skill
```

For a full LLM reconstruction, provide the model JSON plus any additional context to an agent that has loaded `skills/contour/SKILL.md`.
