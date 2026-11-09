# Harness installation

IC does not embed a model or harness runtime. Install a supported Pi, Claude Code or Codex version, then configure its MCP connection with `ic mcp give`. Start the harness directly in the intended project directory.

`ic install --harness pi|claude-code|codex --version EXACT --directory NEW_PATH` installs an explicitly selected version into a new directory. External harness dependencies are separate from the Rust service. `ic launch` is removed.

Use `ic --help` for the accepted arguments. Tests use deterministic loopback model endpoints; production model credentials are not required for IC protocol tests.
