# Security And Privacy

The scanner never executes scanned files. Source paths are resolved before reading, symlink targets are rejected, file sizes are bounded, extensions are allowlisted, and common generated/vendor directories are excluded.

Source context is sent to the configured LLM endpoint. Keep `OLLAMA_BASE_URL` pointed at a trusted local service when scanning proprietary code.
