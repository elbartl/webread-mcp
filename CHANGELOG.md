# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added agent skill `skills/webread/SKILL.md` (repository only, not included in the npm package).

### Changed
- README: step-by-step installation with config file locations for Claude Code, Claude Desktop (macOS/Windows), Cursor and Codex CLI; how to get Cloudflare credentials; self-test with shell variables; skill install paths; files created in the state directory.
- README: new "Anonymization" section (scope, built-in rules, own rules file, testing, enabling with an absolute path) and "For AI Agents" section.
- docs/AGENT_INSTALL.md: config locations table, merge-not-overwrite rule, skill install step, safer anonymization step, restart before verification.

## [0.1.0] - 2026-11-17

### Added
- Model Context Protocol (MCP) server providing the `web_read` tool via standard input/output (stdio) JSON-RPC (JavaScript Object Notation Remote Procedure Call).
- Strict Server-Side Request Forgery (SSRF) validation blocking private IPv4 and IPv6 addresses, loopback, Carrier-Grade Network Address Translation (CGNAT), link-local, multicast, and reserved ranges.
- DNS resolution checks on all resolved records and IP pinning preventing Domain Name System (DNS) rebinding attacks.
- Streaming HTTP/HTTPS fetch with size cap (~2 MB) and per-hop redirect re-validation.
- HTML text extraction removing comments, invisible Unicode, bidirectional override characters, and CSS/HTML-hidden content.
- Pluggable prompt injection and hijack scanner backends:
  - `clef` (default): Cloudflare Workers AI `@cf/cloudflare/clef` model with automated chunking and daily neuron budget enforcement.
  - `ollama`: Local Large Language Model (LLM) backend via Ollama HTTP API (`qwen3:4b` by default).
  - `none`: Explicit pass-through mode with visible security warnings.
- State management and atomic budget locking (`budget.json` and `budget.lock`) preventing concurrent quota exhaustion.
- Cryptographic Hash-based Message Authentication Code (HMAC-SHA256) signature verification and `<external-source>` content envelopes.
- Sensitive data anonymization prior to cloud inspection (built-in private IP and email rules, plus custom JSON configuration with ReDoS protection).
- CLI utility commands: `webread-mcp` (stdio server), `self-test`, `anonymize-test`, `verify`, and `--version`.
