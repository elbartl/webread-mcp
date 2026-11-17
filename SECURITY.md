# Security Policy

## Supported Versions

Only the latest published version of `webread-mcp` receives active security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of `webread-mcp` seriously. If you discover a vulnerability or potential security risk, please report it privately.

**Do not report security issues through public GitHub issues or public discussions.**

Please submit your report through **GitHub Security Advisories**:
1. Navigate to the repository on GitHub (`https://github.com/elbartl/webread-mcp`).
2. Go to the **Security** tab.
3. Click **Report a vulnerability** to open an advisory draft.

Your report should include:
- A clear description of the vulnerability.
- Steps to reproduce the issue (including proof-of-concept code, inputs, or requests if applicable).
- Potential impact and affected configurations (e.g. scanner backend, network context).

We will review your submission, validate the vulnerability, and coordinate a fix and release.

## Scope

In scope for security reports:
- Server-Side Request Forgery (SSRF) bypasses allowing access to private, loopback, link-local, or reserved network destinations.
- DNS (Domain Name System) rebinding bypasses or IP pinning circumvention.
- Flaws in HTML text extraction that allow invisible, bidirectional, or hidden prompt injection payloads to pass undetected.
- Bypass of Hash-based Message Authentication Code (HMAC) signature verification.
- Denial of Service (DoS) / Regular Expression Denial of Service (ReDoS) vulnerabilities in anonymization or parsing rules.

Out of scope:
- Client-side attacks against downstream Model Context Protocol (MCP) clients that do not observe returned output envelopes.
- False negatives from machine learning classification models (prompt injection detection is probabilistic and serves as defense-in-depth).
