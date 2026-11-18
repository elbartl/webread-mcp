# Sensitive Data Anonymization Guide

Before sending webpage content to a cloud-hosted Large Language Model (LLM) scanner such as Cloudflare Workers AI, `webread-mcp` automatically anonymizes sensitive data to protect privacy.

This document explains how anonymization works, what data to redact, how to configure custom rules using `WEBREAD_ANONYMIZE_FILE`, and common pitfalls to avoid.

---

## Why Anonymize?

- **Cloud Backends (e.g., Cloudflare Workers AI `clef`):** Content chunks are transmitted over the internet to Cloudflare Workers AI for prompt injection classification. Redacting private identifiers, hostnames, user names, and account numbers ensures external services never see sensitive information.
- **Local Backends (e.g., Ollama):** When running locally with Ollama, data never leaves your machine. Anonymization remains active as a defense-in-depth measure, but is less critical than with cloud-based inference.

**Scope:** anonymization changes only the text sent to the scanner backend. The page URL is not sent to the scanner, and the agent still receives the original, unredacted page text.

---

## Built-In Rules

By default, `webread-mcp` automatically detects and redacts:
1. **Private IPv4 addresses:** RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, and the 16-bit private-use block), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and Carrier-Grade Network Address Translation (`100.64.0.0/10`) -> replaced with `[IP_ADDRESS]`.
2. **Private IPv6 addresses:** Loopback (`::1`), Unique Local Addresses (`fc00::/7`), link-local (`fe80::/10`), and IPv4-mapped private IPv6 addresses -> replaced with `[IPV6_ADDRESS]`.
3. **Email addresses:** General email patterns -> replaced with `[EMAIL]`.
4. **Common API credentials:** Common patterns for tokens such as `sk-...`, `ghp_...`, `AKIA...`, `xoxb-...` -> replaced with `[API_TOKEN]`.

---

## Custom Anonymization File

You can supply additional custom rules via an environment variable pointing to a JSON (JavaScript Object Notation) file:

```bash
export WEBREAD_ANONYMIZE_FILE="$HOME/.config/webread/anonymize.json"
```

In an MCP client config file (JSON or TOML), put the variable in the server's `env` block with an **absolute path**, e.g. `"WEBREAD_ANONYMIZE_FILE": "/home/you/.config/webread/anonymize.json"`. `~` and `$HOME` are not expanded there. Set `chmod 600` on the file and keep it out of version control: it lists your private data. Step-by-step setup: [README → Anonymization](../README.md#anonymization).

### What to Include in Your Custom File
- **Personal and organizational names:** User full name, usernames, organization names.
- **Internal domain names:** Corporate or internal domains (e.g. `mycompany.lan`, `corp.internal`).
- **Internal hostnames:** Server and machine names (e.g. `gateway-prod-01`, `db-master`).
- **Messenger and account IDs:** Chat user/channel IDs, messenger IDs, team account numbers.
- **Physical addresses and telephone numbers:** Office addresses, phone numbers.
- **Internal identifiers:** Customer IDs, employee IDs, project codes.

---

## File Format: Literals vs. Patterns

The JSON file accepts two top-level arrays: `literals` and `patterns`.

```json
{
  "literals": [
    {
      "value": "Alice Smith",
      "replace": "[NAME]",
      "caseInsensitive": true
    },
    {
      "value": "internal.company.com",
      "replace": "[INTERNAL_DOMAIN]",
      "caseInsensitive": true
    }
  ],
  "patterns": [
    {
      "regex": "\\bEMP-\\d{5}\\b",
      "flags": "g",
      "replace": "[EMPLOYEE_ID]"
    },
    {
      "regex": "\\bTG-\\d{8,12}\\b",
      "flags": "gi",
      "replace": "[MESSENGER_ID]"
    }
  ]
}
```

### 1. `literals` (Exact Substrings)
Use `literals` for static strings like names, domain names, or server identifiers.
- `value` (string, required): Exact text to match.
- `replace` (string, required): Substitution placeholder.
- `caseInsensitive` (boolean, optional, default `false`): If `true`, matches regardless of character casing.

**Order of execution:** Literals are automatically sorted by string length in descending order before replacement. This prevents shorter substrings from breaking longer names (e.g., matching "Alice Smith" before "Alice").

### 2. `patterns` (Regular Expressions)
Use `patterns` for structured identifiers matching a dynamic pattern (account numbers, user codes).
- `regex` (string, required): Regular expression string (remember to escape backslashes in JSON, e.g. `\\b` or `\\d`).
- `flags` (string, optional, default `"g"`): Regex flags (e.g. `"gi"` for global and case-insensitive).
- `replace` (string, required): Substitution text.

---

## Order of Replacement

When text is anonymized, rules are evaluated in this exact sequence:
1. **Custom Literals:** Longest strings replaced first.
2. **Custom Patterns:** Applied in the order listed in the JSON file.
3. **Built-in Rules:** IP addresses, emails, and credentials redacted last.

---

## Testing Your Rules: `anonymize-test`

You can test your custom configuration on any sample text file without starting the Model Context Protocol (MCP) server:

```bash
WEBREAD_ANONYMIZE_FILE="./my-rules.json" webread-mcp anonymize-test sample.txt
```

This prints the redacted output directly to standard output (`stdout`), allowing you to inspect whether all target strings were substituted properly.

---

## Safety Limits & Pitfalls to Avoid

To maintain system reliability and prevent Regular Expression Denial of Service (ReDoS) attacks, `webread-mcp` validates all configuration rules at startup:

1. **ReDoS Protection (Nested Quantifiers):**
   Patterns with nested repetitions such as `(a+)+`, `(a*)*`, or `([a-z]+)+` trigger catastrophic backtracking when evaluated against non-matching text. `webread-mcp` automatically detects nested quantifiers and **fails immediately with a descriptive startup error**.
2. **Rule Counts & Length Bounds:**
   - Maximum 100 literals (max length 500 characters per literal).
   - Maximum 50 regex patterns (max length 200 characters per regex).
   - Maximum replacement string length: 100 characters.
3. **Avoid Overly Broad Patterns:**
   - Do NOT use unanchored patterns like `.*` or `\\d+` without word boundaries (`\\b`), as they will corrupt normal prose and URLs.
   - Always anchor regular expressions with word boundaries (`\\b`) or distinctive prefixes (e.g. `\\bID-\\d{4}\\b`).
4. **Invalid Regular Expressions:**
   - Any syntax error in a regular expression will fail validation during startup rather than being silently ignored. Run `webread-mcp self-test` to verify your configuration.
