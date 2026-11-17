# Agent Installation Guide for webread-mcp

This step-by-step procedure is intended for an Artificial Intelligence (AI) assistant or agent automating the installation and configuration of `webread-mcp` on behalf of a user.

Follow each step sequentially. Observe strict security rules regarding user secrets and permissions.

---

## Step 1: Verify Node.js Environment (>= 20 Required)

`webread-mcp` uses native Node.js built-in modules (including `node:test`, `node:crypto`, and native `fetch`) and requires **Node.js version 20 or later**.

Run:
```bash
node -v
```

If the version is lower than `v20.0.0`, halt and advise the user to upgrade their Node.js runtime.

---

## Step 2: Inquire About the Scanner Backend

Ask the user to choose their preferred prompt injection scanner backend:

1. **Cloudflare Workers AI (`clef`, Recommended / Default):**
   - Uses Cloudflare Workers AI model `@cf/cloudflare/clef`.
   - Requires Cloudflare Account ID (`CF_ACCOUNT_ID`) and API (Application Programming Interface) Token (`CF_API_TOKEN`).
   - Content is sent over the internet to Cloudflare after automatic data anonymization.
2. **Local Ollama (`ollama`):**
   - Runs locally on the user's machine (default URL: `http://127.0.0.1:11434`, model: `qwen3:4b`).
   - Complete privacy: no external network requests.
   - Requires an active Ollama instance with a suitable model downloaded. Run `ollama pull <model>` (e.g. `ollama pull qwen3:4b` or `ollama pull qwen3:4b-instruct`) or set `WEBREAD_OLLAMA_MODEL` to an installed model; `webread-mcp self-test` checks `/api/tags` to verify the model exists.
   - Note: Running a local model on CPU can be slow. `webread-mcp self-test` executes a test scan and reports latency in milliseconds. If response times exceed the scanner timeout or prove too slow for interactive use, consider enabling GPU acceleration, choosing a lighter model, or increasing `WEBREAD_SCAN_TIMEOUT_MS` (default: 90000 ms for Ollama, 20000 ms for CLEF).
3. **Disabled / Pass-Through (`none`):**
   - **CRITICAL:** Do NOT set `WEBREAD_SCANNER=none` without explicit, informed consent from the user. Bypassing the scanner removes prompt injection detection and increases risk from malicious webpages.

---

## Step 3: Handle Credentials Securely

If the user chooses the Cloudflare (`clef`) backend:
- **Never display secrets in chat, prompt outputs, or public logs.**
- Instruct the user to save their credentials in their client configuration file (e.g. Claude Desktop configuration) or a protected `.env` file with `chmod 600` permissions.
- Required credentials:
  - `CF_ACCOUNT_ID`: Cloudflare account identifier.
  - `CF_API_TOKEN`: Cloudflare Workers AI API bearer token.

---

## Step 4: Add Server to the MCP Client Configuration

### Option A: Claude Code
Add via Claude CLI (Command-Line Interface):
```bash
claude mcp add webread -- npx -y webread-mcp
```
Or for local development:
```bash
claude mcp add webread -- node /path/to/webread-mcp/bin/webread-mcp.js
```

### Option B: Claude Desktop (`claude_desktop_config.json`)
Add under `mcpServers`:
```json
{
  "mcpServers": {
    "webread": {
      "command": "npx",
      "args": ["-y", "webread-mcp"],
      "env": {
        "WEBREAD_SCANNER": "clef",
        "CF_ACCOUNT_ID": "your_cloudflare_account_id",
        "CF_API_TOKEN": "your_cloudflare_api_token"
      }
    }
  }
}
```

### Option C: Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "webread": {
      "command": "npx",
      "args": ["-y", "webread-mcp"],
      "env": {
        "WEBREAD_SCANNER": "ollama",
        "OLLAMA_URL": "http://127.0.0.1:11434",
        "WEBREAD_OLLAMA_MODEL": "qwen3:4b"
      }
    }
  }
}
```

---

## Step 5: Run Self-Test Verification

Execute the built-in self-test to verify runtime compatibility, state directory write permissions, cryptographic Hash-based Message Authentication Code (HMAC) key creation, and scanner configuration:

```bash
npx -y webread-mcp self-test
```
(Or `node bin/webread-mcp.js self-test` in local repository).

Check the output:
- Ensure all checks display `[PASS]`.
- Verify no errors or missing credential warnings are reported.
- If using `ollama`, verify that the model check passes (if missing, pull it with `ollama pull <model>` or adjust `WEBREAD_OLLAMA_MODEL`). Note that `self-test` executes a probe scan and prints the response time in milliseconds; if the scan exceeds `WEBREAD_SCAN_TIMEOUT_MS`, a `[WARN]` is issued with recommendations.

---

## Step 6: Propose Custom Anonymization Rules

Offer to help the user configure a custom anonymization file to redact their sensitive names, domain names, usernames, or internal IDs before sending content to Cloudflare:
- Point them to `docs/anonymization.md` and `examples/anonymize.example.json`.
- Assist them in creating `~/.config/webread/anonymize.json` and pointing `WEBREAD_ANONYMIZE_FILE` to it.
- Verify the file using `webread-mcp anonymize-test <sample.txt>`.

---

## Step 7: Verify Tool Execution

Verify that the MCP tool operates properly by calling `web_read`:
1. Request reading a known safe website:
   ```json
   {
     "url": "https://example.com"
   }
   ```
2. Validate response properties:
   - `ok`: `true`
   - `verdict`: `"clean"`
   - `scanned`: `"clef"`, `"ollama"`, or `"none"`
   - `text`: Wrapped inside `<external-source url="..." scanned="..." verdict="clean" sha="...">` tags followed by an HMAC stamp comment (`<!-- webread:ok:<hmac> -->`).
