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
- **Never ask the user to paste secrets into the chat, and never print them in outputs or logs.**
- Tell the user where to get them: Account ID on the Cloudflare dashboard home page; API token under **My Profile → API Tokens → Create Token → "Workers AI" template**.
- Write the MCP config with placeholders (`your_account_id`, `your_api_token`) and let the user fill them in, or have them store the values in a `chmod 600` env file.
- Required credentials:
  - `CF_ACCOUNT_ID`: Cloudflare account identifier.
  - `CF_API_TOKEN`: Cloudflare Workers AI API bearer token.

---

## Step 4: Add Server to the MCP Client Configuration

Detect which client the user runs and edit the right file. **Merge** the `webread` entry into the existing configuration; never overwrite or remove other servers. Make a backup copy of the file before editing.

| Client | Config location |
| ------ | --------------- |
| Claude Code | CLI command below (stored in `~/.claude.json`) |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` (all projects) or `<project>/.cursor/mcp.json` |
| Codex CLI | `~/.codex/config.toml` |

### Option A: Claude Code
```bash
claude mcp add webread --scope user \
  -e CF_ACCOUNT_ID=your_account_id \
  -e CF_API_TOKEN=your_api_token \
  -- npx -y webread-mcp
```
For Ollama use `-e WEBREAD_SCANNER=ollama -e WEBREAD_OLLAMA_MODEL=<model>` instead of the Cloudflare variables. Keep the server name (`webread`) right after `add`: `-e` accepts several values and would swallow a name placed after it. Confirm with `claude mcp get webread`.

For a local checkout instead of npm:
```bash
claude mcp add webread --scope user -- node /absolute/path/to/webread-mcp/bin/webread-mcp.js
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
        "CF_ACCOUNT_ID": "your_account_id",
        "CF_API_TOKEN": "your_api_token"
      }
    }
  }
}
```

### Option C: Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)
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

### Option D: Codex CLI (`~/.codex/config.toml`)
```toml
[mcp_servers.webread]
command = "npx"
args = ["-y", "webread-mcp"]
env = { CF_ACCOUNT_ID = "your_account_id", CF_API_TOKEN = "your_api_token" }
```

---

## Step 5: Run Self-Test Verification

`self-test` reads environment variables from the shell it runs in, **not** from the MCP client config. Run it with the same variables the user configured:

```bash
CF_ACCOUNT_ID=... CF_API_TOKEN=... npx -y webread-mcp self-test
# or
WEBREAD_SCANNER=ollama WEBREAD_OLLAMA_MODEL=<model> npx -y webread-mcp self-test
```
(Or `node bin/webread-mcp.js self-test` in a local checkout.)

If the credentials are only in the client config and you cannot run the command without seeing them, ask the user to run it and paste back only the `[PASS]`/`[FAIL]` lines.

Check the output:
- Ensure all checks display `[PASS]` and the last line is `Self-test PASSED successfully.`
- `[FAIL] Cloudflare Workers AI credentials missing` means the variables were not set in that shell.
- If using `ollama`, verify that the model check passes (if missing, pull it with `ollama pull <model>` or adjust `WEBREAD_OLLAMA_MODEL`). `self-test` executes a probe scan and prints the response time; if the scan exceeds `WEBREAD_SCAN_TIMEOUT_MS`, a `[WARN]` is issued with recommendations.

---

## Step 6: Install the Agent Skill

The skill tells agents when to use `web_read` and how to handle each verdict. It is in the GitHub repository only, not in the npm package.

| Agent | Destination |
| ----- | ----------- |
| Claude Code (all projects) | `~/.claude/skills/webread/SKILL.md` |
| Claude Code (one project) | `<project>/.claude/skills/webread/SKILL.md` |
| Other agents with `SKILL.md` support | `webread/SKILL.md` in that agent's skills directory |
| Agents without skill support | add the file's content to the agent's instructions (e.g. `AGENTS.md`) |

```bash
mkdir -p ~/.claude/skills/webread
curl -fsSL https://raw.githubusercontent.com/elbartl/webread-mcp/main/skills/webread/SKILL.md \
  -o ~/.claude/skills/webread/SKILL.md
```

---

## Step 7: Propose Custom Anonymization Rules

Anonymization redacts strings from the text sent to the scanner (Cloudflare or Ollama). The agent still receives the original page text. Offer it especially when the user chose `clef`.

1. Ask the user which values to hide: their name, organization, internal domains, host names, account or customer ID formats. Do not guess or collect these from other files without asking.
2. Create `~/.config/webread/anonymize.json` from `examples/anonymize.example.json` and set `chmod 600`. Put fixed strings in `literals` and ID formats in `patterns` (anchored with `\\b`). Rules: [docs/anonymization.md](anonymization.md).
3. Create a short sample text containing the values and run:
   ```bash
   WEBREAD_ANONYMIZE_FILE=$HOME/.config/webread/anonymize.json npx -y webread-mcp anonymize-test sample.txt
   ```
   Confirm every value became a placeholder, then delete the sample file.
4. Add `WEBREAD_ANONYMIZE_FILE` with an **absolute path** to the server `env` in the client config. `~` and `$HOME` are not expanded inside JSON or TOML.
5. Run `self-test` with the same variable and expect `[PASS] Anonymization file valid`. An invalid file stops the server at startup.
6. Never commit the rules file or copy it into shared folders: it lists the user's private data.

---

## Step 8: Restart and Verify Tool Execution

Ask the user to restart the MCP client (Claude Desktop: fully quit and reopen; Claude Code / Codex: start a new session). Then verify that the MCP tool operates properly by calling `web_read`:
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
3. Report the result to the user, including the scanner in use and where the config was written.
