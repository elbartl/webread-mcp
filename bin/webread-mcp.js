#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const config = require('../src/config.js');
const hmac = require('../src/hmac.js');
const anonymizeModule = require('../src/anonymize.js');
const server = require('../src/server.js');
const ollamaBackend = require('../src/backends/ollama.js');

const pkg = require('../package.json');

const USAGE = `webread-mcp v${pkg.version} - Secure Web Page Reader MCP Server

Usage:
  webread-mcp                       Start stdio Model Context Protocol (MCP) server
  webread-mcp --version, -v         Display package version
  webread-mcp --help, -h            Show this help message
  webread-mcp self-test             Verify configuration, state directory, and scanner
  webread-mcp anonymize-test <file> Test data redaction rules on a text file
  webread-mcp verify <file>         Cryptographically verify an HMAC-signed envelope
`;

function maskString(str) {
    if (!str || typeof str !== 'string') return '[not set]';
    if (str.length <= 8) return '****';
    return `${str.slice(0, 4)}...${str.slice(-4)}`;
}

async function runSelfTest() {
    console.log(`Running self-test for webread-mcp v${pkg.version}...`);
    let hasErrors = false;

    // 1. Check Node.js version (>= 20)
    const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
    if (nodeMajor >= 20) {
        console.log(`[PASS] Node.js version: v${process.versions.node} (>= 20)`);
    } else {
        console.error(`[FAIL] Node.js version: v${process.versions.node} (< 20 required)`);
        hasErrors = true;
    }

    // 2. State directory write permissions and HMAC key generation
    const paths = config.getPaths();
    try {
        fs.mkdirSync(paths.stateDir, { recursive: true, mode: 0o700 });
        const testFile = path.join(paths.stateDir, `.test-write-${process.pid}`);
        fs.writeFileSync(testFile, 'test', { mode: 0o600 });
        fs.unlinkSync(testFile);
        console.log(`[PASS] State directory writable: ${paths.stateDir}`);
    } catch (err) {
        console.error(`[FAIL] State directory write error (${paths.stateDir}): ${err.message}`);
        hasErrors = true;
    }

    // HMAC key
    try {
        const key = hmac.ensureKey(paths.key);
        if (key && key.length === 32) {
            console.log(`[PASS] HMAC secret key verified (256-bit, mode 0600)`);
        } else {
            console.error(`[FAIL] HMAC secret key length mismatch`);
            hasErrors = true;
        }
    } catch (err) {
        console.error(`[FAIL] HMAC key setup error: ${err.message}`);
        hasErrors = true;
    }

    // 3. Check anonymization file if configured
    const anonFile = process.env.WEBREAD_ANONYMIZE_FILE;
    if (anonFile) {
        try {
            const rules = anonymizeModule.loadAnonymizeFile(anonFile);
            const lCount = rules.literals ? rules.literals.length : 0;
            const pCount = rules.patterns ? rules.patterns.length : 0;
            console.log(`[PASS] Anonymization file valid (${anonFile}): ${lCount} literals, ${pCount} patterns`);
        } catch (err) {
            console.error(`[FAIL] Anonymization file error (${anonFile}): ${err.message}`);
            hasErrors = true;
        }
    } else {
        console.log(`[INFO] No custom WEBREAD_ANONYMIZE_FILE set; built-in rules active (private IPs, emails, tokens)`);
    }

    // 4. Scanner backend check
    let cfg;
    try {
        cfg = config.getConfig();
    } catch (err) {
        console.error(`[FAIL] ${err.message}`);
        hasErrors = true;
    }

    if (cfg) {
        console.log(`[INFO] Configured scanner backend: ${cfg.scanner}`);

        if (cfg.disabled) {
            console.log(`[WARN] Emergency kill switch is ACTIVE (disabled mode)`);
        }

        if (cfg.scanner === 'none') {
            console.log(`[PASS] Scanner explicitly set to 'none' (pass-through mode with warnings)`);
        } else if (cfg.scanner === 'clef') {
            if (cfg.cfAccountId && cfg.cfApiToken) {
                console.log(`[PASS] Cloudflare credentials configured (Account ID: [configured], Token: [configured])`);
                console.log(`[INFO] Daily neurons budget: ${cfg.dailyNeurons}`);
            } else {
                console.error(`[FAIL] Cloudflare Workers AI credentials missing (CF_ACCOUNT_ID and CF_API_TOKEN required)`);
                hasErrors = true;
            }
        } else if (cfg.scanner === 'ollama') {
            console.log(`[INFO] Ollama backend configured (URL: ${cfg.ollamaUrl}, Model: ${cfg.ollamaModel})`);
            try {
                const ac = new AbortController();
                const timer = setTimeout(() => ac.abort(), 2000);
                const tagsUrl = `${cfg.ollamaUrl.replace(/\/+$/, '')}/api/tags`;
                const res = await fetch(tagsUrl, { signal: ac.signal });
                clearTimeout(timer);
                if (res.ok) {
                    const json = await res.json();
                    const available = Array.isArray(json && json.models)
                        ? json.models.map(m => m.name || m.model).filter(Boolean)
                        : [];
                    const target = cfg.ollamaModel;
                    const found = available.some(name => {
                        if (name === target) return true;
                        if (name === `${target}:latest`) return true;
                        if (target.endsWith(':latest') && name === target.slice(0, -7)) return true;
                        return false;
                    });
                    if (found) {
                        console.log(`[PASS] Ollama backend connection and model "${target}" verified (${cfg.ollamaUrl})`);
                        // Probe test scan on short innocent text
                        const probeText = 'Hello, this is a test page to verify scanner response time.';
                        const scanTimeout = cfg.scanTimeoutMs;
                        const t0 = Date.now();
                        try {
                            const probeRes = await ollamaBackend.scanChunk(probeText, {
                                ollamaUrl: cfg.ollamaUrl,
                                model: target,
                                timeoutMs: scanTimeout,
                                scanTimeoutMs: scanTimeout,
                            });
                            const durationMs = Date.now() - t0;
                            if (probeRes.reason === 'timeout' || durationMs >= scanTimeout) {
                                console.warn(`[WARN] Ollama test scan took ${durationMs}ms (exceeded scanner timeout of ${scanTimeout}ms). Consider using a smaller model, GPU acceleration, or increasing WEBREAD_SCAN_TIMEOUT_MS.`);
                            } else if (probeRes.verdict === 'unverified') {
                                console.error(`[FAIL] Ollama test scan failed: ${probeRes.reason || 'unverified'}`);
                                hasErrors = true;
                            } else {
                                console.log(`[PASS] Ollama test scan completed in ${durationMs}ms (verdict: ${probeRes.verdict})`);
                            }
                        } catch (err) {
                            const durationMs = Date.now() - t0;
                            if (err.name === 'AbortError' || durationMs >= scanTimeout) {
                                console.warn(`[WARN] Ollama test scan took ${durationMs}ms (exceeded scanner timeout of ${scanTimeout}ms). Consider using a smaller model, GPU acceleration, or increasing WEBREAD_SCAN_TIMEOUT_MS.`);
                            } else {
                                console.error(`[FAIL] Ollama test scan error: ${err.message}`);
                                hasErrors = true;
                            }
                        }
                    } else {
                        console.error(`[FAIL] Ollama model "${target}" not found in local tags. Available models: ${available.length > 0 ? available.join(', ') : 'none'}. Run \`ollama pull ${target}\` or configure WEBREAD_OLLAMA_MODEL.`);
                        hasErrors = true;
                    }
                } else {
                    console.error(`[FAIL] Ollama backend returned HTTP ${res.status} (${tagsUrl})`);
                    hasErrors = true;
                }
            } catch (err) {
                console.error(`[FAIL] Ollama backend not reachable at ${cfg.ollamaUrl}: ${err.message}`);
                hasErrors = true;
            }
        } else {
            console.error(`[FAIL] Unknown scanner backend: ${cfg.scanner} (valid: clef, ollama, none)`);
            hasErrors = true;
        }
    }

    if (hasErrors) {
        console.error('\nSelf-test finished with ERRORS.');
        process.exit(1);
    } else {
        console.log('\nSelf-test PASSED successfully.');
        process.exit(0);
    }
}

function runAnonymizeTest(filePath) {
    if (!filePath) {
        console.error('Error: file path argument required for anonymize-test');
        console.error('Usage: webread-mcp anonymize-test <file.txt>');
        process.exit(1);
    }

    let text;
    try {
        text = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        console.error(`Error reading file "${filePath}": ${err.message}`);
        process.exit(1);
    }

    try {
        const redacted = anonymizeModule.anonymize(text);
        process.stdout.write(redacted);
        process.exit(0);
    } catch (err) {
        console.error(`Anonymization error: ${err.message}`);
        process.exit(1);
    }
}

function runVerify(inputArg) {
    let content = '';

    if (inputArg && inputArg !== '-') {
        try {
            content = fs.readFileSync(inputArg, 'utf8');
        } catch (_) {
            content = String(inputArg);
        }
    } else {
        try {
            content = fs.readFileSync(0, 'utf8');
        } catch (err) {
            console.error(`Error reading input: ${err.message}`);
            process.exit(1);
        }
    }

    const res = hmac.verify(content);
    if (res.ok) {
        console.log('VALID');
        console.log(`URL: ${res.url}`);
        console.log(`Scanned by: ${res.scanned}`);
        console.log(`Verdict: ${res.verdict}`);
        console.log(`SHA-256: ${res.sha}`);
        process.exit(0);
    } else {
        console.error(`INVALID (${res.reason})`);
        process.exit(1);
    }
}

async function main() {
    const args = process.argv.slice(2);
    const cmd = args[0];

    if (!cmd || cmd === 'serve') {
        server.startStdioServer();
        return;
    }

    if (cmd === '--version' || cmd === '-v') {
        console.log(pkg.version);
        process.exit(0);
    }

    if (cmd === '--help' || cmd === '-h') {
        console.log(USAGE);
        process.exit(0);
    }

    if (cmd === 'self-test') {
        await runSelfTest();
        return;
    }

    if (cmd === 'anonymize-test') {
        runAnonymizeTest(args[1]);
        return;
    }

    if (cmd === 'verify') {
        runVerify(args[1]);
        return;
    }

    console.error(`Unknown command: ${cmd}\n`);
    console.error(USAGE);
    process.exit(1);
}

main().catch((err) => {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
});
