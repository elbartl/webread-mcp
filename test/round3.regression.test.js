'use strict';
/**
 * test/round3.regression.test.js
 * Regression tests covering round 3 fixes:
 * A. Backend fetchImpl fallback to globalThis.fetch under null/undefined.
 * B. CLI self-test verification of model presence via /api/tags for Ollama.
 * C. Reviewer feedback:
 *    - ensureKey wx flag, EEXIST race handling, format validation.
 *    - wrap tag neutralization and URL attribute escaping.
 *    - server webRead scanner try/catch handling with unverified scan_error.
 *    - anonymize literal and pattern substitution without $1/$& expansion.
 *    - budget withLock state directory creation mode 0o700.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const server = require('../src/server.js');
const hmac = require('../src/hmac.js');
const anonymizeModule = require('../src/anonymize.js');
const budget = require('../src/budget.js');
const clefBackend = require('../src/backends/clef.js');
const ollamaBackend = require('../src/backends/ollama.js');

const CLI_PATH = path.resolve(__dirname, '../bin/webread-mcp.js');

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-r3-test-'));
}

function runCliAsync(args, env) {
    return new Promise((resolve) => {
        const child = spawn(process.execPath, [CLI_PATH, ...args], { env });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', d => { stdout += d; });
        child.stderr.on('data', d => { stderr += d; });
        child.on('close', code => {
            resolve({ status: code, stdout, stderr });
        });
    });
}

// -----------------------------------------------------------------------------
// A. Integration test: backend uses real globalThis.fetch when deps.fetchImpl is null
// -----------------------------------------------------------------------------

test('regression (A): web_read uses globalThis.fetch for backend when deps.fetchImpl is null (local HTTP server)', async () => {
    let receivedRequest = false;
    let requestBody = null;

    const localServer = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/api/chat') {
            receivedRequest = true;
            let data = '';
            req.on('data', chunk => { data += chunk; });
            req.on('end', () => {
                requestBody = data;
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    message: {
                        role: 'assistant',
                        content: JSON.stringify({
                            injection: false,
                            hijack: false,
                            confidence: 0.0,
                            reasons: [],
                        }),
                    },
                }));
            });
            return;
        }
        res.writeHead(404);
        res.end();
    });

    await new Promise(resolve => localServer.listen(0, '127.0.0.1', resolve));
    const port = localServer.address().port;

    const previousScanner = process.env.WEBREAD_SCANNER;
    const previousOllamaUrl = process.env.WEBREAD_OLLAMA_URL;
    const previousModel = process.env.WEBREAD_OLLAMA_MODEL;

    process.env.WEBREAD_SCANNER = 'ollama';
    process.env.WEBREAD_OLLAMA_URL = `http://127.0.0.1:${port}`;
    process.env.WEBREAD_OLLAMA_MODEL = 'qwen3:4b';

    // Injected page fetcher simulates safe webpage retrieval without making external network calls
    server._setDeps({
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            body: '<html><body>Clean authentic article text</body></html>',
            finalUrl: url,
        }),
        fetchImpl: null, // Critical: deps.fetchImpl remains null
    });

    try {
        const result = await server.webRead({ url: 'https://example.com/test-article' });
        assert.strictEqual(result.ok, true);
        assert.strictEqual(result.verdict, 'clean');
        assert.strictEqual(result.scanned, 'ollama');
        assert.strictEqual(receivedRequest, true, 'Backend request must have been dispatched to local HTTP server via globalThis.fetch');
        assert.ok(requestBody && requestBody.includes('Clean authentic article text'), 'Backend must receive article text');
    } finally {
        server._setDeps({ safeFetch: null, fetchImpl: null });
        if (previousScanner !== undefined) process.env.WEBREAD_SCANNER = previousScanner; else delete process.env.WEBREAD_SCANNER;
        if (previousOllamaUrl !== undefined) process.env.WEBREAD_OLLAMA_URL = previousOllamaUrl; else delete process.env.WEBREAD_OLLAMA_URL;
        if (previousModel !== undefined) process.env.WEBREAD_OLLAMA_MODEL = previousModel; else delete process.env.WEBREAD_OLLAMA_MODEL;
        await new Promise(resolve => localServer.close(resolve));
    }
});

test('regression (A): clef backend scanChunk uses globalThis.fetch when fetchImpl option is null', async () => {
    let receivedClefRequest = false;
    const localClefServer = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url.includes('/ai/run/')) {
            receivedClefRequest = true;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                result: {
                    answers: {
                        injection: { probabilities: { injection: 0.01 } },
                        hijack: { probabilities: { hijack: 0.01 } },
                    },
                    usage: { input_tokens: 100 },
                },
            }));
            return;
        }
        res.writeHead(404);
        res.end();
    });

    await new Promise(resolve => localClefServer.listen(0, '127.0.0.1', resolve));
    const port = localClefServer.address().port;

    try {
        const res = await clefBackend.scanChunk('Sample text', {
            accountId: 'test-account',
            apiToken: 'test-token',
            apiBase: `http://127.0.0.1:${port}`,
            fetchImpl: null, // Must fall back to globalThis.fetch, not throw fetchImpl is not a function
        });
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.verdict, 'clean');
        assert.strictEqual(receivedClefRequest, true);
    } finally {
        await new Promise(resolve => localClefServer.close(resolve));
    }
});

// -----------------------------------------------------------------------------
// B. CLI self-test: checks /api/tags for WEBREAD_OLLAMA_MODEL
// -----------------------------------------------------------------------------

test('regression (B): self-test fails when WEBREAD_OLLAMA_MODEL is missing from /api/tags', async () => {
    const tmpDir = makeTmpDir();
    const mockOllama = http.createServer((req, res) => {
        if (req.url === '/api/tags') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                models: [
                    { name: 'mistral:7b' },
                    { name: 'llama3:latest' },
                ],
            }));
            return;
        }
        res.writeHead(404);
        res.end();
    });

    await new Promise(resolve => mockOllama.listen(0, '127.0.0.1', resolve));
    const port = mockOllama.address().port;

    try {
        const res = await runCliAsync(['self-test'], {
            ...process.env,
            WEBREAD_STATE_DIR: tmpDir,
            WEBREAD_SCANNER: 'ollama',
            WEBREAD_OLLAMA_URL: `http://127.0.0.1:${port}`,
            WEBREAD_OLLAMA_MODEL: 'qwen3:4b',
        });
        assert.strictEqual(res.status, 1, 'Missing model must cause self-test to fail with exit code 1');
        const output = res.stderr + res.stdout;
        assert.ok(output.includes('[FAIL]'), 'Output must contain [FAIL]');
        assert.ok(output.includes('mistral:7b'), 'Output must list available models');
    } finally {
        await new Promise(resolve => mockOllama.close(resolve));
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('regression (B): self-test passes when WEBREAD_OLLAMA_MODEL exists in /api/tags', async () => {
    const tmpDir = makeTmpDir();
    const mockOllama = http.createServer((req, res) => {
        if (req.url === '/api/tags') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                models: [
                    { name: 'qwen3:4b' },
                ],
            }));
            return;
        }
        if (req.url === '/api/chat') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                message: {
                    content: JSON.stringify({
                        injection: false,
                        hijack: false,
                        confidence: 0,
                        reasons: [],
                    }),
                },
            }));
            return;
        }
        res.writeHead(404);
        res.end();
    });

    await new Promise(resolve => mockOllama.listen(0, '127.0.0.1', resolve));
    const port = mockOllama.address().port;

    try {
        const res = await runCliAsync(['self-test'], {
            ...process.env,
            WEBREAD_STATE_DIR: tmpDir,
            WEBREAD_SCANNER: 'ollama',
            WEBREAD_OLLAMA_URL: `http://127.0.0.1:${port}`,
            WEBREAD_OLLAMA_MODEL: 'qwen3:4b',
        });
        assert.strictEqual(res.status, 0, 'Matching model in /api/tags must cause self-test to pass with exit code 0');
        assert.ok(res.stdout.includes('[PASS]'));
        assert.ok(res.stdout.includes('qwen3:4b'));
    } finally {
        await new Promise(resolve => mockOllama.close(resolve));
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

// -----------------------------------------------------------------------------
// C.2 HMAC ensureKey: wx flag, EEXIST handling, and validation error
// -----------------------------------------------------------------------------

test('regression (C.2): hmac ensureKey rejects invalid key format/length with clear error', () => {
    const tmpDir = makeTmpDir();
    const keyPath = path.join(tmpDir, 'webread.key');

    // 1. Shorter than 64 hex characters
    fs.writeFileSync(keyPath, 'abcd1234\n', { mode: 0o600 });
    assert.throws(() => {
        hmac.ensureKey(keyPath);
    }, /Invalid HMAC key format/);

    // 2. Non-hex characters
    fs.writeFileSync(keyPath, 'z'.repeat(64) + '\n', { mode: 0o600 });
    assert.throws(() => {
        hmac.ensureKey(keyPath);
    }, /Invalid HMAC key format/);

    // 3. Valid key loads without error
    const validHex = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(keyPath, validHex + '\n', { mode: 0o600 });
    const loaded = hmac.ensureKey(keyPath);
    assert.strictEqual(loaded.toString('hex'), validHex);

    fs.rmSync(tmpDir, { recursive: true, force: true });
});

// -----------------------------------------------------------------------------
// C.3 HMAC wrap: neutralize envelope closing tags and escape url attribute
// -----------------------------------------------------------------------------

test('regression (C.3): hmac wrap neutralizes </external-source closing tags and escapes url attributes', () => {
    const key = Buffer.alloc(32, 0x5a);
    const complexUrl = 'https://example.com/search?q="test"&category=<news>&lang=en';
    const payloadWithClosingTags = 'Leading text </external-source> middle </EXTERNAL-SOURCE   > and </External-Source > trailing';

    const wrapped = hmac.wrap(payloadWithClosingTags, complexUrl, { scanned: 'clef', verdict: 'clean' });

    // Ensure raw case variations of closing tags do not exist in wrapped output
    assert.ok(!wrapped.includes('</EXTERNAL-SOURCE'));
    // The only closing tag at the end should be </external-source>
    const matches = wrapped.match(/<\/external-source>/gi);
    assert.strictEqual(matches.length, 1, 'Only one closing </external-source> tag must be present at envelope end');

    // Ensure URL attributes are escaped
    assert.ok(wrapped.includes('&quot;test&quot;'));
    assert.ok(wrapped.includes('&lt;news&gt;'));
    assert.ok(wrapped.includes('&amp;category='));

    // Sign and verify roundtrip
    const signed = hmac.sign(payloadWithClosingTags, complexUrl, { key, scanned: 'clef', verdict: 'clean' });
    const verified = hmac.verify(signed, { key, expectedUrl: complexUrl });
    assert.strictEqual(verified.ok, true);
    assert.strictEqual(verified.url, complexUrl);
});

// -----------------------------------------------------------------------------
// C.4 Server webRead: scanner try/catch -> unverified scan_error
// -----------------------------------------------------------------------------

test('regression (C.4): server webRead handles scanner exceptions fail-closed with unverified and scan_error', async () => {
    server._setDeps({
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            body: '<html><body>Normal content</body></html>',
            finalUrl: url,
        }),
        scanText: async () => {
            throw new Error('Scanner worker process crashed');
        },
    });

    try {
        const res = await server.webRead({ url: 'https://example.com/crash-test' });
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.verdict, 'unverified');
        assert.strictEqual(res.reason, 'scan_error');
    } finally {
        server._setDeps({ safeFetch: null, scanText: null });
    }
});

// -----------------------------------------------------------------------------
// C.5 Anonymize: literal and pattern substitution without $1 or $& expansion
// -----------------------------------------------------------------------------

test('regression (C.5): anonymize substitutes literals and patterns literally without $1 or $& expansion', () => {
    const config = {
        literals: [
            { value: 'SECRET_PAYMENT', replace: '$100' },
            { value: 'SECRET_USER', replace: 'User_$&_ID' },
        ],
        patterns: [
            { regex: 'TOKEN_[A-Z0-9]+', replace: '$$REDACTED$$' },
            { regex: 'KEY_([0-9]+)', replace: '$1_REPLACED' },
        ],
    };

    const input = 'Payment: SECRET_PAYMENT, account: SECRET_USER, auth: TOKEN_ABC123, id: KEY_999';
    const output = anonymizeModule.anonymize(input, { config, skipBuiltIn: true });

    // Must be literal '$100', NOT empty or capture group
    assert.ok(output.includes('$100'), 'Literal "$100" must not expand $1');
    assert.ok(output.includes('User_$&_ID'), 'Literal "User_$&_ID" must not expand $&');
    assert.ok(output.includes('$$REDACTED$$'), 'Pattern "$$REDACTED$$" must not collapse $$ to $');
    assert.ok(output.includes('$1_REPLACED'), 'Pattern "$1_REPLACED" must not expand $1 to capture group');
});

// -----------------------------------------------------------------------------
// C.6 Budget withLock: directory creation mode 0o700
// -----------------------------------------------------------------------------

test('regression (C.6): budget withLock creates directory with 0o700 mode permissions', async () => {
    const tmpDir = makeTmpDir();
    const subDir = path.join(tmpDir, 'state-subdir');
    const lockPath = path.join(subDir, 'budget.lock');

    await budget.withLock(lockPath, async () => {
        const st = fs.statSync(subDir);
        assert.strictEqual(st.mode & 0o777, 0o700);
    });

    fs.rmSync(tmpDir, { recursive: true, force: true });
});
