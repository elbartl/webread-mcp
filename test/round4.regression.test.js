'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');

const config = require('../src/config.js');
const ollama = require('../src/backends/ollama.js');
const extract = require('../src/extract.js');

const CLI_PATH = path.join(__dirname, '..', 'bin', 'webread-mcp.js');

function runCliAsync(args, env = {}) {
    return new Promise((resolve) => {
        const proc = spawn(process.execPath, [CLI_PATH, ...args], {
            env: { ...process.env, ...env },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        proc.stdout.on('data', (d) => { stdout += d; });
        proc.stderr.on('data', (d) => { stderr += d; });
        proc.on('close', (status) => {
            resolve({ status, stdout, stderr });
        });
    });
}

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-r4-test-'));
}

// -----------------------------------------------------------------------------
// 1. WEBREAD_SCAN_TIMEOUT_MS (Separate scanner timeout and validation)
// -----------------------------------------------------------------------------

test('round 4 (1): validateScanTimeoutMs returns defaults when unset', () => {
    assert.strictEqual(config.validateScanTimeoutMs(undefined, 'clef'), 20000);
    assert.strictEqual(config.validateScanTimeoutMs(null, 'clef'), 20000);
    assert.strictEqual(config.validateScanTimeoutMs('', 'clef'), 20000);

    assert.strictEqual(config.validateScanTimeoutMs(undefined, 'ollama'), 90000);
    assert.strictEqual(config.validateScanTimeoutMs(null, 'ollama'), 90000);
    assert.strictEqual(config.validateScanTimeoutMs('', 'ollama'), 90000);
});

test('round 4 (1): validateScanTimeoutMs accepts positive numbers', () => {
    assert.strictEqual(config.validateScanTimeoutMs(5000, 'clef'), 5000);
    assert.strictEqual(config.validateScanTimeoutMs('45000', 'ollama'), 45000);
    assert.strictEqual(config.validateScanTimeoutMs(100.5, 'clef'), 100.5);
});

test('round 4 (1): validateScanTimeoutMs throws on non-positive or non-finite values', () => {
    assert.throws(() => config.validateScanTimeoutMs(0, 'clef'), /Must be a positive number/);
    assert.throws(() => config.validateScanTimeoutMs(-1000, 'clef'), /Must be a positive number/);
    assert.throws(() => config.validateScanTimeoutMs('-50', 'ollama'), /Must be a positive number/);
    assert.throws(() => config.validateScanTimeoutMs('invalid', 'clef'), /Must be a positive number/);
    assert.throws(() => config.validateScanTimeoutMs(NaN, 'clef'), /Must be a positive number/);
    assert.throws(() => config.validateScanTimeoutMs(Infinity, 'clef'), /Must be a positive number/);
});

test('round 4 (1): getConfig correctly distinguishes timeoutMs and scanTimeoutMs', () => {
    const cfg = config.getConfig({
        scanner: 'ollama',
        timeoutMs: 12000,
        scanTimeoutMs: 85000,
    });
    assert.strictEqual(cfg.timeoutMs, 12000, 'Page fetch timeout');
    assert.strictEqual(cfg.scanTimeoutMs, 85000, 'Scanner timeout');
});

test('round 4 (1): CLI fails with exit code 1 on invalid WEBREAD_SCAN_TIMEOUT_MS', async () => {
    const tmpDir = makeTmpDir();
    try {
        const res = await runCliAsync(['self-test'], {
            WEBREAD_STATE_DIR: tmpDir,
            WEBREAD_SCANNER: 'none',
            WEBREAD_SCAN_TIMEOUT_MS: '-500',
        });
        assert.strictEqual(res.status, 1);
        assert.ok(res.stderr.includes('Invalid WEBREAD_SCAN_TIMEOUT_MS'));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

// -----------------------------------------------------------------------------
// 2. Ollama backend: num_predict: 128 and concise reason in SYSTEM_PROMPT
// -----------------------------------------------------------------------------

test('round 4 (2): ollama scanChunk includes num_predict: 128 and temperature: 0 in request body', async () => {
    let capturedBody = null;
    const mockFetch = async (url, opts) => {
        capturedBody = JSON.parse(opts.body);
        return {
            ok: true,
            status: 200,
            json: async () => ({
                message: {
                    content: JSON.stringify({
                        injection: false,
                        hijack: false,
                        confidence: 0,
                        reasons: [],
                    }),
                },
            }),
        };
    };

    const res = await ollama.scanChunk('Sample text', {
        fetchImpl: mockFetch,
    });

    assert.strictEqual(res.ok, true);
    assert.strictEqual(res.verdict, 'clean');
    assert.ok(capturedBody != null);
    assert.strictEqual(capturedBody.options.temperature, 0);
    assert.strictEqual(capturedBody.options.num_predict, 128);
});

test('round 4 (2): ollama SYSTEM_PROMPT instructs concise single-sentence reasons', () => {
    assert.ok(ollama.SYSTEM_PROMPT.includes('reasons'));
    assert.ok(/at most ONE short sentence/i.test(ollama.SYSTEM_PROMPT));
});

// -----------------------------------------------------------------------------
// 3. self-test for Ollama: test probe scan and timeout handling
// -----------------------------------------------------------------------------

test('round 4 (3): self-test logs latency in ms on successful probe scan', async () => {
    const tmpDir = makeTmpDir();
    const mockOllama = http.createServer((req, res) => {
        if (req.url === '/api/tags') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                models: [{ name: 'qwen3:4b' }],
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
                        confidence: 0.0,
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
            WEBREAD_STATE_DIR: tmpDir,
            WEBREAD_SCANNER: 'ollama',
            WEBREAD_OLLAMA_URL: `http://127.0.0.1:${port}`,
            WEBREAD_OLLAMA_MODEL: 'qwen3:4b',
            WEBREAD_SCAN_TIMEOUT_MS: '10000',
        });
        assert.strictEqual(res.status, 0);
        assert.ok(res.stdout.includes('[PASS] Ollama test scan completed in'));
        assert.ok(/completed in \d+ms/.test(res.stdout));
    } finally {
        await new Promise(resolve => mockOllama.close(resolve));
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('round 4 (3): self-test issues [WARN] and does NOT fail if probe scan exceeds timeout', async () => {
    const tmpDir = makeTmpDir();
    const mockOllama = http.createServer((req, res) => {
        if (req.url === '/api/tags') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                models: [{ name: 'qwen3:4b' }],
            }));
            return;
        }
        if (req.url === '/api/chat') {
            // Delay longer than WEBREAD_SCAN_TIMEOUT_MS (e.g. 150ms when timeout is 50ms)
            setTimeout(() => {
                try {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        message: {
                            content: JSON.stringify({
                                injection: false,
                                hijack: false,
                                confidence: 0.0,
                                reasons: [],
                            }),
                        },
                    }));
                } catch (_) {}
            }, 150);
            return;
        }
        res.writeHead(404);
        res.end();
    });

    await new Promise(resolve => mockOllama.listen(0, '127.0.0.1', resolve));
    const port = mockOllama.address().port;

    try {
        const res = await runCliAsync(['self-test'], {
            WEBREAD_STATE_DIR: tmpDir,
            WEBREAD_SCANNER: 'ollama',
            WEBREAD_OLLAMA_URL: `http://127.0.0.1:${port}`,
            WEBREAD_OLLAMA_MODEL: 'qwen3:4b',
            WEBREAD_SCAN_TIMEOUT_MS: '50', // tiny timeout triggers probe timeout
        });
        assert.strictEqual(res.status, 0, 'Exceeding scan timeout in probe must produce WARN, not FAIL (exit 0)');
        const combined = res.stdout + res.stderr;
        assert.ok(combined.includes('[WARN]'));
        assert.ok(combined.includes('exceeded'));
        assert.ok(combined.includes('WEBREAD_SCAN_TIMEOUT_MS'));
        assert.ok(res.stdout.includes('Self-test PASSED successfully'));
    } finally {
        await new Promise(resolve => mockOllama.close(resolve));
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

// -----------------------------------------------------------------------------
// 4. extract.js: <!doctype ...> and <?xml ...?> stripping
// -----------------------------------------------------------------------------

test('round 4 (4): extract strips <!doctype ...> in various cases and formats', () => {
    const cases = [
        '<!doctype html><html><body><p>Hello world</p></body></html>',
        '<!DOCTYPE HTML><html><body><p>Hello world</p></body></html>',
        '<!DocType html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd"><html><body><p>Hello world</p></body></html>',
        '<!DOCTYPE html SYSTEM "about:legacy-compat"><html><body><p>Hello world</p></body></html>',
        '<!doctype><html><body><p>Hello world</p></body></html>',
        '<!DOCTYPE html [\n<!ENTITY foo "bar">\n]><html><body><p>Hello world</p></body></html>',
    ];

    for (const html of cases) {
        const res = extract.htmlToText(html);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.text, 'Hello world');
        assert.ok(!res.text.toLowerCase().includes('doctype'), `Extracted text must not contain doctype: "${res.text}"`);
        assert.ok(!res.text.includes(']>'), `Extracted text must not contain ]: "${res.text}"`);
        assert.ok(!res.text.includes('ENTITY'), `Extracted text must not contain ENTITY: "${res.text}"`);
    }
});

test('round 4 (4): extract strips <?xml ...?> and processing instructions', () => {
    const cases = [
        '<?xml version="1.0" encoding="utf-8"?><html><body><p>Hello XML</p></body></html>',
        '<?XML version="1.0"?><html><body><p>Hello XML</p></body></html>',
        '<?xml-stylesheet type="text/xsl" href="style.xsl"?><html><body><p>Hello XML</p></body></html>',
        '<?php echo "evil instruction"; ?><html><body><p>Hello XML</p></body></html>',
        '<?xml version="1.0"><html><body><p>Hello XML</p></body></html>',
    ];

    for (const html of cases) {
        const res = extract.htmlToText(html);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.text, 'Hello XML');
        assert.ok(!res.text.includes('<?xml'), `Extracted text must not contain <?xml: "${res.text}"`);
        assert.ok(!res.text.includes('<?php'), `Extracted text must not contain <?php: "${res.text}"`);
    }
});

test('round 4 (4): extract strips both <!DOCTYPE> and <?xml ...?> when combined', () => {
    const html = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test Page</title></head>
<body>
<h1>Heading</h1>
<p>Article paragraph text.</p>
</body>
</html>`;

    const res = extract.extractContent(html, 'application/xhtml+xml');
    assert.strictEqual(res.ok, true);
    assert.ok(!res.text.toLowerCase().includes('doctype'));
    assert.ok(!res.text.includes('<?xml'));
    assert.ok(res.text.includes('Heading'));
    assert.ok(res.text.includes('Article paragraph text.'));
});
