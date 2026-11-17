'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const server = require('../src/server.js');
const { sanitizeUrl, stripQuery, handle, _setDeps } = server;

function createTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-server-test-'));
}

async function rpc(method, params, id = 1) {
    let out;
    await handle({ jsonrpc: '2.0', id, method, params }, (m) => { out = m; });
    return out;
}

async function call(name, args = {}) {
    const r = await rpc('tools/call', { name, arguments: args });
    const res = r.result;
    const text = res && res.content && res.content[0] && res.content[0].text;
    let json = null;
    if (res && text) {
        try { json = JSON.parse(text); } catch (_) {}
    }
    return { isError: (res && res.isError) || false, text, json, raw: r };
}

test('server: initialize, ping, and tools/list adhere to MCP specification', async () => {
    const init = await rpc('initialize', { protocolVersion: '2024-11-05' });
    assert.equal(init.result.serverInfo.name, 'webread-mcp');
    assert.equal(init.result.serverInfo.version, '0.1.0');

    const ping = await rpc('ping');
    assert.deepEqual(ping.result, {});

    const list = await rpc('tools/list');
    assert.equal(list.result.tools.length, 1);
    assert.equal(list.result.tools[0].name, 'web_read');

    // Confirm that the legacy 'summary' parameter is removed
    const props = list.result.tools[0].inputSchema.properties;
    assert.ok(props.url);
    assert.ok(props.max_chars);
    assert.equal(props.summary, undefined);

    // Unknown tool
    const unknownTool = await rpc('tools/call', { name: 'non_existent', arguments: {} });
    assert.ok(unknownTool.error);
    assert.equal(unknownTool.error.code, -32602);

    // Unknown method
    const unknownMethod = await rpc('unknown_method', {});
    assert.ok(unknownMethod.error);
    assert.equal(unknownMethod.error.code, -32601);
});

test('server: sanitizeUrl strips credentials, sensitive keys, and hash fragments', () => {
    const raw = 'https://example.com/page?token=secret123&sk=sk-1234567890abcdef1234567890&apikey=key1&clean_param=normal#section1';
    const clean = sanitizeUrl(raw);
    const u = new URL(clean);

    assert.equal(u.searchParams.get('token'), null);
    assert.equal(u.searchParams.get('sk'), null);
    assert.equal(u.searchParams.get('apikey'), null);
    assert.equal(u.searchParams.get('clean_param'), 'normal');
    assert.equal(u.hash, '');

    assert.equal(stripQuery('https://example.com/path?foo=bar#section'), 'https://example.com/path');
});

test('server: web_read clean page returns wrapped content stamped with HMAC and scanned=clef', async () => {
    const tmpDir = createTmpDir();
    const testKey = crypto.randomBytes(32);

    _setDeps({
        stateDir: tmpDir,
        key: testKey,
        scanner: 'clef',
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            finalUrl: url,
            body: Buffer.from('<html><body><h1>Documentation</h1><p>Clean factual text.</p></body></html>'),
        }),
        scanText: async () => ({
            ok: true,
            verdict: 'clean',
            scanned: 'clef',
            scans: 1,
        }),
    });

    const res = await call('web_read', { url: 'https://example.com/docs' });
    assert.equal(res.isError, false);
    assert.ok(res.json);
    assert.equal(res.json.ok, true);
    assert.equal(res.json.verdict, 'clean');
    assert.equal(res.json.scanned, 'clef');
    assert.ok(res.json.text.includes('<external-source url="https://example.com/docs" scanned="clef" verdict="clean"'));
    assert.ok(res.json.text.includes('<!-- webread:ok:'));
});

test('server: web_read quarantine withholding malicious payload', async () => {
    const tmpDir = createTmpDir();
    const testKey = crypto.randomBytes(32);

    _setDeps({
        stateDir: tmpDir,
        key: testKey,
        scanner: 'clef',
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            finalUrl: url,
            body: Buffer.from('<html><body><p>Adversarial instructions</p></body></html>'),
        }),
        scanText: async () => ({
            ok: false,
            verdict: 'quarantine',
            reason: 'prompt_injection_detected',
            scanned: 'clef',
            scans: 1,
        }),
    });

    const res = await call('web_read', { url: 'https://example.com/attack' });
    assert.equal(res.isError, true);
    assert.ok(res.json);
    assert.equal(res.json.ok, false);
    assert.equal(res.json.verdict, 'quarantine');
    assert.equal(res.json.reason, 'prompt_injection_detected');
    assert.equal(res.json.scanned, 'clef');
    assert.equal(res.json.text, undefined); // Content withheld
});

test('server: web_read unverified on fetch failure or scanner error', async () => {
    const tmpDir = createTmpDir();
    _setDeps({
        stateDir: tmpDir,
        scanner: 'clef',
        safeFetch: async () => ({
            ok: false,
            reason: 'private_ip',
        }),
    });

    const res1 = await call('web_read', { url: 'http://127.0.0.1/' });
    assert.equal(res1.isError, true);
    assert.equal(res1.json.verdict, 'unverified');
    assert.equal(res1.json.reason, 'ssrf_private_ip');
    assert.equal(res1.json.scanned, 'clef');

    // Scanner timeout
    _setDeps({
        stateDir: tmpDir,
        scanner: 'ollama',
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            finalUrl: url,
            body: Buffer.from('Normal body'),
        }),
        scanText: async () => ({
            ok: false,
            verdict: 'unverified',
            reason: 'timeout',
            scanned: 'ollama',
            scans: 1,
        }),
    });

    const res2 = await call('web_read', { url: 'https://example.com/timeout' });
    assert.equal(res2.isError, true);
    assert.equal(res2.json.verdict, 'unverified');
    assert.equal(res2.json.reason, 'timeout');
    assert.equal(res2.json.scanned, 'ollama');
});

test('server: web_read none backend includes security warning in text', async () => {
    const tmpDir = createTmpDir();
    const testKey = crypto.randomBytes(32);

    _setDeps({
        stateDir: tmpDir,
        key: testKey,
        scanner: 'none',
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            finalUrl: url,
            body: Buffer.from('<html><body><p>Pass-through article</p></body></html>'),
        }),
        scanText: async () => ({
            ok: true,
            verdict: 'clean',
            scanned: 'none',
            scans: 0,
            warning: 'SECURITY WARNING: Unscanned content.',
        }),
    });

    const res = await call('web_read', { url: 'https://example.com/none' });
    assert.equal(res.isError, false);
    assert.equal(res.json.verdict, 'clean');
    assert.equal(res.json.scanned, 'none');
    assert.ok(res.json.text.includes('SECURITY WARNING'));
});

test('server: handle(null), hyphenated secret params, sign failure fail-closed, and CLI commands', async () => {
    // 1. handle(null) must not throw
    await handle(null, () => {});

    // 2. Hyphenated api-key and hash token stripped
    const cleaned = sanitizeUrl('https://api.example.com/data?api-key=sec123&q=ok#access_token=sk-123456789012345678901234');
    assert.ok(!cleaned.includes('api-key'));
    assert.ok(!cleaned.includes('sk-1234567890'));
    assert.ok(cleaned.includes('q=ok'));

    // 3. Signer failure returns unverified and never leaks content
    const tmpDir = createTmpDir();
    _setDeps({
        stateDir: tmpDir,
        scanner: 'clef',
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/plain',
            finalUrl: url,
            body: Buffer.from('CONFIDENTIAL_BODY_TEXT_DO_NOT_LEAK'),
        }),
        scanText: async () => ({
            ok: true,
            verdict: 'clean',
            scanned: 'clef',
            scans: 1,
        }),
        sign: () => {
            throw new Error('HSM signing error');
        },
    });

    const signFailRes = await call('web_read', { url: 'https://example.com/sign-fail' });
    assert.equal(signFailRes.isError, true);
    assert.equal(signFailRes.json.verdict, 'unverified');
    assert.equal(signFailRes.json.reason, 'sign_failed');
    assert.ok(!signFailRes.text.includes('CONFIDENTIAL_BODY_TEXT_DO_NOT_LEAK'));

    // 4. CLI commands (--version, self-test, anonymize-test, verify)
    const { execFileSync } = require('node:child_process');
    const binPath = path.join(__dirname, '..', 'bin', 'webread-mcp.js');

    const verOut = execFileSync(process.execPath, [binPath, '--version'], { encoding: 'utf8' }).trim();
    assert.equal(verOut, '0.1.0');

    const selfTestOut = execFileSync(process.execPath, [binPath, 'self-test'], {
        encoding: 'utf8',
        env: { ...process.env, WEBREAD_SCANNER: 'none', WEBREAD_STATE_DIR: tmpDir },
    });
    assert.ok(selfTestOut.includes('Self-test PASSED'));

    const sampleFile = path.join(tmpDir, 'sample.txt');
    fs.writeFileSync(sampleFile, 'Contact user@example.org at 10.0.0.9');
    const anonOut = execFileSync(process.execPath, [binPath, 'anonymize-test', sampleFile], {
        encoding: 'utf8',
        env: { ...process.env, WEBREAD_STATE_DIR: tmpDir },
    });
    assert.ok(anonOut.includes('[EMAIL]'));
    assert.ok(anonOut.includes('[IP_ADDRESS]'));

    const signedFile = path.join(tmpDir, 'signed.txt');
    const stamped = server.sign('Verified body', 'https://example.com/v', { stateDir: tmpDir });
    fs.writeFileSync(signedFile, stamped);
    const verifyOut = execFileSync(process.execPath, [binPath, 'verify', signedFile], {
        encoding: 'utf8',
        env: { ...process.env, WEBREAD_STATE_DIR: tmpDir },
    });
    assert.ok(verifyOut.includes('VALID'));
});

test('server: extraction failure or timeout returns unverified and never clean', async () => {
    const tmpDir = createTmpDir();
    _setDeps({
        stateDir: tmpDir,
        scanner: 'clef',
        safeFetch: async (url) => ({
            ok: true,
            status: 200,
            contentType: 'text/html',
            finalUrl: url,
            body: Buffer.from('<html><body>MALICIOUS_BODY</body></html>'),
        }),
        extractContent: () => ({
            ok: false,
            error: 'extraction_timeout',
            reason: 'extraction_timeout',
            length: 0,
            hiddenCount: 0,
        }),
    });

    const res = await call('web_read', { url: 'https://example.com/timeout' });
    assert.equal(res.isError, true);
    assert.equal(res.json.verdict, 'unverified');
    assert.equal(res.json.reason, 'extraction_timeout');
    assert.ok(!res.text.includes('MALICIOUS_BODY'));
});
