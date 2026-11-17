'use strict';
/**
 * test/server.edge.test.js
 * Adversarial and edge-case test suite for MCP server stdio interface.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { handle, webRead, sanitizeUrl, _setDeps } = require('../src/server.js');

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-server-edge-'));
}

test('Server edge: handle(null) does not throw unhandled TypeError', async () => {
    let caughtError = null;
    try {
        await handle(null, () => {});
    } catch (e) {
        caughtError = e;
    }
    assert.strictEqual(caughtError, null, 'handle(null) must not throw unhandled exception killing process');
});

test('Server edge: token leak in URL hash fragment (#token=...) and hyphenated parameters', () => {
    // Hash fragment leak: #access_token=sk-...
    const urlWithHashToken = 'https://example.com/oauth/callback#access_token=sk-123456789012345678901234&token_type=bearer';
    const cleanedHash = sanitizeUrl(urlWithHashToken);
    assert.ok(!cleanedHash.includes('sk-1234567890'), 'Fragment #access_token with sk- token must not remain in URL');

    // Hyphenated parameter: api-key=...
    const urlWithHyphen = 'https://api.example.com/data?api-key=secret123456';
    const cleanedHyphen = sanitizeUrl(urlWithHyphen);
    assert.ok(!cleanedHyphen.includes('api-key'), 'Parameter api-key must not remain in URL');
});

test('Server edge: query string filter removes standard tokens, secrets, and prefixes sk-, ghp-, AKIA', () => {
    const dirtyUrl = 'https://api.example.com/v1/search?q=test&token=secretToken1234567890&auth=pass123&sk=sk-abc12345678901234567890&ghp=ghp_abcdefghijklmnop123456&aws=AKIAIOSFODNN7EXAMPLE';
    const cleaned = sanitizeUrl(dirtyUrl);
    const u = new URL(cleaned);

    assert.strictEqual(u.searchParams.get('q'), 'test', 'Non-sensitive query parameter q must be preserved');
    assert.strictEqual(u.searchParams.get('token'), null);
    assert.strictEqual(u.searchParams.get('auth'), null);
    assert.strictEqual(u.searchParams.get('sk'), null);
    assert.strictEqual(u.searchParams.get('ghp'), null);
    assert.strictEqual(u.searchParams.get('aws'), null);
});

test('Server edge: MCP protocol validation (missing fields, unknown tool, unsupported method)', async () => {
    const responses = [];
    const send = (msg) => responses.push(msg);

    // 1. Unknown method
    await handle({ id: 1, method: 'unknown/method', params: {} }, send);
    assert.strictEqual(responses[0].error.code, -32601);

    // 2. Unknown tool in tools/call
    await handle({ id: 2, method: 'tools/call', params: { name: 'unknown_tool', arguments: {} } }, send);
    assert.strictEqual(responses[1].error.code, -32602);

    // 3. Missing url argument in tools/call for web_read
    await handle({ id: 3, method: 'tools/call', params: { name: 'web_read', arguments: {} } }, send);
    assert.strictEqual(responses[2].result.isError, true);
    assert.ok(responses[2].result.content[0].text.includes('bad_input'));
});

test('Server edge: fail-closed assurance - zero page content in rejection and error messages', async () => {
    const tmpDir = makeTmpDir();
    try {
        const secretPageContent = 'CONFIDENTIAL_CORPORATE_DATA_MUST_NOT_LEAK_ON_ERROR';

        _setDeps({
            stateDir: tmpDir,
            safeFetch: async () => ({
                ok: true,
                status: 200,
                contentType: 'text/plain',
                body: Buffer.from(secretPageContent),
            }),
            validateUrl: () => ({ ok: true, url: 'https://example.com/test' }),
            scanText: async () => ({ ok: false, verdict: 'quarantine', reason: 'prompt_injection_flagged', scans: 1 }),
        });

        const responses = [];
        await handle({
            id: 10,
            method: 'tools/call',
            params: { name: 'web_read', arguments: { url: 'https://example.com/test' } },
        }, (msg) => responses.push(msg));

        assert.strictEqual(responses[0].result.isError, true);
        const errorText = responses[0].result.content[0].text;

        // Content text must never include confidential page body
        assert.ok(!errorText.includes(secretPageContent), 'Page body leaked into error message');
        assert.ok(errorText.includes('prompt_injection_flagged'));
    } finally {
        _setDeps({ safeFetch: null, validateUrl: null, scanText: null, stateDir: null });
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('Server edge: CRITICAL SECURITY - _allowPrivateForTesting unreachable from external MCP tools/call or via ENV', async () => {
    // 1. tools/call with 127.0.0.1 and variations of _allowPrivateForTesting
    const testArgs = [
        { url: 'http://127.0.0.1:8080/', _allowPrivateForTesting: true },
        { url: 'http://localhost:8080/', _allowPrivateForTesting: true },
        { url: 'http://127.0.0.1:8080/', allowPrivateForTesting: true },
        { url: 'http://127.0.0.1:8080/', options: { _allowPrivateForTesting: true } },
        { url: 'http://[::1]:8080/', _allowPrivateForTesting: true },
    ];

    for (let i = 0; i < testArgs.length; i++) {
        let resp = null;
        await handle({
            jsonrpc: '2.0',
            id: 100 + i,
            method: 'tools/call',
            params: { name: 'web_read', arguments: testArgs[i] },
        }, (out) => { resp = out; });

        assert.strictEqual(resp.result.isError, true, `Attempt ${i} must be rejected`);
        const jsonText = resp.result.content[0].text;
        assert.ok(
            jsonText.includes('private_ip') || jsonText.includes('localhost_not_allowed'),
            `Expected private_ip or localhost_not_allowed, got: ${jsonText}`
        );
    }

    // 2. Attempt to enable via environment variable
    const oldEnv = process.env.ALLOW_PRIVATE_FOR_TESTING;
    try {
        process.env.ALLOW_PRIVATE_FOR_TESTING = '1';
        let resp = null;
        await handle({
            jsonrpc: '2.0',
            id: 200,
            method: 'tools/call',
            params: { name: 'web_read', arguments: { url: 'http://127.0.0.1:8080/' } },
        }, (out) => { resp = out; });

        assert.strictEqual(resp.result.isError, true);
        const jsonText = resp.result.content[0].text;
        assert.ok(jsonText.includes('private_ip') || jsonText.includes('localhost_not_allowed'));
    } finally {
        if (oldEnv === undefined) delete process.env.ALLOW_PRIVATE_FOR_TESTING;
        else process.env.ALLOW_PRIVATE_FOR_TESTING = oldEnv;
    }
});

test('Server edge: fail-closed HMAC signing (signer error and missing key -> sign_failed, zero content)', async () => {
    const tmpDir = makeTmpDir();
    try {
        const secretText = 'Confidential page content must not leak on signature failure!';

        // A. Signer throws exception
        _setDeps({
            stateDir: tmpDir,
            safeFetch: async () => ({ ok: true, status: 200, contentType: 'text/plain', body: Buffer.from(secretText) }),
            validateUrl: () => ({ ok: true, url: 'http://example.com/test' }),
            extractContent: () => ({ ok: true, text: secretText, length: secretText.length, hiddenCount: 0 }),
            scanText: async () => ({ ok: true, verdict: 'clean', scans: 1, chunks: 1 }),
            sign: () => { throw new Error('Cryptographic HSM error'); },
        });

        let respA = null;
        await handle({
            jsonrpc: '2.0',
            id: 301,
            method: 'tools/call',
            params: { name: 'web_read', arguments: { url: 'http://example.com/test' } },
        }, (out) => { respA = out; });

        assert.strictEqual(respA.result.isError, true);
        assert.ok(respA.result.content[0].text.includes('sign_failed'));
        assert.strictEqual(JSON.stringify(respA).includes(secretText), false, 'Page body must not leak when signer throws');

        // B. Key is explicitly null / missing
        _setDeps({
            stateDir: tmpDir,
            safeFetch: async () => ({ ok: true, status: 200, contentType: 'text/plain', body: Buffer.from(secretText) }),
            validateUrl: () => ({ ok: true, url: 'http://example.com/test' }),
            extractContent: () => ({ ok: true, text: secretText, length: secretText.length, hiddenCount: 0 }),
            scanText: async () => ({ ok: true, verdict: 'clean', scans: 1, chunks: 1 }),
            sign: null,
            key: null,
        });

        let respB = null;
        await handle({
            jsonrpc: '2.0',
            id: 302,
            method: 'tools/call',
            params: { name: 'web_read', arguments: { url: 'http://example.com/test' } },
        }, (out) => { respB = out; });

        assert.strictEqual(respB.result.isError, true);
        assert.ok(respB.result.content[0].text.includes('sign_failed'));
        assert.strictEqual(JSON.stringify(respB).includes(secretText), false, 'Page body must not leak when key is missing');
    } finally {
        _setDeps({ safeFetch: null, validateUrl: null, extractContent: null, scanText: null, sign: null, key: undefined, stateDir: null });
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});
