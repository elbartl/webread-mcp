'use strict';
/**
 * test/none.test.js
 * Comprehensive tests for WEBREAD_SCANNER=none backend (pass-through with explicit warnings).
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const noneBackend = require('../src/backends/none.js');
const { scanText } = require('../src/scan.js');
const { handle, _setDeps } = require('../src/server.js');
const { verify } = require('../src/hmac.js');

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-none-test-'));
}

test('none backend: direct scan returns clean verdict, scanned=none and security warning', async () => {
    const res = await noneBackend.scan(['Chunk 1', 'Chunk 2']);
    assert.strictEqual(res.ok, true);
    assert.strictEqual(res.verdict, 'clean');
    assert.strictEqual(res.backend, 'none');
    assert.strictEqual(res.scans, 0);
    assert.ok(res.warning.includes('SECURITY WARNING'));
    assert.ok(res.warning.includes('NOT scanned'));
    assert.ok(res.warning.includes('WEBREAD_SCANNER=none'));
});

test('scanText: none backend returns clean, scanned=none, and preserves security warning', async () => {
    const res = await scanText('Normal web content', { scanner: 'none' });
    assert.strictEqual(res.ok, true);
    assert.strictEqual(res.verdict, 'clean');
    assert.strictEqual(res.scanned, 'none');
    assert.strictEqual(res.backend, 'none');
    assert.strictEqual(res.scans, 0);
    assert.ok(res.warning.includes('WEBREAD_SCANNER=none'));
});

test('server: web_read with scanner=none produces signed envelope with scanned=none and warning in body', async () => {
    const tmpDir = makeTmpDir();
    try {
        _setDeps({
            stateDir: tmpDir,
            scanner: 'none',
            safeFetch: async (url) => ({
                ok: true,
                status: 200,
                contentType: 'text/html',
                finalUrl: url,
                body: Buffer.from('<html><body><h1>Unscanned Page</h1><p>Content text</p></body></html>'),
            }),
        });

        let resp = null;
        await handle({
            jsonrpc: '2.0',
            id: 50,
            method: 'tools/call',
            params: { name: 'web_read', arguments: { url: 'https://example.com/unscanned' } },
        }, (out) => { resp = out; });

        assert.strictEqual(resp.result.isError, false);
        assert.strictEqual(resp.result.verdict, 'clean');
        assert.strictEqual(resp.result.scanned, 'none');

        const json = JSON.parse(resp.result.content[0].text);
        assert.strictEqual(json.ok, true);
        assert.strictEqual(json.verdict, 'clean');
        assert.strictEqual(json.scanned, 'none');
        assert.ok(json.text.includes('SECURITY WARNING'));
        assert.ok(json.text.includes('WEBREAD_SCANNER=none'));
        assert.ok(json.text.includes('<external-source url="https://example.com/unscanned" scanned="none" verdict="clean"'));
        assert.ok(json.text.includes('<!-- webread:ok:'));

        // Verify HMAC integrity
        const verified = verify(json.text, { stateDir: tmpDir });
        assert.strictEqual(verified.ok, true);
        assert.strictEqual(verified.scanned, 'none');
        assert.strictEqual(verified.verdict, 'clean');
    } finally {
        _setDeps({ safeFetch: null, stateDir: null, scanner: null });
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});
