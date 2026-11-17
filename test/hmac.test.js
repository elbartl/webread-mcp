'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const hmac = require('../src/hmac.js');

function createTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-hmac-test-'));
}

test('hmac: ensureKey creates 256-bit key with 0600 permissions', () => {
    const dir = createTmpDir();
    const keyPath = path.join(dir, 'test.key');

    const key = hmac.ensureKey(keyPath);
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);

    const stat = fs.statSync(keyPath);
    assert.equal(stat.mode & 0o777, 0o600);

    // Reading again loads the exact same key
    const reloaded = hmac.ensureKey(keyPath);
    assert.deepEqual(reloaded, key);
});

test('hmac: wrap creates external-source envelope with correct attributes', () => {
    const wrapped = hmac.wrap('Sample web page text', 'https://example.com/page', {
        scanned: 'clef',
        verdict: 'clean',
    });

    assert.ok(wrapped.startsWith('<external-source url="https://example.com/page" scanned="clef" verdict="clean" sha="'));
    assert.ok(wrapped.includes('Sample web page text'));
    assert.ok(wrapped.endsWith('</external-source>'));
});

test('hmac: sign and verify roundtrip succeeds for valid content', () => {
    const key = Buffer.alloc(32, 0x42);
    const text = 'Clean informational text';
    const url = 'https://example.com/clean';

    const stamped = hmac.sign(text, url, { key, scanned: 'clef', verdict: 'clean' });
    assert.ok(stamped.includes('<!-- webread:ok:'));

    const res = hmac.verify(stamped, { key, expectedUrl: url });
    assert.equal(res.ok, true);
    assert.equal(res.url, url);
    assert.equal(res.scanned, 'clef');
    assert.equal(res.verdict, 'clean');
    assert.equal(res.text, text);
});

test('hmac: verify rejects tampered body content (sha_mismatch or bad_hmac)', () => {
    const key = Buffer.alloc(32, 0x42);
    const text = 'Original text';
    const url = 'https://example.com';

    const stamped = hmac.sign(text, url, { key });
    // Modify body text inside the signed envelope
    const tampered = stamped.replace('Original text', 'Manipulated malicious text');

    const res = hmac.verify(tampered, { key });
    assert.equal(res.ok, false);
    assert.ok(res.reason === 'bad_hmac' || res.reason === 'sha_mismatch');
});

test('hmac: verify rejects tampered HMAC stamp', () => {
    const key = Buffer.alloc(32, 0x42);
    const text = 'Original text';
    const url = 'https://example.com';

    const stamped = hmac.sign(text, url, { key });
    const tampered = stamped.replace(/([0-9a-fA-F]{4}) -->$/, '0000 -->');

    const res = hmac.verify(tampered, { key });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'bad_hmac');
});

test('hmac: verify rejects mismatched expectedUrl', () => {
    const key = Buffer.alloc(32, 0x42);
    const text = 'Original text';
    const url = 'https://example.com/original';

    const stamped = hmac.sign(text, url, { key });
    const res = hmac.verify(stamped, { key, expectedUrl: 'https://example.com/different' });

    assert.equal(res.ok, false);
    assert.equal(res.reason, 'url_mismatch');
});

test('hmac: verify rejects missing stamp or missing key', () => {
    const text = '<external-source url="https://example.com" sha="1234">text</external-source>';
    assert.equal(hmac.verify(text, { key: Buffer.alloc(32, 1) }).ok, false);
    assert.equal(hmac.verify(text, { key: null }).ok, false);
});
