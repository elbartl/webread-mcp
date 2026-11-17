'use strict';
/**
 * test/scan.edge.test.js
 * Adversarial and edge-case test suite for scanner orchestration and cryptographic signing.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { scanText, splitChunks } = require('../src/scan.js');
const { wrap, sign, verify } = require('../src/hmac.js');

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-scan-edge-'));
}

test('Scan edge: chunk splitting and overlap guarantees', () => {
    // 1. Instruction length <= overlap (200 chars)
    const chunkSize = 3000;
    const overlap = 200;
    const prefix = 'A'.repeat(2950);
    const injection = 'INJECTION_COMMAND_UNDER_200_CHARS_X'.repeat(4); // ~140 chars
    assert.ok(injection.length <= overlap);

    const fullText = prefix + injection + 'B'.repeat(1000);
    const chunks = splitChunks(fullText, chunkSize, overlap);
    assert.strictEqual(chunks.length, 2);

    // Chunk 2 starts at 2800, so it contains the full injection from 2950 to 3090
    assert.ok(chunks[1].includes(injection), 'Chunk 2 must contain the complete instruction due to window overlap');
});

test('Scan edge: injection instruction longer than overlap window at chunk boundary', () => {
    // When injection payload is longer than overlap (e.g. 248 chars) and crosses chunk boundary
    const chunkSize = 3000;
    const overlap = 200;
    const prefix = 'A'.repeat(2780);
    const longInjection = 'SYSTEM_PROMPT_OVERRIDE_PAYLOAD_'.repeat(8); // 248 chars
    assert.ok(longInjection.length > overlap);

    const fullText = prefix + longInjection + 'B'.repeat(500);
    const chunks = splitChunks(fullText, chunkSize, overlap);

    const chunk0HasFull = chunks[0].includes(longInjection);
    const chunk1HasFull = chunks[1].includes(longInjection);
    assert.strictEqual(chunk0HasFull, false, 'Chunk 0 has truncated end of instruction');
    assert.strictEqual(chunk1HasFull, false, 'Chunk 1 has truncated start of instruction');
});

test('Scan edge: concurrency race on budget.json prevented via lockfile', async () => {
    const tmpDir = makeTmpDir();
    const budgetPath = path.join(tmpDir, 'budget.json');

    try {
        const slowClef = async () => {
            await new Promise(r => setTimeout(r, 40));
            return { verdict: 'clean', neurons: 10 };
        };

        // 5 parallel calls of 1 chunk each
        const tasks = [1, 2, 3, 4, 5].map(i => scanText('Staff report ' + i, {
            clefMock: slowClef,
            stateDir: tmpDir,
        }));

        await Promise.all(tasks);

        assert.ok(fs.existsSync(budgetPath), 'budget.json file must exist');
        const b = JSON.parse(fs.readFileSync(budgetPath, 'utf8'));

        assert.strictEqual(b.calls, 5, `Expected calls=5, recorded ${b.calls}`);
        assert.strictEqual(b.scans, 5, `Expected scans=5, recorded ${b.scans}`);
        assert.strictEqual(b.used, 50, `Expected used=50, recorded ${b.used}`);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('Scan edge: empty input and emergency stop (DISABLED)', async () => {
    const tmpDir = makeTmpDir();
    try {
        // 1. Empty input
        const resEmpty = await scanText('', { stateDir: tmpDir });
        assert.strictEqual(resEmpty.ok, true);
        assert.strictEqual(resEmpty.scans, 0);
        assert.strictEqual(resEmpty.reason, 'empty');

        // 2. Emergency stop via DISABLED file
        fs.writeFileSync(path.join(tmpDir, 'DISABLED'), 'emergency stop');
        const resDisabled = await scanText('Normal text', { stateDir: tmpDir });
        assert.strictEqual(resDisabled.ok, false);
        assert.strictEqual(resDisabled.verdict, 'unverified');
        assert.strictEqual(resDisabled.reason, 'disabled');
        assert.strictEqual(resDisabled.scans, 0);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('Scan edge: cryptographic verification of HMAC signature, content integrity, and URL', () => {
    const key = crypto.randomBytes(32);
    const url = 'https://docs.example.com/security';
    const text = 'All operating systems are updated.';

    const signed = sign(text, url, { key });
    assert.ok(signed.includes('<!-- webread:ok:'));

    // 1. Valid signature
    const vOk = verify(signed, { key });
    assert.strictEqual(vOk.ok, true);
    assert.strictEqual(vOk.url, url);
    assert.strictEqual(vOk.text, text);

    // 2. Forged HMAC stamp
    const fakeHmac = signed.replace(/<!-- webread:ok:[0-9a-fA-F]{64} -->/, '<!-- webread:ok:' + '0'.repeat(64) + ' -->');
    const vFake = verify(fakeHmac, { key });
    assert.strictEqual(vFake.ok, false);
    assert.strictEqual(vFake.reason, 'bad_hmac');

    // 3. Tampered text with original stamp
    const tamperedText = signed.replace('are updated', 'are COMPROMISED');
    const vTampered = verify(tamperedText, { key });
    assert.strictEqual(vTampered.ok, false);
    assert.strictEqual(vTampered.reason, 'bad_hmac');

    // 4. Tampered URL with original stamp
    const tamperedUrl = signed.replace(url, 'https://evil.com/phishing');
    const vTamperedUrl = verify(tamperedUrl, { key });
    assert.strictEqual(vTamperedUrl.ok, false);
    assert.strictEqual(vTamperedUrl.reason, 'bad_hmac');
});
