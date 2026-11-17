'use strict';
/**
 * test/cli.test.js
 * End-to-end tests for CLI commands (anonymize-test, verify, self-test, --version)
 * executed via child_process without network calls.
 */
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const hmac = require('../src/hmac.js');

const CLI_PATH = path.resolve(__dirname, '../bin/webread-mcp.js');

function makeTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-cli-test-'));
}

test('CLI: --version displays package version and exits 0', () => {
    const res = spawnSync(process.execPath, [CLI_PATH, '--version'], { encoding: 'utf8' });
    assert.strictEqual(res.status, 0);
    assert.strictEqual(res.stdout.trim(), '0.1.0');
});

test('CLI: --help displays usage information and exits 0', () => {
    const res = spawnSync(process.execPath, [CLI_PATH, '--help'], { encoding: 'utf8' });
    assert.strictEqual(res.status, 0);
    assert.ok(res.stdout.includes('Usage:'));
    assert.ok(res.stdout.includes('anonymize-test'));
    assert.ok(res.stdout.includes('verify'));
    assert.ok(res.stdout.includes('self-test'));
});

test('CLI: self-test passes cleanly when scanner=none is configured', () => {
    const tmpDir = makeTmpDir();
    try {
        const res = spawnSync(process.execPath, [CLI_PATH, 'self-test'], {
            encoding: 'utf8',
            env: {
                ...process.env,
                WEBREAD_STATE_DIR: tmpDir,
                WEBREAD_SCANNER: 'none',
            },
        });
        assert.strictEqual(res.status, 0);
        assert.ok(res.stdout.includes('Self-test PASSED successfully.'));
        assert.ok(res.stdout.includes('[PASS] Node.js version'));
        assert.ok(res.stdout.includes('[PASS] State directory writable'));
        assert.ok(res.stdout.includes('[PASS] HMAC secret key verified'));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('CLI: anonymize-test redacts private IPs, emails, and secrets', () => {
    const tmpDir = makeTmpDir();
    try {
        const sampleFile = path.join(tmpDir, 'sample.txt');
        fs.writeFileSync(sampleFile, 'Contact admin@internal.local on server 10.0.0.15 with token sk-abcdef123456789012345678.');

        const res = spawnSync(process.execPath, [CLI_PATH, 'anonymize-test', sampleFile], {
            encoding: 'utf8',
        });

        assert.strictEqual(res.status, 0);
        assert.ok(res.stdout.includes('[EMAIL]'));
        assert.ok(res.stdout.includes('[IP_ADDRESS]'));
        assert.ok(res.stdout.includes('[API_TOKEN]'));
        assert.ok(!res.stdout.includes('admin@internal.local'));
        assert.ok(!res.stdout.includes('10.0.0.15'));
        assert.ok(!res.stdout.includes('sk-abcdef123456789012345678'));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('CLI: anonymize-test respects custom rules via WEBREAD_ANONYMIZE_FILE', () => {
    const tmpDir = makeTmpDir();
    try {
        const rulesFile = path.join(tmpDir, 'rules.json');
        fs.writeFileSync(rulesFile, JSON.stringify({
            literals: [{ value: 'Acme Corp', replace: '[ORGANIZATION]' }],
            patterns: [{ regex: 'CONFIDENTIAL-\\d+', flags: 'g', replace: '[CLASSIFIED]' }],
        }));

        const sampleFile = path.join(tmpDir, 'contract.txt');
        fs.writeFileSync(sampleFile, 'Agreement with Acme Corp regarding CONFIDENTIAL-987654.');

        const res = spawnSync(process.execPath, [CLI_PATH, 'anonymize-test', sampleFile], {
            encoding: 'utf8',
            env: {
                ...process.env,
                WEBREAD_ANONYMIZE_FILE: rulesFile,
            },
        });

        assert.strictEqual(res.status, 0);
        assert.ok(res.stdout.includes('[ORGANIZATION]'));
        assert.ok(res.stdout.includes('[CLASSIFIED]'));
        assert.ok(!res.stdout.includes('Acme Corp'));
        assert.ok(!res.stdout.includes('CONFIDENTIAL-987654'));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('CLI: anonymize-test fails gracefully on missing argument or non-existent file', () => {
    // Missing argument
    const resNoArg = spawnSync(process.execPath, [CLI_PATH, 'anonymize-test'], { encoding: 'utf8' });
    assert.strictEqual(resNoArg.status, 1);
    assert.ok(resNoArg.stderr.includes('file path argument required'));

    // Non-existent file
    const resNoFile = spawnSync(process.execPath, [CLI_PATH, 'anonymize-test', '/non/existent/file.txt'], { encoding: 'utf8' });
    assert.strictEqual(resNoFile.status, 1);
    assert.ok(resNoFile.stderr.includes('Error reading file'));
});

test('CLI: verify validates genuine HMAC-signed envelopes and rejects tampered ones', () => {
    const tmpDir = makeTmpDir();
    try {
        const key = crypto.randomBytes(32);
        const keyFile = path.join(tmpDir, 'webread.key');
        fs.writeFileSync(keyFile, key.toString('hex') + '\n', { mode: 0o600 });

        const testUrl = 'https://example.com/verified-article';
        const testContent = 'Authentic unmodified article content.';
        const signedEnvelope = hmac.sign(testContent, testUrl, { key, scanned: 'clef', verdict: 'clean' });

        const validFile = path.join(tmpDir, 'valid.txt');
        fs.writeFileSync(validFile, signedEnvelope);

        // 1. Verify valid envelope via file argument
        const resValid = spawnSync(process.execPath, [CLI_PATH, 'verify', validFile], {
            encoding: 'utf8',
            env: { ...process.env, WEBREAD_STATE_DIR: tmpDir },
        });

        assert.strictEqual(resValid.status, 0);
        assert.ok(resValid.stdout.includes('VALID'));
        assert.ok(resValid.stdout.includes(`URL: ${testUrl}`));
        assert.ok(resValid.stdout.includes('Scanned by: clef'));
        assert.ok(resValid.stdout.includes('Verdict: clean'));

        // 2. Verify tampered envelope
        const tamperedEnvelope = signedEnvelope.replace('Authentic unmodified', 'TAMPERED MALICIOUS');
        const tamperedFile = path.join(tmpDir, 'tampered.txt');
        fs.writeFileSync(tamperedFile, tamperedEnvelope);

        const resTampered = spawnSync(process.execPath, [CLI_PATH, 'verify', tamperedFile], {
            encoding: 'utf8',
            env: { ...process.env, WEBREAD_STATE_DIR: tmpDir },
        });

        assert.strictEqual(resTampered.status, 1);
        assert.ok(resTampered.stderr.includes('INVALID (bad_hmac)'));

        // 3. Verify via stdin (-)
        const resStdin = spawnSync(process.execPath, [CLI_PATH, 'verify', '-'], {
            input: signedEnvelope,
            encoding: 'utf8',
            env: { ...process.env, WEBREAD_STATE_DIR: tmpDir },
        });

        assert.strictEqual(resStdin.status, 0);
        assert.ok(resStdin.stdout.includes('VALID'));

        // 4. Verify invalid content with missing stamp
        const resPlain = spawnSync(process.execPath, [CLI_PATH, 'verify', '-'], {
            input: 'Just plain unverified text without stamp',
            encoding: 'utf8',
            env: { ...process.env, WEBREAD_STATE_DIR: tmpDir },
        });

        assert.strictEqual(resPlain.status, 1);
        assert.ok(resPlain.stderr.includes('INVALID (missing_stamp)'));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});
