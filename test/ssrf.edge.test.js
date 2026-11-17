'use strict';
/**
 * test/ssrf.edge.test.js
 * Adversarial and edge-case test suite for SSRF protection and safe HTTP fetch.
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { isPrivateIp, validateUrl, safeFetch } = require('../src/ssrf.js');

test('SSRF edge: IPv4 special forms, CGNAT, and address boundaries', () => {
    // 0.0.0.0/8
    assert.strictEqual(isPrivateIp('0.0.0.0'), true, '0.0.0.0 must be blocked');
    assert.strictEqual(isPrivateIp('0.255.255.255'), true, '0/8 must be blocked');

    // 100.64.0.0/10 (CGNAT RFC 6598: 100.64.0.0 to 100.127.255.255)
    assert.strictEqual(isPrivateIp('100.64.0.1'), true, '100.64.0.1 (CGNAT) must be private');
    assert.strictEqual(isPrivateIp('100.127.255.254'), true, '100.127.255.254 (CGNAT upper bound) must be private');
    assert.strictEqual(isPrivateIp('100.63.255.255'), false, '100.63.x.x outside CGNAT must be public');
    assert.strictEqual(isPrivateIp('100.128.0.1'), false, '100.128.x.x outside CGNAT must be public');

    // 127.0.0.0/8 Loopback
    assert.strictEqual(isPrivateIp('127.0.0.2'), true, '127.0.0.2 must be private');
    assert.strictEqual(isPrivateIp('127.255.255.254'), true, '127.255.255.254 must be private');

    // 169.254.0.0/16 Link-local
    assert.strictEqual(isPrivateIp('169.254.1.1'), true, '169.254.1.1 must be private');
});

test('SSRF edge: IPv6 compact, expanded, and special addresses', () => {
    // Unspecified ::
    assert.strictEqual(isPrivateIp('::'), true, ':: must be private');
    assert.strictEqual(isPrivateIp('0:0:0:0:0:0:0:0'), true, 'expanded 0:0:0:0:0:0:0:0 must be private');

    // Loopback ::1
    assert.strictEqual(isPrivateIp('::1'), true, '::1 must be private');
    assert.strictEqual(isPrivateIp('0:0:0:0:0:0:0:1'), true, 'expanded 0:0:0:0:0:0:0:1 must be private');

    // ULA fc00::/7 (fc00 to fdff)
    assert.strictEqual(isPrivateIp('fc00::1'), true, 'fc00::1 must be private');
    assert.strictEqual(isPrivateIp('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), true, 'fdff:: must be private');

    // Link-Local fe80::/10 (fe80 to febf)
    assert.strictEqual(isPrivateIp('fe80::1'), true, 'fe80::1 must be private');
    assert.strictEqual(isPrivateIp('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), true, 'febf:: must be private');

    // Multicast ff00::/8
    assert.strictEqual(isPrivateIp('ff01::1'), true, 'ff01::1 must be private');
    assert.strictEqual(isPrivateIp('ff02::1'), true, 'ff02::1 must be private');

    // IPv4-mapped with private and public IPv4
    assert.strictEqual(isPrivateIp('::ffff:127.0.0.1'), true, '::ffff:127.0.0.1 must be private');
    assert.strictEqual(isPrivateIp('::ffff:10.0.0.1'), true, '::ffff:10.0.0.1 must be private');
    assert.strictEqual(isPrivateIp('::ffff:93.184.216.34'), false, '::ffff:public IPv4 must be public');

    // 64:ff9b:: WKP (RFC 6052)
    assert.strictEqual(isPrivateIp('64:ff9b::127.0.0.1'), true, '64:ff9b::127.0.0.1 must be private');
    assert.strictEqual(isPrivateIp('64:ff9b::93.184.216.34'), false, '64:ff9b::public must be public');
});

test('SSRF edge: IPv4-compatible (::127.0.0.1) and SIIT (::ffff:0:127.0.0.1) validation', () => {
    // IPv4-compatible IPv6 (RFC 4291) - e.g. ::127.0.0.1 or ::10.0.0.1
    const isCompatPrivate = isPrivateIp('::127.0.0.1');
    assert.strictEqual(isCompatPrivate, true, '::127.0.0.1 (IPv4-compatible loopback) must be detected as private');

    // SIIT IPv4-translated (RFC 2765 / RFC 6052) - ::ffff:0:a.b.c.d
    const isSiitPrivate = isPrivateIp('::ffff:0:127.0.0.1');
    assert.strictEqual(isSiitPrivate, true, '::ffff:0:127.0.0.1 (SIIT IPv4-translated loopback) must be detected as private');
});

test('SSRF edge: validateUrl rejects obfuscated IPs, unsafe schemes, and credentials', () => {
    // Obfuscated IP representations
    assert.strictEqual(validateUrl('http://0177.0.0.1/').ok, false, 'octal IP must be rejected');
    assert.strictEqual(validateUrl('http://0x7f000001/').ok, false, 'hex IP must be rejected');
    assert.strictEqual(validateUrl('http://0x7f.0.0.1/').ok, false, 'mixed hex/dec IP must be rejected');
    assert.strictEqual(validateUrl('http://2130706433/').ok, false, 'dword numeric IP must be rejected');
    assert.strictEqual(validateUrl('http://127.1/').ok, false, 'shorthand IP must be rejected');

    // Credentials in URL
    assert.strictEqual(validateUrl('http://user:pass@example.com/').ok, false, 'user:pass must be rejected');
    assert.strictEqual(validateUrl('http://user@example.com/').ok, false, 'user@ must be rejected');
    assert.strictEqual(validateUrl('http://:pass@example.com/').ok, false, ':pass@ must be rejected');

    // Non-HTTP/HTTPS schemes
    assert.strictEqual(validateUrl('file:///etc/passwd').ok, false, 'file: must be rejected');
    assert.strictEqual(validateUrl('ftp://example.com/file').ok, false, 'ftp: must be rejected');
    assert.strictEqual(validateUrl('gopher://example.com/').ok, false, 'gopher: must be rejected');
    assert.strictEqual(validateUrl('data:text/html,test').ok, false, 'data: must be rejected');
    assert.strictEqual(validateUrl('javascript:alert(1)').ok, false, 'javascript: must be rejected');
});

test('SSRF edge: safeFetch redirect handling (relative, empty, looped, public->private)', async () => {
    // 1. Redirect with missing location header
    const mockEmptyLocationFetch = async () => ({
        status: 302,
        headers: { 'content-type': 'text/html' },
        body: '',
    });
    const resEmpty = await safeFetch('http://example.com/start', {
        lookup: () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockEmptyLocationFetch,
    });
    assert.strictEqual(resEmpty.ok, false);
    assert.strictEqual(resEmpty.reason, 'redirect_missing_location');

    // 2. Relative redirect: Location: /destination
    let hop = 0;
    const mockRelativeRedirectFetch = async (url) => {
        hop++;
        if (hop === 1) {
            return {
                status: 302,
                headers: { 'location': '/destination', 'content-type': 'text/html' },
                body: '',
            };
        }
        return {
            status: 200,
            headers: { 'content-type': 'text/html' },
            body: '<html><body>Destination reached</body></html>',
        };
    };
    const resRel = await safeFetch('http://example.com/start', {
        lookup: () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockRelativeRedirectFetch,
    });
    assert.strictEqual(resRel.ok, true);
    assert.strictEqual(resRel.finalUrl, 'http://example.com/destination');

    // 3. Public to private IP redirect
    let hopPriv = 0;
    const mockPrivRedirectFetch = async () => {
        hopPriv++;
        if (hopPriv === 1) {
            return {
                status: 302,
                headers: { 'location': 'http://127.0.0.1/admin', 'content-type': 'text/html' },
                body: '',
            };
        }
        return { status: 200, headers: { 'content-type': 'text/html' }, body: 'leak' };
    };
    const resPriv = await safeFetch('http://example.com/start', {
        lookup: () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockPrivRedirectFetch,
    });
    assert.strictEqual(resPriv.ok, false);
    assert.strictEqual(resPriv.reason, 'private_ip');
});

test('SSRF edge: safeFetch DNS rebinding and IP pinning', async () => {
    // DNS rebinding: first lookup returns public IP, second lookup returns private IP
    let lookupCount = 0;
    const rebindingLookup = async () => {
        lookupCount++;
        if (lookupCount === 1) {
            return [{ address: '93.184.216.34', family: 4 }];
        }
        return [{ address: '10.0.1.100', family: 4 }];
    };

    let fetchCount = 0;
    const mockRedirectFetch = async () => {
        fetchCount++;
        return {
            status: 302,
            headers: { 'location': 'http://rebinding.target.com/hop2', 'content-type': 'text/html' },
            body: '',
        };
    };

    const resRebind = await safeFetch('http://rebinding.target.com/start', {
        lookup: rebindingLookup,
        fetchImpl: mockRedirectFetch,
    });
    assert.strictEqual(resRebind.ok, false);
    assert.strictEqual(resRebind.reason, 'private_ip');
});

test('SSRF edge: stream limit in safeFetch (too_large) and buffer protection', async () => {
    // Generate response exceeding 2MB (2 * 1024 * 1024)
    const bigChunk = Buffer.alloc(1024 * 1024, 'a'); // 1MB
    const makeStream = () => {
        const { Readable } = require('node:stream');
        let count = 0;
        return new Readable({
            read() {
                if (count < 3) {
                    count++;
                    this.push(bigChunk);
                } else {
                    this.push(null);
                }
            },
        });
    };

    const mockBigFetch = async () => ({
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: makeStream(),
    });

    const res = await safeFetch('http://example.com/bigfile', {
        lookup: () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockBigFetch,
        maxBytes: 2 * 1024 * 1024,
    });

    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.reason, 'too_large');
    assert.strictEqual(res.body, undefined, 'Partial body must not be returned');
});

test('SSRF edge: default Node client fetch and 302 redirect with IP pinning', async () => {
    let hops = [];
    const server = http.createServer((req, res) => {
        hops.push(req.url);
        if (req.url === '/hop1') {
            res.writeHead(302, { Location: '/hop2' });
            res.end();
        } else if (req.url === '/hop2') {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Response from hop2');
        }
    });

    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;

    try {
        const res = await safeFetch(`http://127.0.0.1:${port}/hop1`, {
            _allowPrivateForTesting: true,
        });

        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.finalUrl, `http://127.0.0.1:${port}/hop2`);
        assert.strictEqual(res.body.toString('utf8'), 'Response from hop2');
        assert.deepStrictEqual(hops, ['/hop1', '/hop2']);
    } finally {
        await new Promise(r => server.close(r));
    }
});

test('SSRF edge: https variant with self-signed certificate rejected fail-closed', async () => {
    const { execSync } = require('node:child_process');
    const https = require('node:https');
    const fs = require('node:fs');
    const path = require('node:path');
    const os = require('node:os');

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-test-'));
    const keyFile = path.join(tmp, 'key.pem');
    const certFile = path.join(tmp, 'cert.pem');

    try {
        execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${keyFile}" -out "${certFile}" -days 1 -nodes -subj "/CN=127.0.0.1"`, { stdio: 'pipe' });
        const key = fs.readFileSync(keyFile);
        const cert = fs.readFileSync(certFile);

        const server = https.createServer({ key, cert }, (req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('https secret');
        });

        await new Promise(r => server.listen(0, '127.0.0.1', r));
        const port = server.address().port;

        try {
            const res = await safeFetch(`https://127.0.0.1:${port}/`, {
                _allowPrivateForTesting: true,
            });
            // HTTPS request with untrusted self-signed certificate must fail closed
            assert.strictEqual(res.ok, false);
            assert.ok(
                res.reason.includes('self-signed certificate') ||
                res.reason.includes('certificate') ||
                res.reason.includes('fetch_error')
            );
        } finally {
            await new Promise(r => server.close(r));
        }
    } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});

test('SSRF edge: isPrivateIp verification for RFC 8215 (64:ff9b:1::/48) and RFC 6052 (64:ff9b::/96)', () => {
    // RFC 8215 Local-Use IPv4/IPv6 Translation Prefix: 64:ff9b:1::/48 - always private regardless of suffix
    assert.strictEqual(isPrivateIp('64:ff9b:1::8.8.8.8'), true, '64:ff9b:1::8.8.8.8 must be private (RFC 8215)');
    assert.strictEqual(isPrivateIp('64:ff9b:1:ffff::1'), true, '64:ff9b:1:ffff::1 must be private (RFC 8215)');
    assert.strictEqual(isPrivateIp('0064:FF9B:0001:0000:0000:0000:0808:0808'), true, 'Full uppercase RFC 8215 must be private');

    // RFC 6052 Well-Known Prefix: 64:ff9b::/96 - private if embedded IPv4 is private, public if public
    assert.strictEqual(isPrivateIp('64:ff9b::7f00:1'), true, '64:ff9b::7f00:1 (127.0.0.1) must be private');
    assert.strictEqual(isPrivateIp('64:ff9b::a00:1'), true, '64:ff9b::a00:1 (10.0.0.1) must be private');
    assert.strictEqual(isPrivateIp('64:ff9b::ac10:101'), true, '64:ff9b::ac10:101 (172.16.1.1) must be private');
    assert.strictEqual(isPrivateIp('64:ff9b::808:808'), false, '64:ff9b::808:808 (8.8.8.8) must be public');
    assert.strictEqual(isPrivateIp('0064:FF9B:0000:0000:0000:0000:7F00:0001'), true, 'Full form with 127.0.0.1 must be private');
    assert.strictEqual(isPrivateIp('0064:FF9B:0000:0000:0000:0000:0808:0808'), false, 'Full form with 8.8.8.8 must be public');
    assert.strictEqual(isPrivateIp('64:FF9B::AC10:0101'), true, 'Uppercase with 172.16.1.1 must be private');
});
