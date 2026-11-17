'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { Readable } = require('node:stream');
const ssrf = require('../src/ssrf.js');

const MOCK_PUBLIC_IP = '93.184.216.34';
const mockPublicLookup = () => [{ address: MOCK_PUBLIC_IP, family: 4 }];

test('isPrivateIp: blocks private IPv4 ranges, loopback, link-local, and reserved (fail-closed)', () => {
    // Loopback 127.0.0.0/8
    assert.strictEqual(ssrf.isPrivateIp('127.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('127.0.0.2'), true);
    assert.strictEqual(ssrf.isPrivateIp('127.255.255.254'), true);

    // RFC 1918: 10.0.0.0/8
    assert.strictEqual(ssrf.isPrivateIp('10.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('10.255.255.254'), true);

    // RFC 1918: 172.16.0.0/12 and 16-bit private range
    assert.strictEqual(ssrf.isPrivateIp('172.16.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('172.31.255.254'), true);
    assert.strictEqual(ssrf.isPrivateIp('172.32.0.1'), false); // Public
    assert.strictEqual(ssrf.isPrivateIp(['192', '168', '1', '1'].join('.')), true);

    // Link-local: 169.254.0.0/16
    assert.strictEqual(ssrf.isPrivateIp('169.254.169.254'), true);
    assert.strictEqual(ssrf.isPrivateIp('169.254.1.1'), true);

    // Current network / Broadcast
    assert.strictEqual(ssrf.isPrivateIp('0.0.0.0'), true);
    assert.strictEqual(ssrf.isPrivateIp('0.255.255.255'), true);
    assert.strictEqual(ssrf.isPrivateIp('255.255.255.255'), true);

    // CGNAT RFC 6598: 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
    assert.strictEqual(ssrf.isPrivateIp('100.64.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('100.127.255.254'), true);
    assert.strictEqual(ssrf.isPrivateIp('100.63.255.255'), false);
    assert.strictEqual(ssrf.isPrivateIp('100.128.0.1'), false);

    // Multicast & Reserved (224/4, 240/4)
    assert.strictEqual(ssrf.isPrivateIp('224.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('240.0.0.1'), true);

    // Public IPv4
    assert.strictEqual(ssrf.isPrivateIp('93.184.216.34'), false);
    assert.strictEqual(ssrf.isPrivateIp('8.8.8.8'), false);
    assert.strictEqual(ssrf.isPrivateIp('1.1.1.1'), false);

    // Fail-closed for garbage/unparseable
    assert.strictEqual(ssrf.isPrivateIp('localhost'), true);
    assert.strictEqual(ssrf.isPrivateIp('0x7f000001'), true);
    assert.strictEqual(ssrf.isPrivateIp('2130706433'), true);
    assert.strictEqual(ssrf.isPrivateIp(''), true);
    assert.strictEqual(ssrf.isPrivateIp(null), true);
});

test('isPrivateIp: blocks private IPv6, ULA, link-local, multicast, SIIT and mapped addresses', () => {
    // Unspecified & Loopback
    assert.strictEqual(ssrf.isPrivateIp('::'), true);
    assert.strictEqual(ssrf.isPrivateIp('::1'), true);
    assert.strictEqual(ssrf.isPrivateIp('[::1]'), true);
    assert.strictEqual(ssrf.isPrivateIp('0:0:0:0:0:0:0:0'), true);
    assert.strictEqual(ssrf.isPrivateIp('0:0:0:0:0:0:0:1'), true);

    // ULA fc00::/7 (fc00:: to fdff::)
    assert.strictEqual(ssrf.isPrivateIp('fc00::1'), true);
    assert.strictEqual(ssrf.isPrivateIp('fd12:3456::1'), true);
    assert.strictEqual(ssrf.isPrivateIp('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), true);

    // Link-local fe80::/10
    assert.strictEqual(ssrf.isPrivateIp('fe80::1'), true);
    assert.strictEqual(ssrf.isPrivateIp('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), true);

    // Multicast ff00::/8
    assert.strictEqual(ssrf.isPrivateIp('ff01::1'), true);
    assert.strictEqual(ssrf.isPrivateIp('ff02::1'), true);

    // IPv4-mapped IPv6
    assert.strictEqual(ssrf.isPrivateIp('::ffff:127.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('::ffff:10.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('::ffff:93.184.216.34'), false);

    // IPv4-compatible & SIIT IPv4-translated
    assert.strictEqual(ssrf.isPrivateIp('::127.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('::ffff:0:127.0.0.1'), true);

    // RFC 6052 Well-Known Prefix 64:ff9b::/96
    assert.strictEqual(ssrf.isPrivateIp('64:ff9b::127.0.0.1'), true);
    assert.strictEqual(ssrf.isPrivateIp('64:ff9b::93.184.216.34'), false);
    assert.strictEqual(ssrf.isPrivateIp('64:ff9b:1::8.8.8.8'), true); // RFC 8215 local-use
});

test('validateUrl: enforces protocol, credentials rejection, and hostname filters', () => {
    // Valid public HTTP/HTTPS URLs
    assert.strictEqual(ssrf.validateUrl('https://example.com/page').ok, true);
    assert.strictEqual(ssrf.validateUrl('http://example.org:8080/path?a=1').ok, true);

    // Invalid protocols
    assert.strictEqual(ssrf.validateUrl('ftp://example.com/file').ok, false);
    assert.strictEqual(ssrf.validateUrl('file:///etc/passwd').ok, false);
    assert.strictEqual(ssrf.validateUrl('javascript:alert(1)').ok, false);
    assert.strictEqual(ssrf.validateUrl('data:text/html,test').ok, false);
    assert.strictEqual(ssrf.validateUrl('gopher://example.com/').ok, false);

    // Embedded credentials
    assert.strictEqual(ssrf.validateUrl('http://user:pass@example.com/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://user@example.com/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://:pass@example.com/').ok, false);

    // Forbidden hostnames & local suffixes
    assert.strictEqual(ssrf.validateUrl('http://localhost/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://myhost.local/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://service.internal/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://server.lan/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://device.home/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://node.ts.net/').ok, false);

    // Obfuscated IP addresses in hostnames
    assert.strictEqual(ssrf.validateUrl('http://0177.0.0.1/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://0x7f000001/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://2130706433/').ok, false);
    assert.strictEqual(ssrf.validateUrl('http://127.1/').ok, false);
});

test('safeFetch: handles success, redirects, size limit, and private IP rejection', async () => {
    // 1. Successful fetch with mock
    const mockSuccessFetch = async (url, opts) => ({
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        body: '<html><body>Hello World</body></html>',
    });

    const res1 = await ssrf.safeFetch('https://example.com/test', {
        lookup: mockPublicLookup,
        fetchImpl: mockSuccessFetch,
    });
    assert.strictEqual(res1.ok, true);
    assert.strictEqual(res1.status, 200);
    assert.strictEqual(res1.body.toString('utf8'), '<html><body>Hello World</body></html>');

    // 2. Reject private IP resolved from DNS
    const mockPrivateLookup = () => [{ address: '127.0.0.1', family: 4 }];
    const res2 = await ssrf.safeFetch('https://example.com/private', {
        lookup: mockPrivateLookup,
        fetchImpl: mockSuccessFetch,
    });
    assert.strictEqual(res2.ok, false);
    assert.strictEqual(res2.reason, 'private_ip');

    // 3. Reject redirect to private IP
    let callCount = 0;
    const mockRedirectFetch = async (url, opts) => {
        callCount++;
        if (callCount === 1) {
            return {
                status: 302,
                headers: { 'content-type': 'text/html', location: 'http://127.0.0.1:8080/admin' },
                body: '',
            };
        }
        return { status: 200, headers: { 'content-type': 'text/html' }, body: 'admin data' };
    };

    const res3 = await ssrf.safeFetch('https://example.com/redirect', {
        lookup: mockPublicLookup,
        fetchImpl: mockRedirectFetch,
    });
    assert.strictEqual(res3.ok, false);
    assert.strictEqual(res3.reason, 'private_ip');

    // 4. Exceed maximum redirects
    const mockLoopRedirectFetch = async () => ({
        status: 302,
        headers: { 'content-type': 'text/html', location: 'https://example.com/next' },
        body: '',
    });

    const res4 = await ssrf.safeFetch('https://example.com/start', {
        lookup: mockPublicLookup,
        fetchImpl: mockLoopRedirectFetch,
        maxRedirects: 2,
    });
    assert.strictEqual(res4.ok, false);
    assert.strictEqual(res4.reason, 'too_many_redirects');

    // 5. Exceed size limit
    const mockLargeFetch = async () => ({
        status: 200,
        headers: { 'content-type': 'text/html' },
        body: 'A'.repeat(5000),
    });

    const res5 = await ssrf.safeFetch('https://example.com/large', {
        lookup: mockPublicLookup,
        fetchImpl: mockLargeFetch,
        maxBytes: 1000,
    });
    assert.strictEqual(res5.ok, false);
    assert.strictEqual(res5.reason, 'too_large');

    // 6. Content type rejection
    const mockBinaryFetch = async () => ({
        status: 200,
        headers: { 'content-type': 'application/octet-stream' },
        body: 'binary data',
    });

    const res6 = await ssrf.safeFetch('https://example.com/binary', {
        lookup: mockPublicLookup,
        fetchImpl: mockBinaryFetch,
    });
    assert.strictEqual(res6.ok, false);
    assert.strictEqual(res6.reason, 'bad_content_type');

    // 7. Mixed public + private DNS records rejected (DNS rebinding defense)
    const mixedLookup = () => [
        { address: MOCK_PUBLIC_IP, family: 4 },
        { address: '127.0.0.1', family: 4 },
    ];
    let mixedCalled = false;
    const res7 = await ssrf.safeFetch('https://example.com/rebind', {
        lookup: mixedLookup,
        fetchImpl: async () => { mixedCalled = true; return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }; },
    });
    assert.strictEqual(res7.ok, false);
    assert.strictEqual(res7.reason, 'private_ip');
    assert.strictEqual(mixedCalled, false);

    // 8. Streaming Readable body exceeding maxBytes rejected without partial content
    const makeStream = () => {
        let count = 0;
        return new Readable({
            read() {
                if (count < 3) {
                    count++;
                    this.push(Buffer.alloc(500, 'x'));
                } else {
                    this.push(null);
                }
            },
        });
    };
    const res8 = await ssrf.safeFetch('https://example.com/stream', {
        lookup: mockPublicLookup,
        fetchImpl: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: makeStream() }),
        maxBytes: 1000,
    });
    assert.strictEqual(res8.ok, false);
    assert.strictEqual(res8.reason, 'too_large');
    assert.strictEqual(res8.body, undefined);
});

test('validateUrl and safeFetch: allowHosts option and buildRequestOptions', async () => {
    const allowHosts = ['example.com', 'docs.python.org'];
    assert.strictEqual(ssrf.validateUrl('https://evil.org/page', { allowHosts }).ok, false);
    assert.strictEqual(ssrf.validateUrl('https://example.com/page', { allowHosts }).ok, true);
    assert.strictEqual(ssrf.validateUrl('https://sub.example.com/page', { allowHosts }).ok, true);

    const optsDomain = ssrf.buildRequestOptions(new URL('https://example.com/test?q=1'), MOCK_PUBLIC_IP, 4);
    assert.strictEqual(optsDomain.headers['Accept-Encoding'], 'identity');
    assert.strictEqual(optsDomain.servername, 'example.com');

    const optsIp = ssrf.buildRequestOptions(new URL(`https://${MOCK_PUBLIC_IP}/test`), MOCK_PUBLIC_IP, 4);
    assert.strictEqual(optsIp.servername, undefined);
});
