'use strict';
/**
 * src/hmac.js - Cryptographic HMAC-SHA256 envelope and verification module.
 *
 * Provides:
 * - Automatic generation and loading of 256-bit HMAC keys with strict 0o600 file permissions.
 * - Enveloping clean web content in <external-source> tags with SHA-256 payload checksums.
 * - HMAC-SHA256 signing over url, content, verdict, and envelope attributes.
 * - Cryptographic verification using timing-safe comparisons to guard against tampering.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('./config.js');

const norm = s => String(s == null ? '' : s).replace(/\r\n|\r/g, '\n').trim();

function readAndValidateKey(keyPath) {
    const raw = fs.readFileSync(keyPath, 'utf8').trim();
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
        throw new Error(`Invalid HMAC key format in "${keyPath}": expected 64-character hex string (256-bit key)`);
    }
    return Buffer.from(raw, 'hex');
}

/**
 * Ensures an HMAC key exists at keyPath, generating a secure 256-bit key if absent.
 * @param {string} keyPath
 * @returns {Buffer}
 */
function ensureKey(keyPath) {
    if (!keyPath) throw new Error('keyPath is required');

    if (fs.existsSync(keyPath)) {
        return readAndValidateKey(keyPath);
    }

    const dir = path.dirname(keyPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    const keyHex = crypto.randomBytes(32).toString('hex');
    try {
        fs.writeFileSync(keyPath, keyHex + '\n', { mode: 0o600, flag: 'wx' });
        try {
            fs.chmodSync(keyPath, 0o600);
        } catch (_) {}
        return Buffer.from(keyHex, 'hex');
    } catch (err) {
        if (err && err.code === 'EEXIST') {
            return readAndValidateKey(keyPath);
        }
        throw err;
    }
}

/**
 * Loads an HMAC key from options, environment, or key file.
 * @param {object} [options]
 * @returns {Buffer|null}
 */
function loadKey(options = {}) {
    if (options && options.key === null) {
        return null;
    }
    if (Buffer.isBuffer(options.key)) {
        return options.key;
    }
    if (typeof options.key === 'string' && /^[0-9a-fA-F]{64}$/.test(options.key.trim())) {
        return Buffer.from(options.key.trim(), 'hex');
    }
    if (process.env.WEBREAD_HMAC_KEY && /^[0-9a-fA-F]{64}$/.test(process.env.WEBREAD_HMAC_KEY.trim())) {
        return Buffer.from(process.env.WEBREAD_HMAC_KEY.trim(), 'hex');
    }
    const keyPath = options.keyPath || config.getPaths(options.stateDir).key;
    if (keyPath) {
        try {
            return ensureKey(keyPath);
        } catch (_) {
            return null;
        }
    }
    return null;
}

function escapeAttr(val) {
    return String(val || '')
        .replace(/[\r\n]/g, '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function unescapeAttr(val) {
    return String(val || '')
        .replace(/&quot;/g, '"')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
}

function neutralizeEnvelopeClosingTags(text) {
    if (text == null) return '';
    return String(text)
        .replace(/<\s*\/\s*external-source(\s*[^>]*)?>/gi, (match) => {
            return match.replace('<', '&lt;').replace('>', '&gt;');
        })
        .replace(/<\s*\/\s*external-source/gi, '&lt;/external-source');
}

/**
 * Wraps content in an <external-source> envelope.
 * @param {string} text
 * @param {string} url
 * @param {object} [options]
 * @returns {string}
 */
function wrap(text, url, options = {}) {
    const rawUrl = escapeAttr(url);
    const str = neutralizeEnvelopeClosingTags(text);
    const scanned = options.scanned || 'clef';
    const verdict = options.verdict || 'clean';
    const sha = crypto.createHash('sha256').update(str, 'utf8').digest('hex');

    return `<external-source url="${rawUrl}" scanned="${scanned}" verdict="${verdict}" sha="${sha}">\n${str}\n</external-source>`;
}

/**
 * Signs wrapped content with an HMAC-SHA256 stamp.
 * @param {string} text
 * @param {string} url
 * @param {object} [options]
 * @returns {string}
 */
function sign(text, url, options = {}) {
    const wrapped = wrap(text, url, options);
    const key = options.key || loadKey(options);
    if (!key) throw new Error('HMAC secret key is missing');
    const n = norm(wrapped);
    const hmac = crypto.createHmac('sha256', key).update(n, 'utf8').digest('hex');
    return `${n}\n\n<!-- webread:ok:${hmac} -->`;
}

/**
 * Verifies an HMAC-signed envelope.
 *
 * @param {string} stampedText
 * @param {object} [options]
 * @returns {{ ok: boolean, reason?: string, url?: string, scanned?: string, verdict?: string, sha?: string, text?: string }}
 */
function verify(stampedText, options = {}) {
    const key = options.key || loadKey(options);
    if (!key) return { ok: false, reason: 'missing_key' };

    const n = norm(stampedText);
    const m = n.match(/<!-- (?:webread|clef):ok:([0-9a-fA-F]{64}) -->$/);
    if (!m) return { ok: false, reason: 'missing_stamp' };

    const content = norm(n.slice(0, m.index));
    const expectedHmac = crypto.createHmac('sha256', key).update(content, 'utf8').digest('hex');

    const want = Buffer.from(expectedHmac, 'hex');
    const got = Buffer.from(m[1], 'hex');
    if (want.length !== 32 || got.length !== 32 || !crypto.timingSafeEqual(want, got)) {
        return { ok: false, reason: 'bad_hmac' };
    }

    // Match envelope format (supporting current and legacy envelope attributes)
    const matchWrapper = content.match(/^<external-source\s+url="([^"]*)"(?:\s+scanned="([^"]*)")?(?:\s+clef="([^"]*)")?(?:\s+verdict="([^"]*)")?\s+sha="([0-9a-fA-F]{64})">\n?([\s\S]*?)\n?<\/external-source>$/);
    if (!matchWrapper) return { ok: false, reason: 'bad_wrapper' };

    const rawAttrUrl = matchWrapper[1];
    const url = unescapeAttr(rawAttrUrl);
    const scanned = matchWrapper[2] || (matchWrapper[3] === 'ok' ? 'clef' : 'unknown');
    const verdict = matchWrapper[4] || (matchWrapper[3] === 'ok' ? 'clean' : 'unknown');
    const sha = matchWrapper[5];
    const text = matchWrapper[6];

    if (options.expectedUrl && url !== options.expectedUrl && rawAttrUrl !== options.expectedUrl) {
        return { ok: false, reason: 'url_mismatch', url, expectedUrl: options.expectedUrl };
    }

    const expectedSha = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
    if (sha.toLowerCase() !== expectedSha.toLowerCase()) {
        return { ok: false, reason: 'sha_mismatch' };
    }

    return {
        ok: true,
        url,
        scanned,
        verdict,
        sha,
        text,
        content,
    };
}

module.exports = {
    ensureKey,
    loadKey,
    wrap,
    sign,
    verify,
    norm,
};
