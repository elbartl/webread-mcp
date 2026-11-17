'use strict';
/**
 * src/server.js - Model Context Protocol (MCP) Server for web_read tool.
 *
 * Exposes the `web_read` tool over stdio JSON-RPC 2.0 without external npm dependencies:
 * 1. Query parameter sanitization (strips credentials, session tokens, API keys).
 * 2. Strict SSRF validation (blocks RFC 1918, loopback, CGNAT, link-local, internal domains).
 * 3. Safe HTTP/HTTPS fetch with IP pinning, streaming size limits, and manual redirect checks.
 * 4. Text extraction with invisible character and CSS/HTML hidden payload stripping.
 * 5. Prompt injection and hijack scanning (via CLEF, Ollama, or explicit None).
 * 6. Content envelopment in <external-source> and HMAC-SHA256 signature stamping.
 * 7. Quarantine logging for rejected payloads and audit JSONL tracking.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const config = require('./config.js');
const ssrf = require('./ssrf.js');
const extract = require('./extract.js');
const scan = require('./scan.js');
const hmac = require('./hmac.js');
const anonymizeModule = require('./anonymize.js');

const TOOLS = [
    {
        name: 'web_read',
        description: 'Securely fetch and read web pages with SSRF protection, content extraction, and prompt injection scanning.',
        inputSchema: {
            type: 'object',
            properties: {
                url: {
                    type: 'string',
                    description: 'Full http(s) URL of the webpage to fetch and read',
                },
                max_chars: {
                    type: 'integer',
                    description: 'Maximum extracted character count (default: 60000)',
                },
            },
            required: ['url'],
        },
    },
];

// Dependency injection for testing
const deps = {
    safeFetch: null,
    validateUrl: null,
    extractContent: null,
    scanText: null,
    sign: null,
    stateDir: null,
    key: undefined,
    keyPath: null,
    keyFile: null,
    lookup: null,
    fetchImpl: null,
    clefMock: null,
    ollamaMock: null,
    scanner: null,
};

function _setDeps(d) {
    Object.assign(deps, d);
}

/**
 * Normalizes URL parameter name.
 */
function normalizeParamName(name) {
    let s = String(name || '');
    try {
        s = decodeURIComponent(s);
    } catch (_) {}
    return s.toLowerCase().replace(/[-_]/g, '');
}

/**
 * Checks if a parameter name indicates a credential, token, or secret.
 */
function isSecretParamName(normName) {
    if (!normName) return false;
    return (
        normName.includes('token') ||
        normName.includes('secret') ||
        normName.includes('password') ||
        normName.includes('passwd') ||
        normName.includes('apikey') ||
        normName.includes('auth') ||
        normName.includes('sig') ||
        normName.includes('session') ||
        normName.includes('credential') ||
        normName === 'key' ||
        normName.endsWith('key') ||
        normName.startsWith('key') ||
        normName.includes('bearer')
    );
}

/**
 * Sanitizes URL by stripping hash fragments and removing sensitive query parameters.
 */
function sanitizeUrl(urlString) {
    if (typeof urlString !== 'string') return urlString;
    const withoutHash = urlString.split('#')[0];
    let u;
    try {
        u = new URL(withoutHash);
    } catch (_) {
        return withoutHash;
    }

    u.hash = '';

    const SECRET_PREFIX_RE = /^(?:sk-|ghp_|xox[baprs]-|AKIA|Bearer\s+)/i;
    const LONG_SECRET_RE = /^[A-Za-z0-9+/=_-]{24,}$/;

    const keysToDelete = new Set();
    for (const [name, val] of u.searchParams.entries()) {
        const normName = normalizeParamName(name);
        if (isSecretParamName(normName)) {
            keysToDelete.add(name);
            continue;
        }
        if (SECRET_PREFIX_RE.test(val)) {
            keysToDelete.add(name);
            continue;
        }
        if (val.length >= 24 && LONG_SECRET_RE.test(val)) {
            keysToDelete.add(name);
            continue;
        }
    }

    for (const name of keysToDelete) {
        u.searchParams.delete(name);
    }
    return u.toString();
}

/**
 * Returns URL without query string and hash for safe logging.
 */
function stripQuery(urlString) {
    try {
        const u = new URL(urlString);
        u.search = '';
        u.hash = '';
        return u.toString();
    } catch (_) {
        return String(urlString).split('?')[0].split('#')[0];
    }
}

/**
 * Writes an audit entry to the JSONL log without storing page body content.
 */
function writeLog(logPath, entry) {
    try {
        fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
        const line = JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n';
        fs.appendFileSync(logPath, line, { mode: 0o600 });
    } catch (_) {
        // Logging failure must never break core functionality
    }
}

/**
 * Saves quarantined (rejected) content to disk.
 */
function saveQuarantine(quarantineDir, text) {
    try {
        fs.mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const sha = crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
        const filePath = path.join(quarantineDir, `${ts}-${sha}.txt`);
        fs.writeFileSync(filePath, text, { mode: 0o600 });
        return filePath;
    } catch (_) {
        return null;
    }
}

/**
 * Main web_read logic.
 *
 * Returns a result in one of three states:
 * - 'clean': content verified and safe, returned wrapped and HMAC-signed.
 * - 'quarantine': content flagged as prompt injection or hijack. Malicious content is withheld.
 * - 'unverified': verification could not be completed (error, timeout, budget exhaustion, disabled).
 *
 * Every result includes `scanned: <backend>`.
 *
 * @param {object} args
 * @returns {Promise<object>}
 */
async function webRead(args = {}) {
    const startTime = Date.now();
    const cfg = config.getConfig({ stateDir: deps.stateDir, scanner: deps.scanner });
    const paths = cfg.paths;
    const logPath = paths.log;

    const rawUrl = String(args && args.url || '').trim();
    if (!rawUrl) {
        const err = new Error('Missing required parameter: url');
        err.code = 'bad_input';
        throw err;
    }

    const maxChars = Number.isFinite(Number(args.max_chars)) && Number(args.max_chars) > 0
        ? Number(args.max_chars)
        : cfg.maxChars;

    const urlNoQuery = stripQuery(rawUrl);
    const backendName = cfg.scanner;

    // 1. Sanitize URL query parameters
    const sanitizedUrl = sanitizeUrl(rawUrl);

    // 2. Validate URL against SSRF risks
    const validator = deps.validateUrl || ssrf.validateUrl;
    const v = validator(sanitizedUrl);
    if (!v.ok) {
        const timeMs = Date.now() - startTime;
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: `ssrf_${v.reason}`,
            scanned: backendName,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: backendName,
            reason: `ssrf_${v.reason}`,
            url: urlNoQuery,
        };
    }

    // 3. Safe fetch with IP pinning
    const fetcher = deps.safeFetch || ssrf.safeFetch;
    let fetchRes;
    try {
        fetchRes = await fetcher(sanitizedUrl, {
            lookup: deps.lookup,
            fetchImpl: deps.fetchImpl,
            timeoutMs: cfg.timeoutMs,
            maxBytes: cfg.maxBytes,
            maxRedirects: cfg.maxRedirects,
        });
    } catch (err) {
        const timeMs = Date.now() - startTime;
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: `fetch_failed: ${err.message}`,
            scanned: backendName,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: backendName,
            reason: `fetch_failed: ${err.message}`,
            url: urlNoQuery,
        };
    }

    if (!fetchRes.ok) {
        const timeMs = Date.now() - startTime;
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: fetchRes.reason,
            scanned: backendName,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: backendName,
            reason: fetchRes.reason,
            url: urlNoQuery,
        };
    }

    // 4. Extract content and strip hidden fragments
    const extractor = deps.extractContent || extract.extractContent;
    const extractRes = extractor(fetchRes.body, fetchRes.contentType, {
        baseUrl: fetchRes.finalUrl || sanitizedUrl,
        maxChars,
    });

    if (!extractRes.ok) {
        const timeMs = Date.now() - startTime;
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: extractRes.reason || extractRes.error || 'extract_failed',
            scanned: backendName,
            length: extractRes.length || 0,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: backendName,
            reason: extractRes.reason || extractRes.error || 'extract_failed',
            url: urlNoQuery,
            length: extractRes.length || 0,
        };
    }

    const cleanText = extractRes.text;

    // 5. Scan text with selected backend
    const scanner = deps.scanText || scan.scanText;
    let scanRes;
    try {
        scanRes = await scanner(cleanText, {
            scanner: deps.scanner || cfg.scanner,
            stateDir: paths.stateDir,
            dailyNeurons: cfg.dailyNeurons,
            clefMock: deps.clefMock,
            ollamaMock: deps.ollamaMock,
            fetchImpl: deps.fetchImpl,
            timeoutMs: cfg.scanTimeoutMs,
            scanTimeoutMs: cfg.scanTimeoutMs,
        });
    } catch (err) {
        const timeMs = Date.now() - startTime;
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: `scan_error: ${err.message}`,
            scanned: backendName,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: backendName,
            reason: 'scan_error',
            url: urlNoQuery,
        };
    }

    const timeMs = Date.now() - startTime;
    const effectiveScanned = scanRes.scanned || backendName;

    // Check scan verdict
    if (scanRes.verdict !== 'clean') {
        if (scanRes.verdict === 'quarantine') {
            saveQuarantine(paths.quarantineDir, cleanText);
            writeLog(logPath, {
                url: urlNoQuery,
                verdict: 'quarantine',
                reason: scanRes.reason,
                scanned: effectiveScanned,
                length: cleanText.length,
                scans: scanRes.scans,
                timeMs,
            });
            return {
                ok: false,
                verdict: 'quarantine',
                scanned: effectiveScanned,
                reason: scanRes.reason,
                url: urlNoQuery,
            };
        }

        // Any error, timeout, or budget issue ALWAYS produces 'unverified'
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: scanRes.reason,
            scanned: effectiveScanned,
            length: cleanText.length,
            scans: scanRes.scans,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: effectiveScanned,
            reason: scanRes.reason,
            url: urlNoQuery,
        };
    }

    // 6. Sign and envelope clean content
    let finalText = cleanText;
    if (effectiveScanned === 'none') {
        const warning = scanRes.warning || '[SECURITY WARNING: Content was NOT scanned for prompt injection (WEBREAD_SCANNER=none).]';
        finalText = `${warning}\n\n${cleanText}`;
    }

    const signer = deps.sign || hmac.sign;
    let wrappedText;
    try {
        wrappedText = signer(finalText, sanitizedUrl, {
            key: deps.key,
            keyPath: deps.keyPath || deps.keyFile || paths.key,
            scanned: effectiveScanned,
            verdict: 'clean',
        });
    } catch (err) {
        writeLog(logPath, {
            url: urlNoQuery,
            verdict: 'unverified',
            reason: 'sign_failed',
            scanned: effectiveScanned,
            length: cleanText.length,
            timeMs,
        });
        return {
            ok: false,
            verdict: 'unverified',
            scanned: effectiveScanned,
            reason: 'sign_failed',
            url: urlNoQuery,
        };
    }

    writeLog(logPath, {
        url: urlNoQuery,
        verdict: 'clean',
        scanned: effectiveScanned,
        length: cleanText.length,
        scans: scanRes.scans,
        timeMs,
    });

    return {
        ok: true,
        verdict: 'clean',
        scanned: effectiveScanned,
        url: sanitizedUrl,
        text: wrappedText,
        length: cleanText.length,
        scans: scanRes.scans || 0,
        hiddenElements: extractRes.hiddenCount || 0,
    };
}

async function callTool(name, a) {
    if (name === 'web_read') {
        return await webRead(a);
    }
    const e = new Error(`Unknown tool: ${name}`);
    e.code = 'unknown_tool';
    throw e;
}

// ---- Standard newline-delimited JSON-RPC 2.0 stdio transport ----
function send(msg) {
    process.stdout.write(JSON.stringify(msg) + '\n');
}

async function handle(msg, sendFn = send) {
    try {
        if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
            const maybeId = (msg && typeof msg === 'object' && msg.id !== undefined) ? msg.id : undefined;
            if (maybeId !== undefined) {
                return sendFn({
                    jsonrpc: '2.0',
                    id: maybeId,
                    error: { code: -32600, message: 'Invalid Request: message must be a JSON object' },
                });
            }
            return;
        }

        const { id, method, params } = msg;
        if (id === undefined) return;

        if (method === 'initialize') {
            return sendFn({
                jsonrpc: '2.0',
                id,
                result: {
                    protocolVersion: (params && params.protocolVersion) || '2024-11-05',
                    capabilities: { tools: {} },
                    serverInfo: { name: 'webread-mcp', version: '0.1.0' },
                },
            });
        }

        if (method === 'ping') {
            return sendFn({ jsonrpc: '2.0', id, result: {} });
        }

        if (method === 'tools/list') {
            return sendFn({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
        }

        if (method === 'tools/call') {
            const name = params && params.name;
            if (!TOOLS.some(t => t.name === name)) {
                return sendFn({
                    jsonrpc: '2.0',
                    id,
                    error: { code: -32602, message: `Unknown tool: ${name}` },
                });
            }
            try {
                const r = await callTool(name, (params && params.arguments) || {});
                return sendFn({
                    jsonrpc: '2.0',
                    id,
                    result: {
                        content: [{ type: 'text', text: JSON.stringify(r, null, 2) }],
                        isError: !r.ok,
                        verdict: r.verdict,
                        scanned: r.scanned,
                    },
                });
            } catch (e) {
                return sendFn({
                    jsonrpc: '2.0',
                    id,
                    result: {
                        content: [{ type: 'text', text: `ERROR [${e.code || 'error'}]: ${e.message}` }],
                        isError: true,
                        code: e.code || 'error',
                    },
                });
            }
        }

        sendFn({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Method not found: ${method}` },
        });
    } catch (err) {
        try {
            if (msg && typeof msg === 'object' && msg.id !== undefined) {
                sendFn({
                    jsonrpc: '2.0',
                    id: msg.id,
                    error: { code: -32603, message: 'Internal error: ' + (err && err.message || 'unknown') },
                });
            }
        } catch (_) {}
    }
}

function startStdioServer() {
    try {
        const cfg = config.getConfig({ stateDir: deps.stateDir, scanner: deps.scanner });
        if (cfg.anonymizeFile) {
            anonymizeModule.loadAnonymizeFile(cfg.anonymizeFile);
        }
        hmac.ensureKey(cfg.paths.key);
    } catch (err) {
        console.error(`Fatal configuration error: ${err.message}`);
        process.exit(1);
    }

    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => {
        try {
            buf += d;
            let nl;
            while ((nl = buf.indexOf('\n')) >= 0) {
                const line = buf.slice(0, nl).trim();
                buf = buf.slice(nl + 1);
                if (!line) continue;
                let msg;
                try {
                    msg = JSON.parse(line);
                } catch (_) {
                    continue;
                }
                handle(msg).catch((e) => {
                    try {
                        if (msg && typeof msg === 'object' && msg.id !== undefined) {
                            send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: e.message } });
                        }
                    } catch (_) {}
                });
            }
        } catch (_) {}
    });
    process.stdin.on('error', () => {});
    process.stdin.on('end', () => process.exit(0));
}

if (require.main === module) {
    startStdioServer();
} else {
    module.exports = {
        TOOLS,
        handle,
        callTool,
        webRead,
        sanitizeUrl,
        stripQuery,
        saveQuarantine,
        writeLog,
        startStdioServer,
        verify: hmac.verify,
        sign: hmac.sign,
        wrap: hmac.wrap,
        _setDeps,
    };
}
