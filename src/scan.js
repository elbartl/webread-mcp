'use strict';
/**
 * src/scan.js - Scanner orchestrator for webread-mcp.
 *
 * Responsibilities:
 * - Text chunking with overlap to prevent injection payloads from crossing split boundaries.
 * - Checking emergency kill switch (WEBREAD_DISABLED=1 or DISABLED file).
 * - Selecting backend: 'clef' (Cloudflare Workers AI), 'ollama' (local LLM), or 'none' (explicit bypass).
 * - Up-front daily budget reservation under file lock for CLEF to prevent quota exhaustion races.
 * - Automatic data anonymization before external API calls.
 * - Sequential chunk scanning with fail-closed short circuiting on detection or error.
 */

const fs = require('node:fs');
const path = require('node:path');
const config = require('./config.js');
const budget = require('./budget.js');
const anonymizeModule = require('./anonymize.js');

const clefBackend = require('./backends/clef.js');
const ollamaBackend = require('./backends/ollama.js');
const noneBackend = require('./backends/none.js');

const DEFAULT_CLEF_CHUNK_SIZE = 4000;
const DEFAULT_CLEF_OVERLAP = 1000;
const DEFAULT_OLLAMA_CHUNK_SIZE = 2000;
const DEFAULT_OLLAMA_OVERLAP = 300;

/**
 * Splits text into overlapping chunks.
 *
 * @param {string} text
 * @param {number} [chunkSize=4000]
 * @param {number} [overlap=1000]
 * @returns {string[]}
 */
function splitChunks(text, chunkSize = DEFAULT_CLEF_CHUNK_SIZE, overlap = DEFAULT_CLEF_OVERLAP) {
    if (text == null) return [];
    const str = String(text);
    if (str.length === 0) return [];
    if (str.length <= chunkSize) return [str];

    const chunks = [];
    const step = Math.max(1, chunkSize - overlap);
    let start = 0;

    while (start < str.length) {
        const end = Math.min(start + chunkSize, str.length);
        chunks.push(str.slice(start, end));
        if (end >= str.length) break;
        start += step;
    }
    return chunks;
}

/**
 * Resolves the backend implementation by name.
 */
function getBackend(name) {
    const norm = config.validateScanner(name);
    if (norm === 'none') return { name: 'none', impl: noneBackend };
    if (norm === 'ollama') return { name: 'ollama', impl: ollamaBackend };
    return { name: 'clef', impl: clefBackend };
}

/**
 * Scans text content for prompt injection or hijack attacks.
 *
 * @param {string} text
 * @param {object} [options]
 * @returns {Promise<{ ok: boolean, verdict: string, reason?: string, scanned: string, scans: number, chunks: number, warning?: string }>}
 */
async function scanText(text, options = {}) {
    const cfg = config.getConfig(options);
    const paths = cfg.paths;
    const nowTime = typeof options.now === 'function' ? options.now() : (options.now || Date.now());

    const scannerChoice = options.scanner || cfg.scanner;
    const { name: backendName, impl: backend } = getBackend(scannerChoice);

    // 1. Check emergency DISABLED switch
    if (cfg.disabled || config.isDisabled(paths)) {
        return {
            ok: false,
            verdict: 'unverified',
            reason: 'disabled',
            scanned: backendName,
            scans: 0,
            chunks: 0,
        };
    }

    // 2. Handle empty content
    if (text == null || String(text).trim().length === 0) {
        return {
            ok: true,
            verdict: 'clean',
            reason: 'empty',
            scanned: backendName,
            scans: 0,
            chunks: 0,
        };
    }

    // 3. Determine chunk parameters
    const chunkSize = options.chunkSize || (backendName === 'ollama' ? DEFAULT_OLLAMA_CHUNK_SIZE : DEFAULT_CLEF_CHUNK_SIZE);
    const overlap = options.overlap || (backendName === 'ollama' ? DEFAULT_OLLAMA_OVERLAP : DEFAULT_CLEF_OVERLAP);
    const chunks = splitChunks(text, chunkSize, overlap);
    const totalChunks = chunks.length;

    // 4. Budget check & reservation (for 'clef')
    const limitNeurons = Number.isFinite(options.dailyNeurons) ? options.dailyNeurons : cfg.dailyNeurons;
    let reservedOk = false;
    let upfrontError = null;
    let estNeurons = 0;

    if (backendName === 'clef') {
        estNeurons = chunks.reduce((acc, c) => acc + budget.estimateNeurons(c), 0);

        await budget.withLock(paths.lock, async () => {
            const b = budget.loadBudget(paths.budget, nowTime);
            if (b.corrupt) {
                upfrontError = {
                    ok: false,
                    verdict: 'unverified',
                    reason: 'corrupted_budget',
                    scanned: 'clef',
                    scans: 0,
                    chunks: totalChunks,
                };
                return;
            }

            const activeNeurons = (b.used || 0) + (b.reservedNeurons || 0);
            const remaining = Math.max(0, limitNeurons - activeNeurons);
            if (estNeurons > remaining || activeNeurons >= limitNeurons) {
                upfrontError = {
                    ok: false,
                    verdict: 'unverified',
                    reason: 'budget_exceeded',
                    scanned: 'clef',
                    scans: 0,
                    chunks: totalChunks,
                };
                return;
            }

            // Reserve allowance
            b.reservedScans = (b.reservedScans || 0) + totalChunks;
            b.reservedNeurons = (b.reservedNeurons || 0) + estNeurons;
            budget.saveBudget(paths.budget, b);
            reservedOk = true;
        });

        if (upfrontError) {
            return upfrontError;
        }
    }

    // 5. Execute scans with anonymized chunks
    let scansUsed = 0;
    let neuronsUsed = 0;
    let scanResult = null;

    try {
        if (backendName === 'none') {
            scanResult = await backend.scan(chunks, options);
        } else {
            // Anonymize chunks before sending to backend
            const anonymizedChunks = chunks.map(c => {
                if (options.anonymize === false) return c;
                return anonymizeModule.anonymize(c, { config: options.anonymizeFile || cfg.anonymizeFile });
            });

            // If backend mock or custom backend function is injected
            if (options.clefMock && backendName === 'clef') {
                for (let i = 0; i < anonymizedChunks.length; i++) {
                    scansUsed++;
                    const res = await options.clefMock(anonymizedChunks[i], { index: i, total: totalChunks });
                    const n = (res && Number.isFinite(res.neurons)) ? res.neurons : 35;
                    neuronsUsed += n;

                    if (!res || res.verdict !== 'clean' && res.verdict !== 'ok') {
                        const isQuarantine = res && (res.verdict === 'quarantine' || res.verdict === 'rejected');
                        scanResult = {
                            ok: false,
                            verdict: isQuarantine ? 'quarantine' : 'unverified',
                            reason: res && res.reason || 'flagged',
                            scanned: 'clef',
                        };
                        break;
                    }
                }
                if (!scanResult) {
                    scanResult = { ok: true, verdict: 'clean', scanned: 'clef' };
                }
            } else if (options.ollamaMock && backendName === 'ollama') {
                for (let i = 0; i < anonymizedChunks.length; i++) {
                    scansUsed++;
                    const res = await options.ollamaMock(anonymizedChunks[i], { index: i, total: totalChunks });
                    if (!res || res.verdict !== 'clean' && res.verdict !== 'ok') {
                        const isQuarantine = res && (res.verdict === 'quarantine' || res.verdict === 'rejected');
                        scanResult = {
                            ok: false,
                            verdict: isQuarantine ? 'quarantine' : 'unverified',
                            reason: res && res.reason || 'flagged',
                            scanned: 'ollama',
                        };
                        break;
                    }
                }
                if (!scanResult) {
                    scanResult = { ok: true, verdict: 'clean', scanned: 'ollama' };
                }
            } else {
                // Call real backend scan
                scanResult = await backend.scan(anonymizedChunks, {
                    ...options,
                    accountId: cfg.cfAccountId,
                    apiToken: cfg.cfApiToken,
                    apiBase: cfg.cfApiBase,
                    ollamaUrl: cfg.ollamaUrl,
                    model: cfg.ollamaModel,
                    timeoutMs: cfg.scanTimeoutMs,
                    scanTimeoutMs: cfg.scanTimeoutMs,
                });
                scansUsed = scanResult.scans || 0;
                neuronsUsed = scanResult.neurons || (scansUsed * 35);
            }
        }
    } finally {
        if (reservedOk) {
            await budget.withLock(paths.lock, async () => {
                const b = budget.loadBudget(paths.budget, nowTime);
                if (!b.corrupt) {
                    b.reservedScans = Math.max(0, (b.reservedScans || 0) - totalChunks);
                    b.reservedNeurons = Math.max(0, (b.reservedNeurons || 0) - estNeurons);
                    if (b.reservedScans === 0) delete b.reservedScans;
                    if (b.reservedNeurons === 0) delete b.reservedNeurons;
                    b.scans = (b.scans || 0) + scansUsed;
                    b.used = (b.used || 0) + neuronsUsed;
                    b.calls = (b.calls || 0) + 1;
                    budget.saveBudget(paths.budget, b);
                }
            });
        }
    }

    return {
        ok: scanResult.ok !== false && scanResult.verdict === 'clean',
        verdict: scanResult.verdict, // 'clean', 'quarantine', or 'unverified'
        score: typeof scanResult.score === 'number' ? scanResult.score : 0,
        reasons: Array.isArray(scanResult.reasons) ? scanResult.reasons : (scanResult.reason ? [scanResult.reason] : []),
        reason: scanResult.reason,
        backend: backendName,
        scanned: backendName,
        scans: scansUsed,
        chunks: totalChunks,
        warning: scanResult.warning,
    };
}

module.exports = {
    scanText,
    splitChunks,
    getBackend,
    DEFAULT_CLEF_CHUNK_SIZE,
    DEFAULT_CLEF_OVERLAP,
    DEFAULT_OLLAMA_CHUNK_SIZE,
    DEFAULT_OLLAMA_OVERLAP,
};
