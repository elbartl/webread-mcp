'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_SCANNER = 'clef';
const VALID_SCANNERS = Object.freeze(['clef', 'ollama', 'none']);

function validateScanner(scanner) {
    if (scanner == null || scanner === '') {
        return DEFAULT_SCANNER;
    }
    const norm = String(scanner).toLowerCase().trim();
    if (!VALID_SCANNERS.includes(norm)) {
        throw new Error(`Invalid or unsupported WEBREAD_SCANNER: "${scanner}". Valid options: ${VALID_SCANNERS.join(', ')}`);
    }
    return norm;
}
const DEFAULT_OLLAMA_URL = 'http://127.0.0.1:11434';
const DEFAULT_OLLAMA_MODEL = 'qwen3:4b';
const DEFAULT_DAILY_NEURONS = 2000;
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_SCAN_TIMEOUT_CLEF_MS = 20000;
const DEFAULT_SCAN_TIMEOUT_OLLAMA_MS = 90000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024; // 2 MB
const DEFAULT_MAX_CHARS = 60000;

function validateScanTimeoutMs(val, scanner) {
    if (val === undefined || val === null || val === '') {
        return scanner === 'ollama' ? DEFAULT_SCAN_TIMEOUT_OLLAMA_MS : DEFAULT_SCAN_TIMEOUT_CLEF_MS;
    }
    const num = Number(val);
    if (!Number.isFinite(num) || num <= 0) {
        throw new Error(`Invalid WEBREAD_SCAN_TIMEOUT_MS: "${val}". Must be a positive number.`);
    }
    return num;
}

function resolveHome() {
    return process.env.HOME || os.homedir();
}

function getPaths(customStateDir) {
    const home = resolveHome();
    const stateDir = customStateDir || process.env.WEBREAD_STATE_DIR || path.join(home, '.local', 'state', 'webread');
    return {
        stateDir,
        budget: path.join(stateDir, 'budget.json'),
        lock: path.join(stateDir, 'budget.lock'),
        key: path.join(stateDir, 'webread.key'),
        quarantineDir: path.join(stateDir, 'quarantine'),
        log: path.join(stateDir, 'log.jsonl'),
        disabled: path.join(stateDir, 'DISABLED'),
    };
}

function isDisabled(paths) {
    if (process.env.WEBREAD_DISABLED === '1') {
        return true;
    }
    const p = paths || getPaths();
    return fs.existsSync(p.disabled);
}

function getConfig(overrides = {}) {
    const paths = getPaths(overrides.stateDir);
    const rawScanner = (overrides.scanner != null && overrides.scanner !== '') ? overrides.scanner : (process.env.WEBREAD_SCANNER || DEFAULT_SCANNER);
    const scanner = validateScanner(rawScanner);

    const cfAccountId = overrides.cfAccountId || process.env.CF_ACCOUNT_ID || process.env.CLOUDFLARE_ACCOUNT_ID || '';
    const cfApiToken = overrides.cfApiToken || process.env.CF_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN || '';
    const cfApiBase = overrides.cfApiBase || process.env.WEBREAD_CLEF_API_BASE || process.env.CF_API_BASE || 'https://api.cloudflare.com';

    const ollamaUrl = overrides.ollamaUrl || process.env.WEBREAD_OLLAMA_URL || process.env.OLLAMA_URL || DEFAULT_OLLAMA_URL;
    const ollamaModel = overrides.ollamaModel || process.env.WEBREAD_OLLAMA_MODEL || DEFAULT_OLLAMA_MODEL;

    const dailyNeuronsRaw = overrides.dailyNeurons !== undefined ? overrides.dailyNeurons : process.env.WEBREAD_DAILY_NEURONS;
    const dailyNeurons = Number.isFinite(Number(dailyNeuronsRaw)) ? Number(dailyNeuronsRaw) : DEFAULT_DAILY_NEURONS;

    const timeoutMsRaw = overrides.timeoutMs !== undefined ? overrides.timeoutMs : process.env.WEBREAD_TIMEOUT_MS;
    const timeoutMs = Number.isFinite(Number(timeoutMsRaw)) ? Number(timeoutMsRaw) : DEFAULT_TIMEOUT_MS;

    const scanTimeoutRaw = overrides.scanTimeoutMs !== undefined ? overrides.scanTimeoutMs : process.env.WEBREAD_SCAN_TIMEOUT_MS;
    const scanTimeoutMs = validateScanTimeoutMs(scanTimeoutRaw, scanner);

    const maxCharsRaw = overrides.maxChars !== undefined ? overrides.maxChars : process.env.WEBREAD_MAX_CHARS;
    const maxChars = Number.isFinite(Number(maxCharsRaw)) ? Number(maxCharsRaw) : DEFAULT_MAX_CHARS;

    const anonymizeFile = overrides.anonymizeFile || process.env.WEBREAD_ANONYMIZE_FILE || null;

    return {
        paths,
        scanner,
        cfAccountId,
        cfApiToken,
        cfApiBase,
        ollamaUrl,
        ollamaModel,
        dailyNeurons,
        timeoutMs,
        scanTimeoutMs,
        maxRedirects: overrides.maxRedirects || DEFAULT_MAX_REDIRECTS,
        maxBytes: overrides.maxBytes || DEFAULT_MAX_BYTES,
        maxChars,
        anonymizeFile,
        disabled: isDisabled(paths),
    };
}

module.exports = {
    DEFAULT_SCANNER,
    VALID_SCANNERS,
    validateScanner,
    DEFAULT_OLLAMA_URL,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_DAILY_NEURONS,
    DEFAULT_TIMEOUT_MS,
    DEFAULT_SCAN_TIMEOUT_CLEF_MS,
    DEFAULT_SCAN_TIMEOUT_OLLAMA_MS,
    validateScanTimeoutMs,
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_CHARS,
    getPaths,
    isDisabled,
    getConfig,
    resolveHome,
};
