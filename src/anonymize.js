'use strict';
/**
 * src/anonymize.js - Anonymization module for redacting sensitive data before cloud inspection.
 *
 * Provides:
 * - Built-in generic rules for private IPv4/IPv6 addresses, email addresses, and API credentials.
 * - Custom rules from JSON file (WEBREAD_ANONYMIZE_FILE) with literals and regex patterns.
 * - Comprehensive validation (schema bounds, regex syntax, ReDoS nested quantifier checks).
 * - Deterministic ordering (custom literals sorted by length descending, custom patterns, then built-in rules).
 */

const fs = require('node:fs');

const MAX_LITERALS = 100;
const MAX_PATTERNS = 50;
const MAX_LITERAL_LENGTH = 500;
const MAX_PATTERN_LENGTH = 200;
const MAX_REPLACE_LENGTH = 100;

// ReDoS heuristic: detect dangerous nested quantifiers such as (a+)+, (a*)*, (a|b+)+, (\d+)+
const NESTED_QUANTIFIER_RE = /(?:[+*]|\{\d+,?\d*\})\s*(?:[+*]|\{\d+,?\d*\})|\([^()]*[+*][^()]*\)\s*[+*]|\([^()]*\+\s*[^()]*\)\s*\+/;

// Built-in redaction rules
const BUILT_IN_RULES = [
    // Private IPv6 addresses (loopback, ULA fc00::/7, link-local fe80::/10, IPv4-mapped/SIIT private)
    {
        name: 'private_ipv6',
        regex: /(?<![0-9A-Za-z:])(?:::1|fe80:[0-9a-fA-F:]+|f[cd][0-9a-fA-F:]{2,}|::ffff:(?:0:)?(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)[0-9.]+)(?![0-9A-Za-z:])/gi,
        replace: '[IPV6_ADDRESS]',
    },
    // Private IPv4 ranges (RFC 1918, loopback 127/8, link-local 169.254/16, CGNAT 100.64/10)
    {
        name: 'private_ipv4',
        regex: /\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b/g,
        replace: '[IP_ADDRESS]',
    },
    // Email addresses
    {
        name: 'email',
        regex: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
        replace: '[EMAIL]',
    },
    // Common API tokens and authorization headers
    {
        name: 'api_tokens',
        regex: /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9a-zA-Z]{10,})\b/g,
        replace: '[API_TOKEN]',
    },
];

/**
 * Validates an anonymization configuration object.
 * Throws an Error with a clear explanation if invalid.
 * @param {object} config
 */
function validateConfig(config) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
        throw new Error('Anonymize configuration must be a JSON object with optional "literals" and "patterns" arrays');
    }

    const { literals = [], patterns = [] } = config;

    if (!Array.isArray(literals)) {
        throw new Error('Configuration property "literals" must be an array');
    }
    if (!Array.isArray(patterns)) {
        throw new Error('Configuration property "patterns" must be an array');
    }

    if (literals.length > MAX_LITERALS) {
        throw new Error(`Too many literals configured (${literals.length} > ${MAX_LITERALS})`);
    }
    if (patterns.length > MAX_PATTERNS) {
        throw new Error(`Too many patterns configured (${patterns.length} > ${MAX_PATTERNS})`);
    }

    for (let i = 0; i < literals.length; i++) {
        const item = literals[i];
        if (!item || typeof item !== 'object') {
            throw new Error(`Literal at index ${i} must be an object with "value" and "replace" properties`);
        }
        if (typeof item.value !== 'string' || item.value.length === 0) {
            throw new Error(`Literal at index ${i} has empty or non-string "value"`);
        }
        if (item.value.length > MAX_LITERAL_LENGTH) {
            throw new Error(`Literal at index ${i} value exceeds maximum length of ${MAX_LITERAL_LENGTH} characters`);
        }
        if (typeof item.replace !== 'string') {
            throw new Error(`Literal at index ${i} has non-string "replace"`);
        }
        if (item.replace.length > MAX_REPLACE_LENGTH) {
            throw new Error(`Literal at index ${i} replace exceeds maximum length of ${MAX_REPLACE_LENGTH} characters`);
        }
    }

    for (let i = 0; i < patterns.length; i++) {
        const item = patterns[i];
        if (!item || typeof item !== 'object') {
            throw new Error(`Pattern at index ${i} must be an object with "regex" and "replace" properties`);
        }
        if (typeof item.regex !== 'string' || item.regex.length === 0) {
            throw new Error(`Pattern at index ${i} has empty or non-string "regex"`);
        }
        if (item.regex.length > MAX_PATTERN_LENGTH) {
            throw new Error(`Pattern at index ${i} regex exceeds maximum length of ${MAX_PATTERN_LENGTH} characters`);
        }
        if (typeof item.replace !== 'string') {
            throw new Error(`Pattern at index ${i} has non-string "replace"`);
        }
        if (item.replace.length > MAX_REPLACE_LENGTH) {
            throw new Error(`Pattern at index ${i} replace exceeds maximum length of ${MAX_REPLACE_LENGTH} characters`);
        }

        // ReDoS check
        if (NESTED_QUANTIFIER_RE.test(item.regex)) {
            throw new Error(`Pattern at index ${i} contains potentially dangerous nested quantifiers (ReDoS risk): ${item.regex}`);
        }

        // Test regex compilation
        try {
            new RegExp(item.regex, item.flags || 'g');
        } catch (err) {
            throw new Error(`Invalid regular expression in pattern at index ${i} ("${item.regex}"): ${err.message}`);
        }
    }

    return true;
}

/**
 * Loads and validates an anonymization configuration file.
 * @param {string} filePath
 * @returns {object}
 */
function loadAnonymizeFile(filePath) {
    if (!filePath || typeof filePath !== 'string') {
        throw new Error('Anonymization file path must be a non-empty string');
    }

    let content;
    try {
        content = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        throw new Error(`Failed to read anonymization file at "${filePath}": ${err.message}`);
    }

    let parsed;
    try {
        parsed = JSON.parse(content);
    } catch (err) {
        throw new Error(`Failed to parse anonymization file at "${filePath}" as JSON: ${err.message}`);
    }

    validateConfig(parsed);
    return parsed;
}

/**
 * Escapes special regex characters in a literal string.
 */
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Applies anonymization rules to text.
 *
 * Order of execution:
 * 1. Custom literal replacements (longer strings first to avoid prefix collisions).
 * 2. Custom regex patterns.
 * 3. Built-in rules (IPs, emails, tokens).
 *
 * @param {string} text
 * @param {object} [options]
 * @param {object|string} [options.config] Custom config object or file path
 * @param {boolean} [options.skipBuiltIn=false]
 * @returns {string}
 */
function anonymize(text, options = {}) {
    if (text == null) return '';
    let result = String(text);

    let config = null;
    if (options.config) {
        if (typeof options.config === 'string') {
            config = loadAnonymizeFile(options.config);
        } else if (typeof options.config === 'object') {
            validateConfig(options.config);
            config = options.config;
        }
    } else if (process.env.WEBREAD_ANONYMIZE_FILE) {
        config = loadAnonymizeFile(process.env.WEBREAD_ANONYMIZE_FILE);
    }

    // 1. Custom literals
    if (config && Array.isArray(config.literals) && config.literals.length > 0) {
        // Sort by length descending
        const sortedLiterals = [...config.literals].sort((a, b) => b.value.length - a.value.length);
        for (const lit of sortedLiterals) {
            const flags = lit.caseInsensitive ? 'gi' : 'g';
            const re = new RegExp(escapeRegex(lit.value), flags);
            result = result.replace(re, () => lit.replace);
        }
    }

    // 2. Custom patterns
    if (config && Array.isArray(config.patterns) && config.patterns.length > 0) {
        for (const pat of config.patterns) {
            const flags = pat.flags || 'g';
            // Ensure global flag so all occurrences are replaced
            const finalFlags = flags.includes('g') ? flags : flags + 'g';
            const re = new RegExp(pat.regex, finalFlags);
            result = result.replace(re, () => pat.replace);
        }
    }

    // 3. Built-in rules
    if (!options.skipBuiltIn) {
        for (const rule of BUILT_IN_RULES) {
            result = result.replace(rule.regex, () => rule.replace);
        }
    }

    return result;
}

module.exports = {
    anonymize,
    loadAnonymizeFile,
    validateConfig,
    BUILT_IN_RULES,
    MAX_LITERALS,
    MAX_PATTERNS,
    MAX_LITERAL_LENGTH,
    MAX_PATTERN_LENGTH,
    MAX_REPLACE_LENGTH,
};
