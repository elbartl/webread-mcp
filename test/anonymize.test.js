'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const anonymizeModule = require('../src/anonymize.js');

function createTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-anon-test-'));
}

test('anonymize: built-in rules redact private IPs, emails, and tokens', () => {
    const input = 'Contact admin@example.org or visit http://10.0.0.5 or token sk-1234567890abcdef1234567890';
    const output = anonymizeModule.anonymize(input);

    assert.ok(!output.includes('admin@example.org'));
    assert.ok(output.includes('[EMAIL]'));

    assert.ok(!output.includes('10.0.0.5'));
    assert.ok(output.includes('[IP_ADDRESS]'));
    assert.equal(anonymizeModule.anonymize(['192', '168', '0', '10'].join('.')), '[IP_ADDRESS]');

    assert.ok(!output.includes('sk-1234567890abcdef1234567890'));
    assert.ok(output.includes('[API_TOKEN]'));
});

test('anonymize: custom literals sort by length descending to prevent substring collisions', () => {
    const config = {
        literals: [
            { value: 'John', replace: '[FIRST_NAME]' },
            { value: 'John Doe', replace: '[FULL_NAME]' },
        ],
    };

    const input = 'The user is John Doe in our department.';
    const output = anonymizeModule.anonymize(input, { config });

    // "John Doe" must match first as [FULL_NAME], not [FIRST_NAME] Doe
    assert.equal(output, 'The user is [FULL_NAME] in our department.');
});

test('anonymize: custom patterns regex replacements work properly', () => {
    const config = {
        patterns: [
            { regex: '\\bID-\\d{4}\\b', flags: 'g', replace: '[USER_ID]' },
        ],
    };

    const input = 'Assigned to ID-4421 and ID-9988 for review.';
    const output = anonymizeModule.anonymize(input, { config });

    assert.equal(output, 'Assigned to [USER_ID] and [USER_ID] for review.');
});

test('anonymize: validation rejects invalid regex syntax', () => {
    const config = {
        patterns: [
            { regex: '[unclosed bracket', replace: '[BAD]' },
        ],
    };

    assert.throws(() => {
        anonymizeModule.validateConfig(config);
    }, /Invalid regular expression/);
});

test('anonymize: validation rejects ReDoS nested quantifiers', () => {
    const config = {
        patterns: [
            { regex: '(a+)+', replace: '[REDOS]' },
        ],
    };

    assert.throws(() => {
        anonymizeModule.validateConfig(config);
    }, /dangerous nested quantifiers/);
});

test('anonymize: loadAnonymizeFile throws clear error on missing or malformed file', () => {
    assert.throws(() => {
        anonymizeModule.loadAnonymizeFile('/non/existent/path/rules.json');
    }, /Failed to read anonymization file/);

    const dir = createTmpDir();
    const brokenJson = path.join(dir, 'broken.json');
    fs.writeFileSync(brokenJson, '{ not valid json');

    assert.throws(() => {
        anonymizeModule.loadAnonymizeFile(brokenJson);
    }, /Failed to parse anonymization file/);
});

test('anonymize: validation enforces count and length limits', () => {
    const tooManyLiterals = {
        literals: Array.from({ length: anonymizeModule.MAX_LITERALS + 1 }, (_, i) => ({
            value: `val${i}`,
            replace: '[X]',
        })),
    };
    assert.throws(() => anonymizeModule.validateConfig(tooManyLiterals), /Too many literals/);

    const tooLongPattern = {
        patterns: [
            { regex: 'a'.repeat(anonymizeModule.MAX_PATTERN_LENGTH + 1), replace: '[X]' },
        ],
    };
    assert.throws(() => anonymizeModule.validateConfig(tooLongPattern), /exceeds maximum length/);
});
