'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const budget = require('../src/budget.js');
const scan = require('../src/scan.js');

function createTmpDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'webread-budget-test-'));
}

test('budget: withLock ensures mutual exclusion under concurrency', async () => {
    const dir = createTmpDir();
    const lockPath = path.join(dir, 'test.lock');

    let counter = 0;
    const task = async () => {
        await budget.withLock(lockPath, async () => {
            const current = counter;
            await new Promise(r => setTimeout(r, 10));
            counter = current + 1;
        });
    };

    // Run 5 concurrent lock acquisitions
    await Promise.all([task(), task(), task(), task(), task()]);
    assert.equal(counter, 5);
    assert.equal(fs.existsSync(lockPath), false);
});

test('budget: loadBudget resets on day change', () => {
    const dir = createTmpDir();
    const budgetPath = path.join(dir, 'budget.json');

    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    fs.writeFileSync(budgetPath, JSON.stringify({
        day: yesterday,
        used: 1500,
        scans: 40,
        calls: 20,
    }));

    const loaded = budget.loadBudget(budgetPath);
    const today = new Date().toISOString().slice(0, 10);
    assert.equal(loaded.day, today);
    assert.equal(loaded.used, 0);
    assert.equal(loaded.scans, 0);
    assert.equal(loaded.calls, 0);
});

test('budget: corrupted budget file returns corrupt: true (fail-closed)', () => {
    const dir = createTmpDir();
    const budgetPath = path.join(dir, 'budget.json');

    // Invalid JSON
    fs.writeFileSync(budgetPath, '{ "day": "2026-11-17", broken json');
    const loaded = budget.loadBudget(budgetPath);
    assert.equal(loaded.corrupt, true);
});

test('budget: scanText halts with unverified when daily budget is exceeded', async () => {
    const dir = createTmpDir();
    const budgetPath = path.join(dir, 'budget.json');
    const today = new Date().toISOString().slice(0, 10);

    // Save budget with limit reached
    fs.writeFileSync(budgetPath, JSON.stringify({
        day: today,
        used: 2000,
        scans: 50,
        calls: 25,
    }));

    const mockFetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({
            result: {
                answers: {
                    injection: { probabilities: { injection: 0.01 } },
                    hijack: { probabilities: { hijack: 0.01 } },
                },
                usage: { input_tokens: 100 },
            },
        }),
    });

    const res = await scan.scanText('Normal content', {
        stateDir: dir,
        scanner: 'clef',
        dailyNeurons: 2000,
        fetchImpl: mockFetch,
    });

    assert.equal(res.ok, false);
    assert.equal(res.verdict, 'unverified');
    assert.equal(res.reason, 'budget_exceeded');
});

test('budget: scanText halts with unverified on corrupted budget file', async () => {
    const dir = createTmpDir();
    const budgetPath = path.join(dir, 'budget.json');
    fs.writeFileSync(budgetPath, 'invalid json content');

    const res = await scan.scanText('Normal content', {
        stateDir: dir,
        scanner: 'clef',
        dailyNeurons: 2000,
    });

    assert.equal(res.ok, false);
    assert.equal(res.verdict, 'unverified');
    assert.equal(res.reason, 'corrupted_budget');
});
