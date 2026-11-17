'use strict';
/**
 * src/budget.js - Daily budget tracking, neuron estimation, and atomic file locking.
 *
 * Provides:
 * - Atomic file locking via linkSync with PID verification and stale lock cleanup.
 * - Daily budget persistence (resets automatically at midnight UTC).
 * - Up-front budget reservation before queries, preventing concurrent race conditions.
 * - Fail-closed handling for corrupted budget files or exhausted allowances.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const NEURONS_PER_1K = 21.8182;
const DEFAULT_DAILY_NEURONS = 2000;

const sleepMs = ms => new Promise(r => setTimeout(r, ms));

function isPidDead(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return true;
    try {
        process.kill(pid, 0);
        return false;
    } catch (e) {
        return e.code === 'ESRCH';
    }
}

/**
 * Runs an asynchronous function under a filesystem-based lock.
 * Uses atomic hard link creation (`fs.linkSync`) to guarantee mutual exclusion.
 * Detects stale locks (abandoned by killed PIDs or older than 30s).
 *
 * @param {string} lockPath
 * @param {Function} fn
 * @returns {Promise<any>}
 */
async function withLock(lockPath, fn) {
    const dir = path.dirname(lockPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    // Clean up abandoned temp files older than 60s
    try {
        const files = fs.readdirSync(dir);
        const now = Date.now();
        for (const f of files) {
            if (/^.*\.lock\..*\.tmp$/.test(f)) {
                try {
                    const stTmp = fs.statSync(path.join(dir, f));
                    if (now - stTmp.mtimeMs > 60000) {
                        fs.unlinkSync(path.join(dir, f));
                    }
                } catch (_) {}
            }
        }
    } catch (_) {}

    const deadline = Date.now() + 10000;
    let myIno = null;

    for (;;) {
        let tmp = null;
        try {
            tmp = `${lockPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
            fs.writeFileSync(tmp, `${process.pid}\n`, { mode: 0o600 });
            const stTmp = fs.statSync(tmp);
            fs.linkSync(tmp, lockPath);
            myIno = stTmp.ino;
            try { fs.unlinkSync(tmp); } catch (_) {}
            break;
        } catch (e) {
            if (tmp) {
                try { fs.unlinkSync(tmp); } catch (_) {}
            }
            if (e.code !== 'EEXIST') throw e;

            let stale = false;
            let st = null;
            try {
                st = fs.statSync(lockPath);
                if (st.isDirectory()) throw new Error('Lock path is a directory');
                const raw = fs.readFileSync(lockPath, 'utf8').trim();
                const pid = parseInt(raw, 10);
                const age = Date.now() - st.mtimeMs;
                if (age > 30000 || (age >= 1000 && isPidDead(pid))) {
                    stale = true;
                }
            } catch (e2) {
                if (e2.message === 'Lock path is a directory') throw e2;
                if (Date.now() >= deadline) throw new Error('Lock acquisition timeout');
                await sleepMs(10 + Math.floor(Math.random() * 20));
                continue;
            }

            if (stale && st) {
                try {
                    if (fs.statSync(lockPath).ino === st.ino) {
                        fs.unlinkSync(lockPath);
                    }
                } catch (_) {}
            }
            if (Date.now() >= deadline) throw new Error('Lock acquisition timeout');
            await sleepMs(10 + Math.floor(Math.random() * 20));
        }
    }

    try {
        return await fn();
    } finally {
        try {
            const st = fs.statSync(lockPath);
            if (st.ino === myIno) {
                fs.unlinkSync(lockPath);
            }
        } catch (_) {}
    }
}

function todayKey(nowMs) {
    const d = nowMs ? new Date(nowMs) : new Date();
    return d.toISOString().slice(0, 10);
}

/**
 * Loads the current daily budget.
 * Automatically resets counters on day rollover.
 * Fail-closed: returns corrupt: true on malformed JSON.
 */
function loadBudget(budgetPath, nowMs) {
    const day = todayKey(nowMs);
    try {
        if (!fs.existsSync(budgetPath)) {
            return { day, used: 0, scans: 0, calls: 0, reservedScans: 0, reservedNeurons: 0 };
        }
        const raw = fs.readFileSync(budgetPath, 'utf8');
        const data = JSON.parse(raw);
        if (!data || typeof data !== 'object' || Array.isArray(data)) {
            return { error: 'corrupt_budget', corrupt: true };
        }
        if (data.day !== day) {
            return { day, used: 0, scans: 0, calls: 0, reservedScans: 0, reservedNeurons: 0 };
        }
        return {
            day: data.day,
            used: Number.isFinite(data.used) ? data.used : 0,
            scans: Number.isFinite(data.scans) ? data.scans : 0,
            calls: Number.isFinite(data.calls) ? data.calls : 0,
            reservedScans: Number.isFinite(data.reservedScans) ? data.reservedScans : 0,
            reservedNeurons: Number.isFinite(data.reservedNeurons) ? data.reservedNeurons : 0,
        };
    } catch (_) {
        return { error: 'corrupt_budget', corrupt: true };
    }
}

/**
 * Saves the budget object atomically via temporary file and rename.
 */
function saveBudget(budgetPath, budget) {
    const dir = path.dirname(budgetPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${budgetPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(budget, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, budgetPath);
}

/**
 * Estimates Cloudflare Workers AI neurons required for a prompt text.
 */
function estimateNeurons(stateText) {
    const bytes = Buffer.byteLength(String(stateText || ''), 'utf8');
    return Math.ceil((bytes / 2.8 + 500) * NEURONS_PER_1K / 1000);
}

module.exports = {
    withLock,
    loadBudget,
    saveBudget,
    estimateNeurons,
    todayKey,
    DEFAULT_DAILY_NEURONS,
    NEURONS_PER_1K,
};
