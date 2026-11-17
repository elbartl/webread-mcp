'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { htmlToText } = require('../src/extract');
const { anonymize } = require('../src/anonymize');

describe('ReDoS protection (< 500 ms per 100k chars input)', () => {
    const htmlInputs = [
        { name: 'unclosed doctype', input: '<!doctype ' + 'a'.repeat(100000) },
        { name: 'repeated processing instructions', input: '<?'.repeat(50000) },
        { name: 'repeated unclosed comments', input: '<!--'.repeat(25000) },
        { name: 'unclosed tag', input: '<' + 'a'.repeat(100000) },
    ];

    for (const { name, input } of htmlInputs) {
        it(`htmlToText handles ${name} in < 500ms`, () => {
            const start = performance.now();
            htmlToText(input);
            const elapsed = performance.now() - start;
            assert.ok(elapsed < 500, `htmlToText(${name}) took ${elapsed.toFixed(1)}ms (limit 500ms)`);
        });
    }

    const anonymizeInputs = [
        { name: 'repeated a@', input: 'a@'.repeat(50000) },
        { name: 'repeated 1.', input: '1.'.repeat(50000) },
        { name: 'repeated :', input: ':'.repeat(100000) },
        { name: 'repeated f:', input: 'f:'.repeat(50000) },
    ];

    for (const { name, input } of anonymizeInputs) {
        it(`anonymize handles ${name} in < 500ms`, () => {
            const start = performance.now();
            anonymize(input);
            const elapsed = performance.now() - start;
            assert.ok(elapsed < 500, `anonymize(${name}) took ${elapsed.toFixed(1)}ms (limit 500ms)`);
        });
    }

    const largeHtmlInputs = [
        { name: '<a .repeat(666667)', input: '<a '.repeat(666667) },
        { name: '<!doctype [ + a.repeat(2e6)', input: '<!doctype [' + 'a'.repeat(2e6) },
        { name: '<!doctype [<!ENTITY x>.repeat(90000)', input: '<!doctype [<!ENTITY x>'.repeat(90000) },
        { name: '<div>.repeat(4e5)', input: '<div>'.repeat(4e5) },
        { name: '<a href="x">.repeat(1.6e5)', input: '<a href="x">'.repeat(1.6e5) },
        { name: '2 MB flat <a href="x">t</a>', input: '<a href="x">t</a>'.repeat(120000) },
        { name: '2 MB nested <a href="x">', input: '<a href="https://example.com/item">'.repeat(50000) + 'text' + '</a>'.repeat(50000) },
        { name: '<y.repeat(500000)', input: '<y'.repeat(500000) },
        { name: 'x<y .repeat(400000)', input: 'x<y '.repeat(400000) },
        { name: '<td>.repeat(500000)', input: '<td>'.repeat(500000) },
        { name: '<table><tr><td>.repeat(130000)', input: '<table><tr><td>'.repeat(130000) },
        { name: '<tr><td>x.repeat(200000)', input: '<tr><td>x'.repeat(200000) },
        { name: '<div>.repeat(200000) + </span>.repeat(200000)', input: '<div>'.repeat(200000) + '</span>'.repeat(200000) },
        { name: '<a href="x"> .repeat(150000) + t + </a>.repeat(150000)', input: '<a href="x"> '.repeat(150000) + 't' + '</a>'.repeat(150000) },
        { name: '<a href="x"> .repeat(70000) + </a>.repeat(70000) + <title>t</title>.repeat(70000)', input: '<a href="x"> '.repeat(70000) + '</a>'.repeat(70000) + '<title>t</title>'.repeat(70000) },
        { name: '<b>x.repeat(250000) + </b>.repeat(250000)', input: '<b>x'.repeat(250000) + '</b>'.repeat(250000) },
        { name: '<div hidden>.repeat(200000) + x + </div>.repeat(200000)', input: '<div hidden>'.repeat(200000) + 'x' + '</div>'.repeat(200000) },
    ];

    for (const { name, input } of largeHtmlInputs) {
        it(`htmlToText handles 2 MB ${name} in < 2000ms`, () => {
            const start = performance.now();
            htmlToText(input);
            const elapsed = performance.now() - start;
            assert.ok(elapsed < 2000, `htmlToText(${name}) took ${elapsed.toFixed(1)}ms (limit 2000ms)`);
        });
    }

    it('htmlToText deadlineMs triggers extraction_timeout on expired deadline (deadlineMs: 0 or 1)', () => {
        const largeHtml = '<p>paragraph content</p>'.repeat(5000);
        const resZero = htmlToText(largeHtml, { deadlineMs: 0 });
        assert.equal(resZero.ok, false);
        assert.equal(resZero.error, 'extraction_timeout');
        assert.equal(resZero.reason, 'extraction_timeout');

        const hugeHtml = '<p>paragraph content</p>'.repeat(20000);
        const resOne = htmlToText(hugeHtml, { deadlineMs: 1 });
        assert.equal(resOne.ok, false);
        assert.equal(resOne.error, 'extraction_timeout');
        assert.equal(resOne.reason, 'extraction_timeout');
    });

    it('htmlToText depth > 256 does not leak hidden text and table formatting remains correct', () => {
        // Hidden text inside nested elements beyond MAX_STACK_DEPTH (256) remains hidden (fail-closed)
        const hiddenNested = '<div style="display:none">' + '<span>'.repeat(300) + 'SECRET' + '</span>'.repeat(300) + '</div>';
        const resHidden = htmlToText(hiddenNested);
        assert.equal(resHidden.ok, true);
        assert.ok(!resHidden.text.includes('SECRET'), 'Hidden content at depth > 256 must not leak into extracted text');

        // Normal 2 rows x 3 cells table extracts 'a | b | c' and 'd | e | f'
        const tableHtml = '<table><tr><td>a</td><td>b</td><td>c</td></tr><tr><td>d</td><td>e</td><td>f</td></tr></table>';
        const resTable = htmlToText(tableHtml);
        assert.equal(resTable.ok, true);
        assert.ok(resTable.text.includes('a | b | c'));
        assert.ok(resTable.text.includes('d | e | f'));
    });

    it('htmlToText depth > 256 properly strips hidden content and preserves visible text', () => {
        // (1) Hidden tags beyond MAX_STACK_DEPTH (256)
        const html1a = '<div>'.repeat(260) + '<p>Visible</p><div style="display:none">SECRET1</div>';
        const res1a = htmlToText(html1a);
        assert.equal(res1a.ok, true);
        assert.ok(!res1a.text.includes('SECRET1'));
        assert.ok(res1a.text.includes('Visible'));

        const html1b = '<div>'.repeat(260) + '<p>Visible</p><span hidden>SECRET2</span>';
        const res1b = htmlToText(html1b);
        assert.equal(res1b.ok, true);
        assert.ok(!res1b.text.includes('SECRET2'));
        assert.ok(res1b.text.includes('Visible'));

        const html1c = '<div>'.repeat(260) + '<p>Visible</p><p aria-hidden="true">SECRET6</p>';
        const res1c = htmlToText(html1c);
        assert.equal(res1c.ok, true);
        assert.ok(!res1c.text.includes('SECRET6'));
        assert.ok(res1c.text.includes('Visible'));

        // (2) Hidden parent with nested elements exceeding MAX_STACK_DEPTH and closing tags
        const html2 = '<p>Visible</p><div style="display:none">' + '<div>'.repeat(300) + 'x' + '</div>'.repeat(256) + 'SECRET8' + '</div>'.repeat(45) + '<p>after</p>';
        const res2 = htmlToText(html2);
        assert.equal(res2.ok, true);
        assert.ok(!res2.text.includes('SECRET8'));
        assert.ok(!res2.text.includes('x'));
        assert.ok(res2.text.includes('Visible'));
        assert.ok(res2.text.includes('after'));

        // Normal nesting beyond 256 with open/close sequence
        const html3 = '<div>'.repeat(300) + '<p>a</p>' + '</div>'.repeat(300) + '<p>b</p>';
        const res3 = htmlToText(html3);
        assert.equal(res3.ok, true);
        assert.ok(res3.text.includes('a'));
        assert.ok(res3.text.includes('b'));

        // Raw content tags beyond 256
        const html4a = '<div>'.repeat(260) + '<script>SECRET3()</script>ok';
        const res4a = htmlToText(html4a);
        assert.equal(res4a.ok, true);
        assert.ok(!res4a.text.includes('SECRET3'));
        assert.ok(res4a.text.includes('ok'));

        const html4b = '<div>'.repeat(260) + '<style>.x{SECRET4}</style>ok';
        const res4b = htmlToText(html4b);
        assert.equal(res4b.ok, true);
        assert.ok(!res4b.text.includes('SECRET4'));
        assert.ok(res4b.text.includes('ok'));
    });

    it('htmlToText returns nesting_too_deep fail-closed when overflowDepth exceeds 100000', () => {
        const deepHtml = '<div>'.repeat(100300) + 'text' + '</div>'.repeat(100300);
        const res = htmlToText(deepHtml);
        assert.equal(res.ok, false);
        assert.equal(res.error, 'nesting_too_deep');
        assert.equal(res.reason, 'nesting_too_deep');
    });

    it('htmlToText overflow zone: mismatched closing tags do not leak hidden content', () => {
        const singleClosers = ['</span>', '</p>', '</br>', '</x>'];
        for (const closer of singleClosers) {
            const html = '<div>'.repeat(256) + '<div style="display:none">' + closer + 'SECRET';
            const res = htmlToText(html);
            assert.equal(res.ok, true);
            assert.ok(!res.text.includes('SECRET'), `Closer ${closer} must not leak hidden content`);
        }

        // Out-of-order '</div></span>' with nested element inside hidden div
        const htmlNestedSpan = '<div>'.repeat(256) + '<div style="display:none"><span>' + '</div></span>' + 'SECRET';
        const resNestedSpan = htmlToText(htmlNestedSpan);
        assert.equal(resNestedSpan.ok, true);
        assert.ok(!resNestedSpan.text.includes('SECRET'), "Out-of-order '</div></span>' must not leak hidden content");

        const htmlNestedDiv = '<div>'.repeat(256) + '<div style="display:none"><div>' + '</div></span>' + 'SECRET';
        const resNestedDiv = htmlToText(htmlNestedDiv);
        assert.equal(resNestedDiv.ok, true);
        assert.ok(!resNestedDiv.text.includes('SECRET'), "Nested div with '</div></span>' must not leak hidden content");
    });

    it('htmlToText overflow zone: proper closing tag reveals subsequent visible text', () => {
        const html = '<div>'.repeat(300) + '<div hidden>HIDDEN</div>' + 'VISIBLE' + '</div>'.repeat(300);
        const res = htmlToText(html);
        assert.equal(res.ok, true);
        assert.ok(res.text.includes('VISIBLE'), 'Visible text after properly closed hidden div must be included');
        assert.ok(!res.text.includes('HIDDEN'), 'Hidden text must not be included');
    });

    it('htmlToText overflow zone performance: adversarial alternating tags and void closers process in < 1000ms', () => {
        const t0 = performance.now();
        const res1 = htmlToText('<div>'.repeat(256) + ('<span></b>'.repeat(100000)) + 'x');
        const dt1 = performance.now() - t0;
        assert.equal(res1.ok, true);
        assert.ok(dt1 < 1000, `Alternating tags took ${dt1.toFixed(1)}ms >= 1000ms`);

        const t1 = performance.now();
        const res2 = htmlToText('<div>'.repeat(256) + '<div hidden>' + '</p>'.repeat(200000) + 'SECRET');
        const dt2 = performance.now() - t1;
        assert.equal(res2.ok, true);
        assert.ok(dt2 < 1000, `Repeated closers took ${dt2.toFixed(1)}ms >= 1000ms`);
        assert.ok(!res2.text.includes('SECRET'), 'Repeated mismatched closers in overflow zone must not leak SECRET');
    });
});
