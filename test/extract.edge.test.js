'use strict';
/**
 * test/extract.edge.test.js
 * Adversarial and edge-case test suite for HTML content extraction and invisible content stripping.
 */
const test = require('node:test');
const assert = require('node:assert');
const { htmlToText, extractContent, cleanInvisibleChars, decodeEntities } = require('../src/extract.js');

test('Extract edge: standard CSS and HTML text hiding variants', () => {
    // hidden attribute uppercase
    const r1 = htmlToText('<div HIDDEN>hidden text</div><p>visible</p>');
    assert.strictEqual(r1.text, 'visible');
    assert.strictEqual(r1.hiddenCount, 1);

    // aria-hidden="true"
    const r2 = htmlToText('<div aria-hidden="true">hidden aria</div><p>visible</p>');
    assert.strictEqual(r2.text, 'visible');

    // display:none uppercase
    const r3 = htmlToText('<div style="DISPLAY: NONE">hidden display</div><p>visible</p>');
    assert.strictEqual(r3.text, 'visible');

    // visibility:collapse
    const r4 = htmlToText('<div style="visibility: collapse">hidden collapse</div><p>visible</p>');
    assert.strictEqual(r4.text, 'visible');

    // font-size: 0px / opacity: 0
    const r5 = htmlToText('<span style="font-size: 0px">zero font</span><span style="opacity: 0">zero opacity</span><p>visible</p>');
    assert.strictEqual(r5.text, 'visible');

    // off-screen text-indent
    const r6 = htmlToText('<div style="text-indent: -9999px">offscreen</div><p>visible</p>');
    assert.strictEqual(r6.text, 'visible');
});

test('Extract edge: HTML entities in attributes bypass hidden content detector', () => {
    // Hex entity in style (e.g. display&#x3a;none)
    const rHex = htmlToText('<div style="display&#x3a;none">hidden via hex entity</div><p>visible</p>');
    assert.strictEqual(rHex.text, 'visible', 'display&#x3a;none must not leak to visible text');

    // Named entity &colon;
    const rNamed = htmlToText('<div style="display&colon;none">hidden via colon entity</div><p>visible</p>');
    assert.strictEqual(rNamed.text, 'visible', 'display&colon;none must not leak to visible text');

    // Entity in attribute name (e.g. &#104;idden)
    const rAttr = htmlToText('<div &#104;idden>hidden via entity in attribute name</div><p>visible</p>');
    assert.strictEqual(rAttr.text, 'visible', '&#104;idden must not leak to visible text');
});

test('Extract edge: Unicode Plane 14 tag characters (invisible LLM instructions)', () => {
    // Unicode Plane 14 Tag Characters (U+E0001, U+E0020-U+E007E) used for hidden prompt injection
    const tagPayload = 'Visible text \u{E0001}\u{E0020}\u{E0041}\u{E0042}\u{E0043} end';
    const cleaned = cleanInvisibleChars(tagPayload);
    assert.strictEqual(cleaned.text, 'Visible text  end', 'Tag characters U+E0000-U+E007F must be stripped');
    assert.ok(cleaned.count >= 4, 'Removed invisible characters count must increase');
});

test('Extract edge: table structure preservation, code, lists, and links with baseUrl', () => {
    const html = `
        <table>
            <tr><th>Header 1</th><th>Header 2</th></tr>
            <tr><td>Data A</td><td>Data B</td></tr>
        </table>
        <ul>
            <li>Item 1</li>
            <li>Item 2</li>
        </ul>
        <pre><code>const a = 1; &amp;&amp; const b = 2;</code></pre>
        <p><a href="/docs/api">Documentation</a></p>
    `;
    const res = htmlToText(html, { baseUrl: 'https://docs.example.com/v1/' });
    assert.strictEqual(res.ok, true);
    assert.ok(res.text.includes('Header 1 | Header 2'));
    assert.ok(res.text.includes('Data A | Data B'));
    assert.ok(res.text.includes('- Item 1'));
    assert.ok(res.text.includes('const a = 1; && const b = 2;'));
    assert.ok(res.text.includes('Documentation (https://docs.example.com/docs/api)'));
});

test('Extract edge: unclosed and nested HTML elements', () => {
    // Unwinding nested and crossed unclosed tags
    const html = '<div><span style="display:none"><b>hidden</span>visible</b></div>';
    const res = htmlToText(html);
    assert.strictEqual(res.ok, true);
    assert.strictEqual(res.text, 'visible');

    // Child of hidden element cannot unmask itself
    const nestedHtml = '<div style="display:none"><div style="display:block">still hidden</div></div><p>visible</p>';
    const resNested = htmlToText(nestedHtml);
    assert.strictEqual(resNested.ok, true);
    assert.strictEqual(resNested.text, 'visible');
});

test('Extract edge: hard character limit (fail-closed, no silent truncation)', () => {
    const longHtml = '<p>' + 'X'.repeat(60001) + '</p>';
    const res = htmlToText(longHtml, { maxChars: 60000 });
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.reason, 'too_long');
    assert.strictEqual(res.text, undefined, 'Truncated text must not be returned upon exceeding limit');
});

test('Extract edge: RAW tag variants (unclosed script, STYLE, type=module, svg, template, comment with script)', () => {
    // 1. Unclosed <script> in middle of text: text before remains, nothing from inside leaks
    const rUnclosed = htmlToText('Visible text before <script> alert("secret payload injection");');
    assert.strictEqual(rUnclosed.ok, true);
    assert.strictEqual(rUnclosed.text, 'Visible text before');
    assert.strictEqual(rUnclosed.text.includes('secret payload'), false);

    // 2. <STYLE> uppercase
    const rStyle = htmlToText('Heading <STYLE> body { background: red; } </STYLE> Article body');
    assert.strictEqual(rStyle.ok, true);
    assert.strictEqual(rStyle.text, 'Heading Article body');
    assert.strictEqual(rStyle.text.includes('background'), false);

    // 3. <script type=module>
    const rModule = htmlToText('Text A <script type="module"> import { inject } from "./exploit.js"; </script> Text B');
    assert.strictEqual(rModule.ok, true);
    assert.strictEqual(rModule.text, 'Text A Text B');
    assert.strictEqual(rModule.text.includes('exploit'), false);

    // 4. <svg><script>
    const rSvg = htmlToText('Text before <svg><script>alert(document.cookie)</script><text>hidden vector</text></svg> Text after');
    assert.strictEqual(rSvg.ok, true);
    assert.strictEqual(rSvg.text, 'Text before Text after');
    assert.strictEqual(rSvg.text.includes('cookie'), false);
    assert.strictEqual(rSvg.text.includes('hidden vector'), false);

    // 5. <template> in middle of text
    const rTpl = htmlToText('Start <template><div>Template should not be in output</div></template> End');
    assert.strictEqual(rTpl.ok, true);
    assert.strictEqual(rTpl.text, 'Start End');
    assert.strictEqual(rTpl.text.includes('Template'), false);

    // 6. Comment containing <script>
    const rComment = htmlToText('Before <!-- comment with <script>payload()</script> inside --> After');
    assert.strictEqual(rComment.ok, true);
    assert.strictEqual(rComment.text, 'Before After');
    assert.strictEqual(rComment.text.includes('payload'), false);

    // 7. </script > with space
    const rSpaceClose = htmlToText('Start <script>alert(1);</script > Middle');
    assert.strictEqual(rSpaceClose.ok, true);
    assert.strictEqual(rSpaceClose.text.includes('Start'), true);
    assert.strictEqual(rSpaceClose.text.includes('alert'), false, 'Code inside script must not leak');
});
