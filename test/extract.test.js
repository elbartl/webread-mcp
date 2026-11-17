'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
    htmlToText,
    extractContent,
    cleanInvisibleChars,
    isStyleHidden,
    isTagHidden,
    MAX_CHARS,
} = require('../src/extract.js');

test('extract: removes script, style, noscript, template, svg, and comments', () => {
    const html = `
        <div>
            <h1>Article Title</h1>
            <script>console.log("malicious code");</script>
            <style>body { color: red; }</style>
            <noscript><p>Enable JavaScript</p></noscript>
            <template><div>Hidden template content</div></template>
            <svg><text>Vector</text></svg>
            <!-- HTML comment with injection instruction -->
            <p>Main content of the page.</p>
        </div>
    `;
    const r = htmlToText(html);
    assert.equal(r.ok, true);
    assert.ok(!r.text.includes('malicious code'));
    assert.ok(!r.text.includes('color: red'));
    assert.ok(!r.text.includes('Enable JavaScript'));
    assert.ok(!r.text.includes('Hidden template content'));
    assert.ok(!r.text.includes('Vector'));
    assert.ok(!r.text.includes('HTML comment'));
    assert.ok(r.text.includes('Article Title'));
    assert.ok(r.text.includes('Main content of the page.'));
});

test('extract: removes CSS and HTML hidden elements (display, visibility, hidden, aria-hidden, opacity, font-size)', () => {
    const html = `
        <article>
            <p>Visible paragraph 1.</p>
            <p style="display:none">Hidden prompt injection display:none</p>
            <div style="display: none; font-size: 14px">Another hidden element</div>
            <span style="visibility:hidden">Hidden text visibility:hidden</span>
            <div hidden>Hidden by hidden attribute</div>
            <p aria-hidden="true">Hidden by aria-hidden</p>
            <div style="opacity: 0">Hidden by opacity: 0</div>
            <span style="font-size: 0px">Hidden by font-size: 0</span>
            <p>Visible paragraph 2.</p>
        </article>
    `;
    const r = htmlToText(html);
    assert.equal(r.ok, true);
    assert.ok(r.text.includes('Visible paragraph 1.'));
    assert.ok(r.text.includes('Visible paragraph 2.'));
    assert.ok(!r.text.includes('Hidden prompt injection'));
    assert.ok(!r.text.includes('Another hidden'));
    assert.ok(!r.text.includes('visibility:hidden'));
    assert.ok(!r.text.includes('hidden attribute'));
    assert.ok(!r.text.includes('aria-hidden'));
    assert.ok(!r.text.includes('opacity: 0'));
    assert.ok(!r.text.includes('font-size: 0'));
    assert.ok(r.hiddenCount >= 7);
});

test('extract: removes elements with matching foreground/background colors and transparent text', () => {
    const html = `
        <div>
            <p>Start of text.</p>
            <span style="color: #ffffff; background-color: #ffffff">White on white</span>
            <span style="color: white; background: white">White on white 2</span>
            <span style="color: transparent">Transparent text</span>
            <span style="color: rgba(255, 0, 0, 0)">Zero alpha text</span>
            <p>End of text.</p>
        </div>
    `;
    const r = htmlToText(html);
    assert.equal(r.ok, true);
    assert.ok(r.text.includes('Start of text.'));
    assert.ok(r.text.includes('End of text.'));
    assert.ok(!r.text.includes('White on white'));
    assert.ok(!r.text.includes('Transparent text'));
    assert.ok(!r.text.includes('Zero alpha text'));
    assert.ok(r.hiddenCount >= 4);
});

test('extract: cleans zero-width and bidi-control characters', () => {
    // U+200B (ZWSP), U+200C (ZWNJ), U+202E (RLO), U+FEFF (BOM)
    const dangerous = 'Norm\u200Bal \u200Cte\u202Ext \uFEFFwith invisible characters';
    const r = htmlToText(`<p>${dangerous}</p>`);
    assert.equal(r.ok, true);
    assert.equal(r.text, 'Normal text with invisible characters');
    assert.equal(r.hiddenCount, 4);

    const { text, count } = cleanInvisibleChars(dangerous);
    assert.equal(text, 'Normal text with invisible characters');
    assert.equal(count, 4);
});

test('extract: alt/title attributes only included when element is visible', () => {
    const html = `
        <div>
            <img src="/logo.png" alt="Company Logo">
            <img src="/track.png" alt="Hidden Tracking" style="display:none">
            <img src="/pixel.png" alt="Hidden Pixel" hidden>
        </div>
    `;
    const r = htmlToText(html);
    assert.equal(r.ok, true);
    assert.ok(r.text.includes('[Company Logo]'));
    assert.ok(!r.text.includes('Hidden Tracking'));
    assert.ok(!r.text.includes('Hidden Pixel'));
    assert.equal(r.hiddenCount, 2);
});

test('extract: preserves tables, code blocks, headings, lists, and formatted links', () => {
    const html = `
        <h1>Heading 1</h1>
        <p>Introduction with link to <a href="/contact">contact</a> and <a href="https://external.org/doc">documentation</a>.</p>
        <ul>
            <li>First item</li>
            <li>Second item</li>
        </ul>
        <pre><code>const a = 1;\nconst b = 2;\nreturn a + b;</code></pre>
        <table>
            <tr><th>Column A</th><th>Column B</th></tr>
            <tr><td>Value 1</td><td>Value 2</td></tr>
        </table>
    `;
    const r = htmlToText(html, { baseUrl: 'https://example.com/sub/' });
    assert.equal(r.ok, true);

    assert.ok(r.text.includes('Heading 1'));
    assert.ok(r.text.includes('- First item'));
    assert.ok(r.text.includes('- Second item'));
    assert.ok(r.text.includes('contact (https://example.com/contact)'));
    assert.ok(r.text.includes('documentation (https://external.org/doc)'));
    assert.ok(r.text.includes('const a = 1;\nconst b = 2;\nreturn a + b;'));
    assert.ok(r.text.includes('Column A | Column B'));
    assert.ok(r.text.includes('Value 1 | Value 2'));
});

test('extract: handles non-HTML formats (text/plain, markdown, json)', () => {
    const jsonStr = '{\n  "status": "ok",\n  "key": "val\u200Bue"\n}';
    const rJson = extractContent(jsonStr, 'application/json');
    assert.equal(rJson.ok, true);
    assert.equal(rJson.text, '{\n  "status": "ok",\n  "key": "value"\n}');
    assert.equal(rJson.hiddenCount, 1);

    const mdStr = '# Markdown Title\n\n- Item 1\n- Item 2\n\n```js\nconst x = 10;\n```';
    const rMd = extractContent(mdStr, 'text/markdown');
    assert.equal(rMd.ok, true);
    assert.equal(rMd.text, mdStr);
    assert.equal(rMd.hiddenCount, 0);

    const txtStr = 'Simple text file without HTML <script>leave intact</script>';
    const rTxt = extractContent(txtStr, 'text/plain');
    assert.equal(rTxt.ok, true);
    assert.equal(rTxt.text, txtStr);
});

test('extract: character limit returns too_long without silent truncation', () => {
    const longText = 'A'.repeat(MAX_CHARS + 50);
    const html = `<p>${longText}</p>`;
    const r = htmlToText(html);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'too_long');
    assert.equal(r.length, MAX_CHARS + 50);
    assert.equal(r.text, undefined);

    const borderText = 'B'.repeat(1000);
    const rOk = htmlToText(`<p>${borderText}</p>`);
    assert.equal(rOk.ok, true);
    assert.equal(rOk.length, 1000);
});

test('extract: unclosed tags do not leak into output', () => {
    const rScript = htmlToText('<p>visible</p><script>alert(1)');
    assert.equal(rScript.ok, true);
    assert.ok(rScript.text.includes('visible'));
    assert.ok(!rScript.text.includes('alert'));

    for (const tag of ['style', 'noscript', 'template', 'svg']) {
        const r = htmlToText(`<p>visible text</p><${tag}>secret_leak_123 <p>nested</p>`);
        assert.equal(r.ok, true);
        assert.ok(r.text.includes('visible text'));
        assert.ok(!r.text.includes('secret_leak_123'));
        assert.ok(!r.text.includes('nested'));
    }
});

test('extract: HTML entities in attributes and Unicode Plane 14 tag characters are stripped', () => {
    const rHex = htmlToText('<div style="display&#x3a;none">hidden hex entity</div><p>visible</p>');
    assert.equal(rHex.text, 'visible');

    const rNamed = htmlToText('<div style="display&colon;none">hidden named entity</div><p>visible</p>');
    assert.equal(rNamed.text, 'visible');

    const rAttr = htmlToText('<div &#104;idden>hidden attr entity</div><p>visible</p>');
    assert.equal(rAttr.text, 'visible');

    const tagPayload = 'Visible text \u{E0001}\u{E0020}\u{E0041}\u{E0042}\u{E0043} end';
    const cleaned = cleanInvisibleChars(tagPayload);
    assert.equal(cleaned.text, 'Visible text  end');
    assert.ok(cleaned.count >= 4);
});
