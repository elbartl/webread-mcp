'use strict';
/**
 * src/extract.js - HTML to clean text extraction and invisible content stripper.
 *
 * Requirements:
 * - htmlToText(html, { baseUrl, maxChars = 60000 })
 * - Zero external dependencies.
 * - Removes: <script>, <style>, <noscript>, <template>, <svg>, HTML comments.
 * - Removes hidden elements: display:none, visibility:hidden, hidden attribute,
 *   aria-hidden="true", opacity:0, font-size:0, matching text & background colors, transparent.
 * - Strips zero-width and bidi-control characters: U+200B-200F, U+202A-202E, U+2060-206F, U+FEFF.
 * - Alt/title attributes included only when element is visible.
 * - Preserves tables (with cell separators), code blocks, headings, lists, links as `text (url)`.
 * - Handles non-HTML formats (text/plain, markdown, json) cleanly by stripping invisible characters.
 * - Enforces character limit: returns reason 'too_long' without silent truncation.
 * - Returns counter of removed hidden fragments.
 */

const MAX_CHARS = 60000;
const MAX_STACK_DEPTH = 256;
const MAX_OVERFLOW_DEPTH = 100000;

// Zero-width, bidi-control, tag characters, variation selectors, and filler characters
const INVISIBLE_RE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

// HTML entities table
const NAMED_ENTITIES = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    nbsp: ' ',
    ndash: '–',
    mdash: '—',
    hellip: '…',
    copy: '©',
    reg: '®',
    trade: '™',
    laquo: '«',
    raquo: '»',
    colon: ':',
    semi: ';',
    equals: '=',
    sol: '/',
    bsol: '\\',
    plus: '+',
    minus: '-',
    hyphen: '-',
    dash: '-',
    comma: ',',
    period: '.',
    excl: '!',
    quest: '?',
    num: '#',
    dollar: '$',
    percnt: '%',
    lowbar: '_',
    vert: '|',
    space: ' ',
    tab: '\t',
    newline: '\n',
};

// HTML5 void tags (no closing tag)
const VOID_TAGS = new Set([
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img',
    'input', 'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

// All standard HTML elements for unclosed tag detection in tail
const KNOWN_HTML_TAGS = new Set([
    'a', 'abbr', 'address', 'area', 'article', 'aside', 'audio',
    'b', 'base', 'bdi', 'bdo', 'blockquote', 'body', 'br', 'button',
    'canvas', 'caption', 'cite', 'code', 'col', 'colgroup',
    'data', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog', 'div', 'dl', 'dt',
    'em', 'embed',
    'fieldset', 'figcaption', 'figure', 'footer', 'form', 'frame', 'frameset',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html',
    'i', 'iframe', 'img', 'input', 'ins',
    'kbd',
    'label', 'legend', 'li', 'link',
    'main', 'map', 'mark', 'math', 'menu', 'meta', 'meter',
    'nav', 'noscript',
    'object', 'ol', 'optgroup', 'option', 'output',
    'p', 'picture', 'portal', 'pre', 'progress',
    'q',
    'rp', 'rt', 'ruby',
    's', 'samp', 'script', 'search', 'section', 'select', 'slot', 'small', 'source', 'span', 'strong', 'style', 'sub', 'summary', 'sup', 'svg',
    'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'track',
    'u', 'ul',
    'var', 'video',
    'wbr',
]);

const DANGEROUS_UNCLOSED_RE = /<\/?(script|style|iframe|noscript|template|object|embed|svg|math|textarea|title)/i;
const UNCLOSED_TAG_RE = /<\/?([a-zA-Z][a-zA-Z0-9:-]*)(?=[\s/]|$)/g;

/**
 * Checks for an unclosed HTML tag in the trailing text after the last '>'.
 * Fail-closed: dangerous tags (<script, <style, etc.) are always truncated.
 * Other tags are truncated only if they match a known HTML element followed by space, '/', or end of string.
 */
function findUnclosedTailCut(tail) {
    let earliest = -1;
    const dangerMatch = tail.match(DANGEROUS_UNCLOSED_RE);
    if (dangerMatch) {
        earliest = dangerMatch.index;
    }

    UNCLOSED_TAG_RE.lastIndex = 0;
    let match;
    while ((match = UNCLOSED_TAG_RE.exec(tail)) !== null) {
        if (earliest !== -1 && match.index >= earliest) {
            break;
        }
        const tag = match[1].toLowerCase();
        if (KNOWN_HTML_TAGS.has(tag)) {
            earliest = match.index;
            break;
        }
    }
    return earliest;
}

/**
 * Formats a link in O(inner link parts length) without quadratic buffer copies or leaving empty strings.
 */
function formatLink(parts, partStart, href) {
    let first = -1;
    for (let i = partStart; i < parts.length; i++) {
        if (parts[i].trim().length > 0) {
            first = i;
            break;
        }
    }

    if (first === -1) {
        // All inner parts were whitespace or empty
        parts.length = partStart;
        const emptyLinkStr = `(${href})`;
        parts.push(emptyLinkStr);
        return emptyLinkStr;
    }

    let last = -1;
    for (let i = parts.length - 1; i >= first; i--) {
        if (parts[i].trim().length > 0) {
            last = i;
            break;
        }
    }

    parts[first] = parts[first].trimStart();
    parts[last] = parts[last].trimEnd();

    let dest = partStart;
    for (let src = first; src <= last; src++) {
        if (parts[src].length > 0) {
            parts[dest++] = parts[src];
        }
    }
    parts.length = dest;

    const linkSuffix = ` (${href})`;
    parts.push(linkSuffix);
    return linkSuffix;
}

// Tags whose contents must never leak into extracted text
const RAW_CONTENT_TAGS = new Set(['script', 'style', 'noscript', 'template', 'svg']);

/**
 * Decodes HTML entities (named, decimal, hexadecimal, with or without semicolon).
 */
function decodeEntities(str) {
    if (!str) return '';
    let s = str.replace(/&#([xX][0-9a-fA-F]+|\d+);?/g, (match, code) => {
        const isHex = code[0] === 'x' || code[0] === 'X';
        const num = isHex ? parseInt(code.slice(1), 16) : parseInt(code, 10);
        if (Number.isFinite(num) && num > 0 && num <= 0x10ffff) {
            try {
                return String.fromCodePoint(num);
            } catch (_) {
                return ' ';
            }
        }
        return ' ';
    });
    s = s.replace(/&([a-zA-Z]+);?/g, (match, name) => {
        const lower = name.toLowerCase();
        if (NAMED_ENTITIES[lower] !== undefined) {
            return NAMED_ENTITIES[lower];
        }
        return match;
    });
    return s;
}

/**
 * Strips zero-width and bidi control characters, returning cleaned string and count.
 */
function cleanInvisibleChars(str) {
    if (str == null) return { text: '', count: 0 };
    const s = String(str);
    const matches = s.match(INVISIBLE_RE);
    const count = matches ? matches.length : 0;
    const text = s.replace(INVISIBLE_RE, '');
    return { text, count };
}

/**
 * Normalizes CSS color values for comparison.
 */
function normalizeCssColor(val) {
    if (!val) return '';
    const v = String(val).trim().toLowerCase().replace(/\s+/g, '');
    if (v === '#fff' || v === '#ffffff' || v === 'white' || v === 'rgb(255,255,255)') return '#ffffff';
    if (v === '#000' || v === '#000000' || v === 'black' || v === 'rgb(0,0,0)') return '#000000';
    return v;
}

/**
 * Heuristic check if an inline style string hides content.
 */
function isStyleHidden(styleStr) {
    if (!styleStr || typeof styleStr !== 'string') return false;
    const s = styleStr.toLowerCase();

    // display: none
    if (/display\s*:\s*none\b/.test(s)) return true;

    // visibility: hidden | collapse
    if (/visibility\s*:\s*(hidden|collapse)\b/.test(s)) return true;

    // opacity: 0 (or 0.0)
    if (/opacity\s*:\s*0(?:\.0+)?(?![0-9])/.test(s)) return true;

    // font-size: 0
    if (/font-size\s*:\s*0(?:px|em|rem|%|pt|vw|vh)?(?![0-9])/.test(s)) return true;

    // zero size with hidden overflow
    if (/(?:height|width)\s*:\s*0(?:px)?\b[^;]*;\s*overflow\s*:\s*hidden/.test(s) ||
        /overflow\s*:\s*hidden\b[^;]*;\s*(?:height|width)\s*:\s*0(?:px)?\b/.test(s)) {
        return true;
    }

    // off-screen positioning tricks
    if (/text-indent\s*:\s*-[0-9]{3,}/.test(s)) return true;
    if (/(?:left|top)\s*:\s*-[0-9]{3,}(?:px|em)/.test(s) && /position\s*:\s*absolute/.test(s)) return true;

    // transparent text
    if (/color\s*:\s*transparent\b/.test(s)) return true;
    if (/color\s*:\s*rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0(?:\.0+)?\s*\)/.test(s)) return true;

    // matching text and background color
    const colorMatch = s.match(/(?:^|;)\s*color\s*:\s*([^;]+)/);
    const bgMatch = s.match(/(?:^|;)\s*(?:background|background-color)\s*:\s*([^;]+)/);
    if (colorMatch && bgMatch) {
        const c = normalizeCssColor(colorMatch[1]);
        const bg = normalizeCssColor(bgMatch[1]);
        if (c && bg && c === bg) return true;
    }

    return false;
}

/**
 * Checks if attributes hide an element.
 */
function isTagHidden(attrStr) {
    if (!attrStr) return false;
    const decoded = decodeEntities(attrStr);

    // hidden attribute (case-insensitive)
    if (/(?:^|[\s/])hidden(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*))?(?=[\s/>]|$)/i.test(decoded)) {
        return true;
    }

    // aria-hidden="true" or aria-hidden (case-insensitive)
    if (/(?:^|[\s/])aria-hidden(?:\s*=\s*["']?true["']?|(?=[\s/>]|$))/i.test(decoded)) {
        return true;
    }

    // style attribute check
    const styleMatch = decoded.match(/(?:^|[\s/])style\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    if (styleMatch) {
        const style = decodeEntities(styleMatch[1] || styleMatch[2] || styleMatch[3] || '');
        if (isStyleHidden(style)) return true;
    }

    return false;
}

/**
 * Strips <!DOCTYPE ...> case-insensitively, supporting normal doctypes,
 * external subsets, and internal subsets [<!ENTITY ...>].
 * Implemented linearly using indexOf to prevent ReDoS / catastrophic backtracking.
 *
 * @param {string} raw
 * @returns {string}
 */
function stripDoctype(raw) {
    const lower = raw.toLowerCase();
    let dtIndex = lower.indexOf('<!doctype');
    if (dtIndex === -1) {
        return raw;
    }

    let result = '';
    let cur = 0;

    while (dtIndex !== -1) {
        result += raw.slice(cur, dtIndex);
        const afterDt = dtIndex + 9; // length of '<!doctype'

        // Check word boundary: next char cannot be alphanumeric or underscore
        if (afterDt < raw.length && /[a-zA-Z0-9_]/.test(raw[afterDt])) {
            result += raw.slice(dtIndex, afterDt);
            cur = afterDt;
            dtIndex = lower.indexOf('<!doctype', cur);
            continue;
        }

        const openBracket = raw.indexOf('[', afterDt);
        const firstGt = raw.indexOf('>', afterDt);

        if (firstGt === -1) {
            // Unclosed doctype without closing '>': fail-closed, strip to end
            cur = raw.length;
            break;
        }

        if (openBracket !== -1 && openBracket < firstGt) {
            // Internal DTD subset: look for ']' followed by '>'
            const closeBracket = raw.indexOf(']', openBracket + 1);
            if (closeBracket === -1) {
                // Unclosed internal subset: fail-closed, strip to end
                cur = raw.length;
                break;
            }
            const closeGt = raw.indexOf('>', closeBracket + 1);
            if (closeGt === -1) {
                // No closing '>' after internal subset: fail-closed, strip to end
                cur = raw.length;
                break;
            }
            cur = closeGt + 1;
        } else {
            // Normal doctype: ends at firstGt
            cur = firstGt + 1;
        }

        dtIndex = lower.indexOf('<!doctype', cur);
    }

    if (cur < raw.length) {
        result += raw.slice(cur);
    }

    return result;
}

/**
 * Parses HTML and extracts clean readable text with hidden fragments removed.
 *
 * @param {string|Buffer} html
 * @param {object} [options]
 * @param {string} [options.baseUrl]
 * @param {number} [options.maxChars=60000]
 * @returns {{ ok: boolean, text?: string, hiddenCount: number, length: number, reason?: string }}
 */
function htmlToText(html, options = {}) {
    const maxChars = options.maxChars || MAX_CHARS;
    const baseUrl = options.baseUrl || '';
    const deadlineMs = typeof options.deadlineMs === 'number' ? options.deadlineMs : 1500;
    const startTime = performance.now();

    if (deadlineMs <= 0) {
        return {
            ok: false,
            error: 'extraction_timeout',
            reason: 'extraction_timeout',
            length: 0,
            hiddenCount: 0,
        };
    }

    let raw = String(html || '');

    // 1. Strip <script>, <style>, <noscript>, <template>, <svg> and their contents (including unclosed to end of doc)
    raw = raw.replace(/<(script|style|noscript|template|svg)\b[^>]*>(?:[\s\S]*?<\/\1>|[\s\S]*$)/gi, '');

    // 2. Strip <!DOCTYPE ...> (case-insensitive, including system/public and internal subsets)
    raw = stripDoctype(raw);

    // 3. Strip XML processing instructions <?xml ...?> and <?...?>
    raw = raw.replace(/<\?[^>]*>?/g, '');

    // 4. Strip HTML comments
    raw = raw.replace(/<!--[\s\S]*?(?:-->|$)/g, '');

    // 3. Clean zero-width and bidi characters
    const { text: cleanRawText, count: invisCount } = cleanInvisibleChars(raw);
    let hiddenCount = invisCount;
    let cleanRaw = cleanRawText;

    // 4. Tokenize HTML into tags and text chunks
    // To prevent ReDoS on unclosed tags missing '>', truncate any unclosed tag after the last '>'
    const lastGt = cleanRaw.lastIndexOf('>');
    const searchStart = lastGt >= 0 ? lastGt + 1 : 0;
    const tail = cleanRaw.slice(searchStart);
    const cutOffset = findUnclosedTailCut(tail);
    if (cutOffset !== -1) {
        cleanRaw = cleanRaw.slice(0, searchStart + cutOffset);
    }

    const TAG_RE = /<\/?([a-zA-Z][a-zA-Z0-9:-]*)((?![a-zA-Z0-9:-])[^>]*)?>/g;
    const stack = [];
    const overflowStack = [];
    let overflowHiddenFrom = -1;
    const parts = [];
    let lastNonEmptyPart = '';

    function appendPart(str) {
        if (str && str.length > 0) {
            parts.push(str);
            lastNonEmptyPart = str;
        }
    }

    let lastIndex = 0;
    let match;
    let tagIterations = 0;

    if (lastGt === -1) {
        if (cleanRaw.length > 0) {
            appendPart(decodeEntities(cleanRaw));
        }
        lastIndex = cleanRaw.length;
    } else {
        while ((match = TAG_RE.exec(cleanRaw)) !== null) {
            tagIterations++;
            if ((tagIterations & 1023) === 0) {
                if (performance.now() - startTime >= deadlineMs) {
                    return {
                        ok: false,
                        error: 'extraction_timeout',
                        reason: 'extraction_timeout',
                        length: 0,
                        hiddenCount,
                    };
                }
            }

            const textBefore = cleanRaw.slice(lastIndex, match.index);
            lastIndex = TAG_RE.lastIndex;

            const isCurrentlyHidden = (stack.length > 0 && stack[stack.length - 1].hidden) || (overflowHiddenFrom !== -1);

            if (textBefore.length > 0 && !isCurrentlyHidden) {
                appendPart(decodeEntities(textBefore));
            }

            const fullTag = match[0];
            const isCloseTag = fullTag.startsWith('</');
            const tagName = match[1].toLowerCase();
            const attrStr = match[2] || '';
            const isVoid = VOID_TAGS.has(tagName) || fullTag.endsWith('/>');

            if (isCloseTag) {
                if (overflowStack.length > 0) {
                    if (tagName === overflowStack[overflowStack.length - 1]) {
                        overflowStack.pop();
                        if (overflowHiddenFrom !== -1 && overflowStack.length < overflowHiddenFrom) {
                            overflowHiddenFrom = -1;
                        }
                    }
                    // Mismatched close tag in overflow zone is ignored (fail-closed, O(1))
                } else {
                    // Find matching open tag in stack
                    let foundIdx = -1;
                    for (let i = stack.length - 1; i >= 0; i--) {
                        if (stack[i].tag === tagName) {
                            foundIdx = i;
                            break;
                        }
                    }

                    if (foundIdx >= 0) {
                        const popped = stack[foundIdx];
                        const wasHidden = popped.hidden;
                        stack.length = foundIdx; // unwind stack

                        if (!wasHidden) {
                            if (tagName === 'a' && popped.href) {
                                lastNonEmptyPart = formatLink(parts, popped.partStart, popped.href);
                            } else if (tagName === 'tr') {
                                appendPart('\n');
                            } else if (tagName === 'table') {
                                appendPart('\n\n');
                            } else if (['p', 'div', 'section', 'article', 'header', 'footer', 'title'].includes(tagName)) {
                                appendPart('\n\n');
                            } else if (['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tagName)) {
                                appendPart('\n\n');
                            } else if (tagName === 'ul' || tagName === 'ol') {
                                appendPart('\n');
                            }
                        }
                    }
                }
            } else {
                // Open tag
                const isRawTag = RAW_CONTENT_TAGS.has(tagName);
                const tagHidden = isTagHidden(attrStr) || isRawTag;
                const hidden = isCurrentlyHidden || tagHidden;

                if (isVoid) {
                    if (tagHidden && !isCurrentlyHidden) {
                        hiddenCount++;
                    }
                    if (!hidden) {
                        if (tagName === 'br') {
                            appendPart('\n');
                        } else if (tagName === 'hr') {
                            appendPart('\n---\n');
                        } else if (tagName === 'img') {
                            const altMatch = attrStr.match(/\balt\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
                            const alt = altMatch ? (altMatch[1] || altMatch[2] || altMatch[3]) : '';
                            if (alt) {
                                appendPart(` [${decodeEntities(alt)}] `);
                            }
                        }
                    }
                } else {
                    if (stack.length < MAX_STACK_DEPTH) {
                        if (tagHidden && !isCurrentlyHidden) {
                            hiddenCount++;
                        }

                        let href = null;
                        if (tagName === 'a') {
                            const hrefMatch = attrStr.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
                            let rawHref = hrefMatch ? (hrefMatch[1] || hrefMatch[2] || hrefMatch[3]) : '';
                            if (rawHref && baseUrl) {
                                try {
                                    rawHref = new URL(rawHref, baseUrl).href;
                                } catch (_) {
                                    // keep rawHref as-is
                                }
                            }
                            href = rawHref;
                        }

                        if (!hidden) {
                            if (tagName === 'title') {
                                if (lastNonEmptyPart.length > 0 && !lastNonEmptyPart.endsWith('\n\n')) {
                                    appendPart(lastNonEmptyPart.endsWith('\n') ? '\n' : '\n\n');
                                }
                            } else if (['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tagName)) {
                                appendPart('\n\n');
                            } else if (tagName === 'li') {
                                appendPart('\n- ');
                            } else if (tagName === 'td' || tagName === 'th') {
                                const activeTr = stack.length > 0 ? stack[stack.length - 1].currentTr : null;
                                if (activeTr) {
                                    if (activeTr.cells > 0) {
                                        appendPart(' | ');
                                    }
                                    activeTr.cells++;
                                }
                            }
                        }

                        const parentTr = stack.length > 0 ? stack[stack.length - 1].currentTr : null;
                        const currentTr = tagName === 'tr' ? { cells: 0 } : parentTr;

                        stack.push({
                            tag: tagName,
                            hidden,
                            href,
                            partStart: parts.length,
                            currentTr,
                        });
                    } else {
                        // Stack is full (stack.length >= MAX_STACK_DEPTH)
                        overflowStack.push(tagName);
                        if (overflowStack.length > MAX_OVERFLOW_DEPTH) {
                            return {
                                ok: false,
                                error: 'nesting_too_deep',
                                reason: 'nesting_too_deep',
                                length: 0,
                                hiddenCount,
                            };
                        }
                        if (tagHidden && !isCurrentlyHidden) {
                            hiddenCount++;
                            overflowHiddenFrom = overflowStack.length;
                        }
                    }
                }
            }

            if (lastIndex > lastGt) {
                break;
            }
        }
    }

    // Trailing text after last tag
    const isFinalHidden = (stack.length > 0 && stack[stack.length - 1].hidden) || (overflowHiddenFrom !== -1);
    if (lastIndex < cleanRaw.length && !isFinalHidden) {
        appendPart(decodeEntities(cleanRaw.slice(lastIndex)));
    }

    let output = parts.join('');

    // 5. Whitespace normalization
    let normalized = output
        .replace(/[ \t\f\v\u00a0]+/g, ' ')
        .replace(/ *\n */g, '\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim();

    // 6. Check maxChars limit (default 60,000)
    if (normalized.length > maxChars) {
        return {
            ok: false,
            reason: 'too_long',
            length: normalized.length,
            hiddenCount,
        };
    }

    return {
        ok: true,
        text: normalized,
        length: normalized.length,
        hiddenCount,
    };
}

/**
 * Extracts content according to Content-Type (HTML, text/plain, markdown, JSON).
 */
function extractContent(body, contentType = 'text/html', options = {}) {
    const raw = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
    const ct = String(contentType || '').toLowerCase();

    if (ct.includes('html') || ct.includes('xml')) {
        return htmlToText(raw, options);
    }

    const deadlineMs = typeof options.deadlineMs === 'number' ? options.deadlineMs : 1500;
    const startTime = performance.now();
    if (deadlineMs <= 0) {
        return {
            ok: false,
            error: 'extraction_timeout',
            reason: 'extraction_timeout',
            length: 0,
            hiddenCount: 0,
        };
    }

    // For plain text, markdown, json: preserve content, strip invisible control characters
    const { text: cleaned, count: invisCount } = cleanInvisibleChars(raw);
    const maxChars = options.maxChars || MAX_CHARS;

    if (cleaned.length > maxChars) {
        return {
            ok: false,
            reason: 'too_long',
            length: cleaned.length,
            hiddenCount: invisCount,
        };
    }

    return {
        ok: true,
        text: cleaned,
        length: cleaned.length,
        hiddenCount: invisCount,
    };
}

module.exports = {
    htmlToText,
    extractContent,
    cleanInvisibleChars,
    isStyleHidden,
    isTagHidden,
    decodeEntities,
    MAX_CHARS,
    MAX_STACK_DEPTH,
    MAX_OVERFLOW_DEPTH,
};
