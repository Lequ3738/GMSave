// Shared CodeMirror extensions: GML highlighting for every code surface.
// The StreamLanguage only tokenizes — without a HighlightStyle nothing gets
// colored, which is why the tool "had no highlighting" before.
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';
import { createGmlLanguage } from './gmlLanguage';

// Colors tuned to the tool's light theme (style.css variables).
const gmlHighlight = HighlightStyle.define([
    { tag: tags.comment, color: '#6a9955' },
    { tag: tags.lineComment, color: '#6a9955' },
    { tag: tags.blockComment, color: '#6a9955' },
    { tag: tags.string, color: '#a31515' },
    { tag: tags.number, color: '#098658' },
    { tag: tags.keyword, color: '#0000ff' },
    { tag: tags.operator, color: '#383838' },
    { tag: tags.function(tags.variableName), color: '#795e26' },
    { tag: tags.variableName, color: '#001080' },
    { tag: tags.constant(tags.variableName), color: '#0070c1' },
    { tag: tags.punctuation, color: '#383838' },
    { tag: tags.brace, color: '#383838' },
    // tags.name (custom word list) intentionally unmapped, same policy as
    // Room-Editor: reserved for per-group decoration colors, no lexical competition.
]);

export function langExt(path: string) {
    if (!path.toLowerCase().endsWith('.gml')) return [];
    return [createGmlLanguage(), syntaxHighlighting(gmlHighlight)];
}
