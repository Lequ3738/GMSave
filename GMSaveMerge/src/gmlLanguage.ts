import { StreamLanguage, StringStream } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";

// 关键字
export const gmlKeywordList = [
    "mod", "div", "if", "else", "switch", "default", "repeat",
    "while", "for", "do", "until", "with", "continue", "break",
    "exit", "return", "case", "and", "or", "xor", "not", "self",
    "other", "all", "noone", "global", "local", "var", "globalvar",
    "then", "begin", "end"
];

// 常量
export const gmlBuiltinList = [];

const gmlKeywords = new RegExp(`^(${gmlKeywordList.join('|')})$`);
const gmlBuiltins = new RegExp(`^(${gmlBuiltinList.join('|')})$`);

const normalize = (s: string) => s.trim();

export function createGmlLanguage(overrideWords: Set<string> = new Set()) {
    function tokenBase(stream: StringStream, state: any): string | null {
        if (stream.eatSpace()) return null;

        if (stream.match("//")) {
            stream.skipToEnd();
            return "lineComment";
        }

        if (stream.match("/*")) {
            state.tokenize = tokenComment;
            return tokenComment(stream, state);
        }

        if (stream.match(/^[{}]/)) {
            return "brace"; 
        }

        const quote = stream.match(/^["']/);
        if (quote) {
            state.tokenize = tokenString((quote as RegExpMatchArray)[0]);
            return state.tokenize(stream, state);
        }

        if (stream.match(/^\$[0-9a-fA-F]+/)) return "number";
        if (stream.match(/^[0-9]+(\.[0-9]+)?/)) return "number";

        if (stream.match(/^[a-zA-Z_][a-zA-Z0-9_]*/)) {
            const word = stream.current();
            const key = normalize(word);

            // 先看规则表：命中后，不再走 keyword / builtin 分类。
            // 返回 "custom"（tokenTable 注册为 t.name：HighlightStyle 未映射 name 色 → 无词法色竞争，颜色由装饰插件按组独占；
            // 不注册会降级为 NodeType.none，装饰无法按节点名命中）
            if (overrideWords.has(key)) return "custom";

            if (gmlKeywords.test(word)) return "keyword";
            if (gmlBuiltins.test(word)) return "constant";

            if (stream.peek() === "(") return "function";

            return "variable";
        }

        if (stream.match(/^[+\-*\/=<>!&|~^%:]+/)) return "operator";
        if (stream.match(/^[()[\]{}]/)) return "punctuation";

        stream.next();
        return null;
    }

    function tokenComment(stream: StringStream, state: any): string {
        let maybeEnd = false;
        let ch;
        while ((ch = stream.next())) {
            if (ch === "/" && maybeEnd) {
                state.tokenize = tokenBase;
                break;
            }
            maybeEnd = ch === "*";
        }
        return "blockComment";
    }

    function tokenString(quote: string) {
        return function (stream: StringStream, state: any): string {
            let escaped = false;
            let ch;
            while ((ch = stream.next()) != null) {
                if (ch === quote && !escaped) {
                    state.tokenize = tokenBase;
                    break;
                }
                escaped = !escaped && ch === "\\";
            }
            return "string";
        };
    }

    return StreamLanguage.define({
        startState: () => ({ tokenize: tokenBase }),
        token: (stream, state) => state.tokenize(stream, state),
        languageData: {
            commentTokens: { line: "//", block: { open: "/*", close: "*/" } },
        },
        tokenTable: {
            lineComment: t.lineComment,
            blockComment: t.blockComment,
            string: t.string,
            number: t.number,
            keyword: t.keyword,
            operator: t.operator,
            function: t.function(t.variableName),
            variable: t.variableName,
            punctuation: t.punctuation,
            constant: t.constant(t.variableName),
            brace: t.brace,
            custom: t.name,
        },
    });
}