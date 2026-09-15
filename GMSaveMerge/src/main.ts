// GMSaveMerge frontend — file list + three-way conflict resolution UI.
// Contract with the DLL: read session\manifest.json + base\local\remote copies;
// write session\decisions.json + decisions\<rel>; exit 0 (apply) / 1 (cancel).
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { MergeView } from '@codemirror/merge';
import { EditorView, lineNumbers, placeholder } from '@codemirror/view';
import { EditorState } from '@codemirror/state';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { keymap } from '@codemirror/view';
import { langExt } from './highlight';
import { T, winTitle } from './i18n';
import './style.css';

interface ConflictRange {
    b: [number, number];
    l: [number, number];
    r: [number, number];
}
interface ManifestFile {
    path: string;
    kind: 'text' | 'binary';
    status: 'conflict' | 'auto' | 'local' | 'remote';
    encoding: string;
    conflicts?: ConflictRange[];
}
interface Manifest {
    version: number;
    files: ManifestFile[];
}

// Per-file resolution state.
interface FileState {
    mf: ManifestFile;
    // text conflicts: one choice per conflict ('local' | 'remote')
    choices: ('local' | 'remote')[];
    manual: string | null; // manual override of the final content
    binary?: 'local' | 'remote'; // binary conflict pick
    // cached split lines
    localLines: string[];
    remoteLines: string[];
    baseLines: string[];
}

let manifest: Manifest | null = null;
const states = new Map<string, FileState>();
let selected: string | null = null;

// ==== Line splitting — MUST match diff3.cpp split_lines exactly ====
function splitLines(text: string): string[] {
    const lines: string[] = [];
    let start = 0;
    while (start <= text.length) {
        const nl = text.indexOf('\n', start);
        if (nl < 0) {
            if (start < text.length) lines.push(text.slice(start));
            break;
        }
        let end = nl;
        if (end > start && text[end - 1] === '\r') end--;
        lines.push(text.slice(start, end));
        start = nl + 1;
    }
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    return lines;
}

// Compute the final content of a conflicted text file: start from the local
// version; for every conflict resolved as "remote", splice the remote block
// over the local block. Conflicts are applied in descending local-start order
// so earlier splices never shift later ranges (all ranges index the ORIGINAL
// local/remote line arrays).
function computeResult(st: FileState): string {
    if (st.manual !== null) return st.manual;
    const out = [...st.localLines];
    const cs = st.mf.conflicts ?? [];
    const order = cs.map((c, i) => ({ c, i })).sort((a, b) => b.c.l[0] - a.c.l[0]);
    for (const { c, i } of order) {
        if (st.choices[i] !== 'remote') continue;
        const [l0, lLen] = c.l;
        const [r0, rLen] = c.r;
        out.splice(l0, lLen, ...st.remoteLines.slice(r0, r0 + rLen));
    }
    return out.join('\r\n') + (out.length ? '\r\n' : '');
}

// ==== UI helpers ====
const $list = document.getElementById('filelist')!;
const $detail = document.getElementById('detail')!;
const $summary = document.getElementById('summary')!;

function toast(msg: string) {
    let t = document.getElementById('toast');
    if (!t) {
        t = document.createElement('div');
        t.id = 'toast';
        document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t!.classList.remove('show'), 1600);
}

function statusLabel(status: string): string {
    return (T.groups as Record<string, string>)[status] ?? status;
}

function renderList() {
    $list.innerHTML = '';
    if (!manifest) return;
    const groups: [string, string][] = [
        ['conflict', T.groups.conflict],
        ['auto', T.groups.auto],
        ['local', T.groups.local],
        ['remote', T.groups.remote],
    ];
    for (const [status, label] of groups) {
        const files = manifest.files.filter((f) => f.status === status);
        if (!files.length) continue;
        const h = document.createElement('div');
        h.className = 'group-header';
        h.textContent = `${label}（${files.length}）`;
        $list.appendChild(h);
        for (const mf of files) {
            const it = document.createElement('div');
            it.className = 'file-item' + (selected === mf.path ? ' sel' : '');
            // A conflict the user explicitly resolved to "remote" is still
            // resolved; only untouched ones count as unresolved.
            const st = states.get(mf.path);
            const unresolved =
                mf.status === 'conflict' &&
                mf.kind === 'binary' &&
                !st?.binary;
            if (unresolved) it.classList.add('hasUnresolved');
            const dot = document.createElement('span');
            dot.className = 'dot ' + mf.status;
            const p = document.createElement('span');
            p.className = 'path';
            p.textContent = mf.path;
            it.append(dot, p);
            it.onclick = () => {
                selected = mf.path;
                renderList();
                renderDetail();
            };
            $list.appendChild(it);
        }
    }
    const conflicts = manifest.files.filter((f) => f.status === 'conflict');
    const textC = conflicts.filter((f) => f.kind === 'text').length;
    const binC = conflicts.filter((f) => f.kind === 'binary');
    const binUnresolved = binC.filter((f) => !states.get(f.path)?.binary).length;
    $summary.textContent = T.summary(manifest.files.length, conflicts.length, textC, binC.length);
    const applyBtn = document.getElementById('btn-apply') as HTMLButtonElement;
    applyBtn.disabled = binUnresolved > 0;
    applyBtn.textContent = binUnresolved > 0 ? T.applyBlocked(binUnresolved) : T.applyReady;
}

// A read-only code pane with line numbers offset by `startLine` (the pane
// shows a slice of the file, so its first row is not line 1). Used for the
// three conflict-card columns; the big side-by-side view is a MergeView.
function codePane(text: string, startLine: number, path: string): HTMLElement {
    const host = document.createElement('div');
    host.className = 'code-pane';
    new EditorView({
        parent: host,
        state: EditorState.create({
            doc: text,
            extensions: [
                lineNumbers({ formatNumber: (n) => String(n - 1 + startLine) }),
                EditorView.editable.of(false),
                EditorState.readOnly.of(true),
                EditorView.theme({
                    '&': { maxHeight: '220px', fontSize: '12px' },
                    '.cm-scroller': { overflow: 'auto', fontFamily: 'Consolas, monospace' },
                }),
                ...(text ? [] : [placeholder(T.colEmpty)]),
                ...langExt(path),
            ],
        }),
    });
    return host;
}

const readOnlyExt = [EditorView.editable.of(false), EditorState.readOnly.of(true), lineNumbers()];

async function renderDetail() {
    if (!manifest || !selected) return;
    const mf = manifest.files.find((f) => f.path === selected)!;
    const st = states.get(selected);
    $detail.innerHTML = '';

    // header
    const head = document.createElement('div');
    head.className = 'detail-head';
    const pathEl = document.createElement('span');
    pathEl.className = 'path';
    pathEl.textContent = mf.path;
    const badge = document.createElement('span');
    badge.className = 'badge ' + mf.status;
    badge.textContent = statusLabel(mf.status);
    const enc = document.createElement('span');
    enc.style.color = 'var(--muted)';
    enc.textContent = mf.kind === 'binary' ? T.kindBinary : T.kindText(mf.encoding.toUpperCase());
    head.append(pathEl, badge, enc);
    $detail.appendChild(head);

    if (mf.kind === 'binary') {
        if (mf.status !== 'conflict') {
            const info = document.createElement('div');
            info.style.color = 'var(--muted)';
            info.textContent = T.binNoConflict;
            $detail.appendChild(info);
            return;
        }
        const wrap = document.createElement('div');
        wrap.className = 'binary-choice';
        const mk = (side: 'local' | 'remote', title: string, meta: string) => {
            const card = document.createElement('div');
            card.className = 'bin-card' + (st?.binary === side ? ' sel' : '');
            const h4 = document.createElement('h4');
            h4.textContent = title;
            const m = document.createElement('div');
            m.className = 'meta';
            m.textContent = meta;
            card.append(h4, m);
            card.onclick = () => {
                const s = states.get(mf.path)!;
                s.binary = side;
                renderList();
                renderDetail();
            };
            return card;
        };
        wrap.append(
            mk('local', T.binLocalTitle, T.binLocalSub),
            mk('remote', T.binRemoteTitle, T.binRemoteSub),
        );
        $detail.appendChild(wrap);
        return;
    }

    // ---- text ----
    const localText = await invoke<string>('read_side', { side: 'local', rel: mf.path }).catch(() => '');
    const remoteText = await invoke<string>('read_side', { side: 'remote', rel: mf.path }).catch(() => '');
    const baseText = await invoke<string>('read_side', { side: 'base', rel: mf.path }).catch(() => '');
    const st2 = states.get(mf.path)!;
    st2.localLines = splitLines(localText);
    st2.remoteLines = splitLines(remoteText);
    st2.baseLines = splitLines(baseText);

    // side-by-side diff overview
    const wrap = document.createElement('div');
    wrap.className = 'mv-wrap';
    const mvHead = document.createElement('div');
    mvHead.className = 'mv-head';
    const hL = document.createElement('div');
    hL.className = 'hlocal';
    hL.textContent = T.mvLocalHead(st2.localLines.length);
    const hR = document.createElement('div');
    hR.className = 'hremote';
    hR.textContent = T.mvRemoteHead(st2.remoteLines.length);
    mvHead.append(hL, hR);
    const mvHost = document.createElement('div');
    wrap.append(mvHead, mvHost);
    $detail.appendChild(wrap);
    const ext = [...readOnlyExt, ...langExt(mf.path)];
    new MergeView({
        parent: mvHost,
        a: { doc: localText, extensions: ext },
        b: { doc: remoteText, extensions: ext },
        gutter: true,
        collapseUnchanged: { margin: 3, minSize: 6 },
    });

    // conflict cards
    const cs = mf.conflicts ?? [];
    if (mf.status === 'conflict' && cs.length) {
        const quick = document.createElement('div');
        quick.style.margin = '12px 0 2px';
        const bAllL = document.createElement('button');
        bAllL.textContent = T.allLocal;
        bAllL.onclick = () => {
            const s = states.get(mf.path)!;
            s.choices = cs.map(() => 'local');
            renderDetail();
        };
        const bAllR = document.createElement('button');
        bAllR.textContent = T.allRemote;
        bAllR.onclick = () => {
            const s = states.get(mf.path)!;
            s.choices = cs.map(() => 'remote');
            renderDetail();
        };
        quick.append(bAllL, bAllR);
        $detail.appendChild(quick);

        cs.forEach((c, i) => {
            const card = document.createElement('div');
            card.className = 'conflict-card';
            const head2 = document.createElement('div');
            head2.className = 'cc-head';
            const title = document.createElement('span');
            title.className = 'cc-title';
            title.textContent = T.conflictN(i + 1);
            const btns = document.createElement('div');
            btns.className = 'cc-btns';
            const mkBtn = (side: 'local' | 'remote', label: string) => {
                const b = document.createElement('button');
                b.textContent = label;
                const s = states.get(mf.path)!;
                if (s.manual !== null) b.disabled = true;
                else if (s.choices[i] === side) {
                    b.classList.add('toggled');
                    b.disabled = true;
                }
                b.onclick = () => {
                    const ss = states.get(mf.path)!;
                    ss.choices[i] = side;
                    renderDetail();
                };
                return b;
            };
            btns.append(mkBtn('local', T.useLocal), mkBtn('remote', T.useRemote));
            head2.append(title, btns);

            const cols = document.createElement('div');
            cols.className = 'cc-cols';
            const mkCol = (cls: 'local-col' | 'remote-col' | 'base-col', label: string, lines: string[], startLine: number) => {
                const col = document.createElement('div');
                col.className = 'cc-col ' + cls;
                const lab = document.createElement('div');
                lab.className = 'cc-label';
                lab.textContent = label;
                col.append(lab, codePane(lines.join('\n'), startLine, mf.path));
                return col;
            };
            cols.append(
                mkCol('local-col', T.colLocal, st2.localLines.slice(c.l[0], c.l[0] + c.l[1]), c.l[0] + 1),
                mkCol('base-col', T.colBase, st2.baseLines.slice(c.b[0], c.b[0] + c.b[1]), c.b[0] + 1),
                mkCol('remote-col', T.colRemote, st2.remoteLines.slice(c.r[0], c.r[0] + c.r[1]), c.r[0] + 1),
            );
            card.append(head2, cols);
            $detail.appendChild(card);
        });
    }

    // result pane
    if (mf.status === 'conflict') {
        const rh = document.createElement('div');
        rh.className = 'result-head';
        const h3 = document.createElement('h3');
        h3.textContent = T.resultTitle;
        const bEdit = document.createElement('button');
        const s = states.get(mf.path)!;
        bEdit.textContent = s.manual !== null ? T.editOn : T.editOff;
        bEdit.onclick = () => {
            const ss = states.get(mf.path)!;
            if (ss.manual === null) {
                ss.manual = computeResult(ss);
                toast(T.toastManualOn);
            } else {
                ss.manual = null;
                toast(T.toastManualOff);
            }
            renderDetail();
        };
        rh.append(h3, bEdit);
        $detail.appendChild(rh);
        const resultHost = document.createElement('div');
        resultHost.className = 'mv-wrap';
        $detail.appendChild(resultHost);
        const finalText = computeResult(s);
        new EditorView({
            parent: resultHost,
            state: EditorState.create({
                doc: finalText,
                extensions: [
                    lineNumbers(),
                    history(),
                    keymap.of([...defaultKeymap, ...historyKeymap]),
                    ...(s.manual !== null ? [] : [EditorView.editable.of(false), EditorState.readOnly.of(true)]),
                    ...langExt(mf.path),
                    EditorView.updateListener.of((v) => {
                        if (s.manual !== null && v.docChanged) s.manual = v.state.doc.toString();
                    }),
                ],
            }),
        });
    }
}

// ==== Apply / cancel ====
async function finish(apply: boolean) {
    const files: { path: string; action: string; content?: string }[] = [];
    if (apply && manifest) {
        for (const mf of manifest.files) {
            if (mf.status !== 'conflict') continue;
            const st = states.get(mf.path);
            if (!st) continue; // manifest/tool mismatch guard
            if (mf.kind === 'binary') {
                files.push({ path: mf.path, action: st.binary ?? 'local' });
            } else {
                files.push({ path: mf.path, action: 'edited', content: computeResult(st) });
            }
        }
    }
    try {
        await invoke('decide', { result: apply ? 'apply' : 'cancel', files });
    } catch (e) {
        console.error('decide failed', e);
    }
    await invoke('exit_now', { code: apply ? 0 : 1 });
}

document.getElementById('btn-apply')!.addEventListener('click', () => finish(true));
document.getElementById('btn-cancel')!.addEventListener('click', () => finish(false));

// ==== Boot ====
(async () => {
    // Follow the system language for static chrome too (index.html ships the
    // Chinese defaults; the window title needs a Tauri call to change).
    document.title = winTitle;
    document.getElementById('title')!.textContent = T.headerTitle;
    const hint = document.getElementById('hint');
    if (hint) hint.innerHTML = T.hint.replace(/本地（GameMaker IDE）/, '<b>本地（GameMaker IDE）</b>');
    (document.getElementById('btn-cancel') as HTMLButtonElement).textContent = T.btnCancel;
    (document.getElementById('btn-apply') as HTMLButtonElement).textContent = T.applyReady;
    getCurrentWindow().setTitle(winTitle).catch(() => {});

    try {
        manifest = await invoke<Manifest>('get_manifest');
    } catch (e) {
        $detail.innerHTML = '';
        const err = document.createElement('div');
        err.style.padding = '40px';
        err.style.color = 'var(--danger)';
        err.textContent = T.errManifest(e);
        $detail.appendChild(err);
        return;
    }
    for (const mf of manifest.files) {
        states.set(mf.path, {
            mf,
            choices: (mf.conflicts ?? []).map(() => 'local' as const),
            manual: null,
            localLines: [],
            remoteLines: [],
            baseLines: [],
        });
    }
    const firstConflict = manifest.files.find((f) => f.status === 'conflict');
    selected = firstConflict?.path ?? manifest.files[0]?.path ?? null;
    renderList();
    await renderDetail();
})();
