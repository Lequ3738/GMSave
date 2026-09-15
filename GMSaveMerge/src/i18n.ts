// UI strings. Follow the system language: Chinese when the OS UI locale is
// Chinese, English otherwise (the DLL-side message boxes do the same).
const ZH = (navigator.language || '').toLowerCase().startsWith('zh');

function pick<T>(zh: T, en: T): T {
    return ZH ? zh : en;
}

export const winTitle = pick(
    'GameMaker 8.0 - 合并外部更改',
    'GameMaker 8.0 - Merge External Changes',
);

export const T = {
    headerTitle: pick('合并外部更改', 'Merge External Changes'),
    summary: (files: number, conflicts: number, text: number, bin: number) =>
        pick(
            `${files} 个文件有差异 · ${conflicts} 个冲突（文本 ${text} / 二进制 ${bin}）`,
            `${files} file(s) changed · ${conflicts} conflict(s) (text ${text} / binary ${bin})`,
        ),
    applyReady: pick('确认并应用（重载项目）', 'Confirm && Apply (Reload Project)'),
    applyBlocked: (n: number) =>
        pick(`还有 ${n} 个二进制冲突未选择`, `${n} binary conflict(s) unresolved`),
    groups: {
        conflict: pick('冲突', 'Conflicts'),
        auto: pick('自动合并', 'Auto-merged'),
        local: pick('仅本地修改', 'Modified locally only'),
        remote: pick('仅外部修改', 'Modified externally only'),
    },
    kindBinary: pick('二进制', 'Binary'),
    kindText: (enc: string) => pick(`文本 · ${enc}`, `Text · ${enc}`),
    binNoConflict: pick(
        '二进制文件不支持内容级合并；本文件无冲突，将自动处理。',
        'Binary files do not support content-level merging; no conflict here — handled automatically.',
    ),
    binLocalTitle: pick('保留本地（IDE 内版本）', 'Keep local (IDE version)'),
    binLocalSub: pick('外部对该文件的更改将被覆盖', 'External changes to this file will be overwritten'),
    binRemoteTitle: pick('使用外部（磁盘版本）', 'Use external (disk version)'),
    binRemoteSub: pick('本地对该文件的更改将被放弃', 'Local changes to this file will be discarded'),
    mvLocalHead: (n: number) =>
        pick(`本地（GameMaker IDE）${n} 行`, `Local (GameMaker IDE) ${n} lines`),
    mvRemoteHead: (n: number) => pick(`外部（磁盘）${n} 行`, `External (disk) ${n} lines`),
    allLocal: pick('全部用本地', 'All local'),
    allRemote: pick('全部用外部', 'All external'),
    conflictN: (n: number) => pick(`冲突 ${n}`, `Conflict ${n}`),
    useLocal: pick('用本地', 'Local'),
    useRemote: pick('用外部', 'External'),
    colLocal: pick('本地', 'Local'),
    colBase: pick('原始（基线）', 'Original (base)'),
    colRemote: pick('外部', 'External'),
    colEmpty: pick('（无内容）', '(empty)'),
    resultTitle: pick('最终内容', 'Result'),
    editOn: pick('撤销手动编辑', 'Undo manual edit'),
    editOff: pick('手动编辑', 'Edit manually'),
    toastManualOn: pick(
        '已进入手动编辑模式，逐冲突选择已停用',
        'Manual edit mode — per-conflict choices disabled',
    ),
    toastManualOff: pick('已恢复逐冲突选择', 'Per-conflict choices restored'),
    btnCancel: pick('取消', 'Cancel'),
    hint: pick(
        '所有冲突默认保留本地（GameMaker IDE）版本；逐个冲突可改选外部版本，或手动编辑最终内容。',
        'Conflicts default to the local (GameMaker IDE) version; pick External per conflict, or edit the result manually.',
    ),
    errManifest: (e: unknown) => pick(`无法读取 manifest：${e}`, `Failed to read manifest: ${e}`),
};
