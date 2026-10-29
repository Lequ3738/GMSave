#include "pch.h"
#include "mm_audit.h"
#include "gm80_addresses.h"
#include "gm_log.h"
#include "i18n.h"
#include <cstdio>
#include <tlhelp32.h>

// 池表布局与锁语义见 mm_audit.h。索引步 4（= 记录步长 32 字节 / 8）。
static const uint32_t kIndexStep = 4;
static const uint32_t kSlots = ADDR_MM_POOL_COUNT / kIndexStep;
// GM8 Delphi MM 的 CAS 自旋循环返回地址（free/alloc 路径）——栈上出现即坐实
// 主线程卡在 MM 锁/块头自旋里。
static const uint32_t kSpinFree = 0x401CFE;
static const uint32_t kSpinAlloc = 0x4019B3;
// 挂死判定阈值：探针持续无响应多久算挂死。流程内（重载/保存/合并）每一步都会
// 泵消息，30 秒足够；流程外的长阻塞主要是 GM 编译工程这类自有任务，整段不泵
// 消息，用宽阈值避开误报。
static const uint32_t kHangMsInFlow = 30000;
static const uint32_t kHangMsIdle = 120000;
// 每进程最多留几份现场（防止探针病态循环无限写盘）。
static const uint32_t kMaxDumps = 20;

// 巡检状态：池锁 streak 数据由后台线程写、主线程守卫读（last_nonzero/
// report_once），一律持 g_cs。g_flow_flag 主线程写（Interlocked）、后台读。
static CRITICAL_SECTION g_cs;
static struct CsInit { CsInit() { InitializeCriticalSection(&g_cs); } } g_cs_init;

static uint16_t g_streak[kSlots];        // 连续观测到非 0 的次数
static uint16_t g_global_streak = 0;     // 全局锁连续观测次数
static bool g_reported[kSlots];          // 每池每进程只报一次
static bool g_global_reported = false;
static bool g_any_recent_nonzero = false;
static mm_audit::StuckPool g_last_nonzero = {}; // 上一轮 tick 首个非零池（日志用）
static bool g_marker_swept = false;      // 本进程已做过遗留标记文件清理
static volatile LONG g_flow_flag = 0;    // 流程进行中（日志用）
static ULONGLONG g_unresponsive_since = 0; // 本轮持续无响应的起点（GetTickCount64）
static uint32_t g_dump_count = 0;        // 本进程已留档次数（每进程上限 kMaxDumps）
static bool g_hang_dumped = false;       // 当前这段持续挂死已留档（恢复响应后重新武装）

static uint8_t* gm_base()
{
    return (uint8_t*)GetModuleHandle(NULL);
}

static inline uint8_t* pool_ptr(const uint8_t* base, uint32_t index)
{
    return (uint8_t*)(base + ADDR_MM_POOL_TABLE + 8 * index);
}

void mm_audit::marker_path(wchar_t* buf, uint32_t cch)
{
    if (!buf || cch == 0) return;
    buf[0] = 0;
    DWORD n = GetTempPathW(cch, buf);
    if (n == 0 || n >= cch) { buf[0] = 0; return; }
    wcscat_s(buf, cch, L"GMSave_MMBroken.txt");
}

// 挂死现场：%TEMP%\GMSave_Hang\hang_<pid>_<yyyymmdd-hhmmss>.txt。与用户提示用的
// 标记文件分开——标记文件在新进程首个干净 tick 会被清掉，现场必须留得住。
static void hang_dump_path(wchar_t* buf, uint32_t cch)
{
    if (!buf || cch == 0) return;
    buf[0] = 0;
    wchar_t dir[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, dir);
    if (n == 0 || n >= MAX_PATH) return;
    wcscat_s(dir, MAX_PATH, L"GMSave_Hang");
    CreateDirectoryW(dir, NULL);
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snwprintf_s(buf, cch, _TRUNCATE,
        L"%s\\hang_%u_%04u%02u%02u-%02u%02u%02u.txt", dir, GetCurrentProcessId(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void write_utf16_file(const wchar_t* path, const wchar_t* body)
{
    if (!path || !path[0]) return;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    static const uint8_t bom[2] = { 0xFF, 0xFE };
    DWORD wrote = 0;
    WriteFile(h, bom, 2, &wrote, NULL);
    WriteFile(h, body, (DWORD)(wcslen(body) * sizeof(wchar_t)), &wrote, NULL);
    CloseHandle(h);
}

// 标记文件：给（不一定看日志的）用户的持久提示 + 给我方后续诊断的现场记录。
// UTF-16LE + BOM（Notepad 可直接识别，不受系统代码页影响）。
static void write_marker_text(const wchar_t* body)
{
    wchar_t path[MAX_PATH];
    mm_audit::marker_path(path, MAX_PATH);
    write_utf16_file(path, body);
}

static void write_marker(uint32_t index, uint16_t size, uint8_t value, uint32_t held_ticks)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t body[1200];
    _snwprintf_s(body, _TRUNCATE,
        L"%s\r\n\r\n"
        L"%s: idx=%u size=%u value=0x%02X\r\n"
        L"%s: %u s\r\n"
        L"%s: pid=%u %04u-%02u-%02u %02u:%02u:%02u\r\n\r\n"
        L"%s\r\n",
        tr(L"GMSave: Game Maker's heap manager is wedged (an internal lock was never released).",
           L"GMSave：Game Maker 的内存管理器已卡死（有内部锁未释放）。"),
        tr(L"Stuck pool", L"卡死池"), index, size, value,
        tr(L"Held for", L"已持续"), held_ticks,
        tr(L"IDE", L"IDE"), GetCurrentProcessId(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        tr(L"Further IDE operations (save / reload / compile) can hang forever.\r\n"
           L"The .gm80 project on disk is normally up to date - restart the IDE soon.",
           L"后续 IDE 操作（保存/重载/编译）可能永久未响应（卡死后不会恢复）。\r\n"
           L"磁盘上的 .gm80 工程一般已是最新；建议尽快重启 IDE 再打开工程。"));
    write_marker_text(body);
}

uint32_t mm_audit::scan_now(StuckPool* out, uint32_t max)
{
    const uint8_t* base = gm_base();
    if (!base || !out) return 0;
    uint32_t n = 0;
    for (uint32_t idx = 0; idx < ADDR_MM_POOL_COUNT && n < max; idx += kIndexStep)
    {
        const uint8_t* p = pool_ptr(base, idx);
        uint8_t v = *(volatile const uint8_t*)p;
        if (v == 0) continue;
        out[n].index = idx;
        out[n].block_size = *(volatile const uint16_t*)(p + 2);
        out[n].value = v;
        n++;
    }
    return n;
}

static void report_once(uint32_t index, uint16_t size, uint8_t value, uint32_t held_ticks,
    const char* how, int flow_active)
{
    uint32_t slot = index / kIndexStep;
    EnterCriticalSection(&g_cs);
    if (slot < kSlots)
    {
        if (g_reported[slot]) { LeaveCriticalSection(&g_cs); return; }
        g_reported[slot] = true;
    }
    LeaveCriticalSection(&g_cs);
    gm_log("MMAudit: pool idx=%u size=%u lock=0x%02X held>=%u (%s, flow_active=%d) — "
           "Delphi MM wedged; IDE save/reload may hang forever",
        index, size, value, held_ticks, how, flow_active);
    write_marker(index, size, value, held_ticks);
}

bool mm_audit::any_stuck_sustained(StuckPool* out)
{
    StuckPool a[4], b[4];
    uint32_t na = scan_now(a, 4);
    if (na == 0) return false; // 现在干净——合法瞬时持有已结束
    ::Sleep(25);
    uint32_t nb = scan_now(b, 4);
    for (uint32_t i = 0; i < nb; i++)
    {
        for (uint32_t j = 0; j < na; j++)
        {
            if (b[i].index != a[j].index) continue;
            if (out) *out = b[i];
            report_once(b[i].index, b[i].block_size, b[i].value, 0, "guard", -1);
            return true;
        }
    }
    return false; // 两次采样不是同一池（各自瞬时）——放行
}

// 后台线程每秒一轮：池锁/全局锁 streak 巡检（机理①判据）。
static void tick_core(bool flow_active)
{
    const uint8_t* base = gm_base();
    if (!base) return;
    EnterCriticalSection(&g_cs);
    g_any_recent_nonzero = false;
    for (uint32_t idx = 0; idx < ADDR_MM_POOL_COUNT; idx += kIndexStep)
    {
        const uint8_t* p = pool_ptr(base, idx);
        uint8_t v = *(volatile const uint8_t*)p;
        uint32_t slot = idx / kIndexStep;
        if (v != 0)
        {
            g_any_recent_nonzero = true;
            g_last_nonzero.index = idx;
            g_last_nonzero.block_size = *(volatile const uint16_t*)(p + 2);
            g_last_nonzero.value = v;
            if (g_streak[slot] < 0xFFFF) g_streak[slot]++;
            if (g_streak[slot] == 2)
            {
                // Already holding g_cs: mark reported here, log + marker
                // outside the lock.
                if (slot < kSlots && !g_reported[slot]) g_reported[slot] = true;
                LeaveCriticalSection(&g_cs);
                gm_log("MMAudit: pool idx=%u size=%u lock=0x%02X held>=2 (tick, flow_active=%d) — "
                       "Delphi MM wedged; IDE save/reload may hang forever",
                    idx, g_last_nonzero.block_size, v, flow_active ? 1 : 0);
                write_marker(idx, g_last_nonzero.block_size, v, 2);
                return;
            }
        }
        else
        {
            g_streak[slot] = 0;
        }
    }
    // 全局锁（中/大块路径）：合法持有可到毫秒级，门槛 4 秒
    uint8_t gv = *(volatile const uint8_t*)(base + ADDR_MM_GLOBAL_LOCK);
    if (gv != 0)
    {
        if (g_global_streak < 0xFFFF) g_global_streak++;
        if (g_global_streak == 4 && !g_global_reported)
        {
            g_global_reported = true;
            LeaveCriticalSection(&g_cs);
            gm_log("MMAudit: GLOBAL lock byte=0x%02X held >=4 ticks (flow_active=%d)",
                gv, flow_active ? 1 : 0);
            write_marker(0xFFFFFFFF, 0, gv, 4);
            return;
        }
    }
    else
    {
        g_global_streak = 0;
    }
    // 本进程首次观测到全干净：清掉上次会话遗留的标记文件
    if (!g_marker_swept && !g_any_recent_nonzero && g_global_streak == 0)
    {
        g_marker_swept = true;
        wchar_t path[MAX_PATH];
        mm_audit::marker_path(path, MAX_PATH);
        if (path[0]) DeleteFileW(path);
    }
    LeaveCriticalSection(&g_cs);
}

bool mm_audit::last_nonzero(StuckPool* out)
{
    EnterCriticalSection(&g_cs);
    bool any = g_any_recent_nonzero;
    if (any && out) *out = g_last_nonzero;
    LeaveCriticalSection(&g_cs);
    return any;
}

void mm_audit::note_flow_active(bool active)
{
    InterlockedExchange(&g_flow_flag, active ? 1 : 0);
}

// 当前阶段：只存指针，字符串必须是静态存储期字面量。挂死取证读它标注现场，
// 区分"卡在重载的哪一段"——日志里的阶段日志停在挂死点之前，但那些行也可能
// 因为缓冲/顺序问题缺失，指针是即时可读的。
static const char* volatile g_stage = "";

void mm_audit::note_stage(const char* stage)
{
    InterlockedExchangePointer((void* volatile*)&g_stage, (void*)stage);
}

// ==== 挂死看门狗（机理②兜底 + 自动取证）====

// 任意地址所属模块。模块表由快照建立：取证时主线程被挂起，若此刻调用
// GetModuleHandleExW 之类的加载器 API，主线程正持加载器锁就会把审计线程一起
// 卡死。Toolhelp 快照不碰目标进程的加载器锁，在挂起主线程之前取一次即可。
struct ModRange
{
    uint32_t base, end;
    char name[32];
};

static ModRange g_mods[256];
static uint32_t g_mod_count = 0;

static void snapshot_modules()
{
    g_mod_count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do
        {
            if (g_mod_count >= _countof(g_mods)) break;
            ModRange& m = g_mods[g_mod_count++];
            m.base = (uint32_t)(uintptr_t)me.modBaseAddr;
            m.end = m.base + me.modBaseSize;
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, m.name, sizeof(m.name), NULL, NULL);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

static const ModRange* module_at(uint32_t addr)
{
    for (uint32_t i = 0; i < g_mod_count; i++)
        if (addr >= g_mods[i].base && addr < g_mods[i].end) return &g_mods[i];
    return NULL;
}

// 最近的导出符号（不含转发导出）：系统 DLL 里停住的地址只能这样读懂。
// 返回 "NtCreateFile+0xC" 形式；没有导出表或地址在首个导出之前返回 false。
static bool export_at(uint32_t addr, char* buf, size_t cch)
{
    const ModRange* mi = module_at(addr);
    if (!mi) return false;
    const uint8_t* b = (const uint8_t*)(uintptr_t)mi->base;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_DATA_DIRECTORY& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;
    const IMAGE_EXPORT_DIRECTORY* exp = (const IMAGE_EXPORT_DIRECTORY*)(b + dir.VirtualAddress);
    const DWORD* names = (const DWORD*)(b + exp->AddressOfNames);
    const WORD* ords = (const WORD*)(b + exp->AddressOfNameOrdinals);
    const DWORD* funcs = (const DWORD*)(b + exp->AddressOfFunctions);
    uint32_t rva = addr - mi->base, best = 0;
    const char* bestName = NULL;
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        uint32_t f = funcs[ords[i]];
        if (!f || f > rva || f < best) continue;
        best = f;
        bestName = (const char*)(b + names[i]);
    }
    if (!bestName) return false;
    _snprintf_s(buf, cch, _TRUNCATE, "%s+0x%X", bestName, rva - best);
    return true;
}

// 一行可读的地址描述：模块名+偏移。只有能解析到导出名且该导出不是模块唯一
// 的占位导出（GMSave.dll 只导出 Fake，标成 Fake+0x… 反而是噪音）时才附加符号。
static void describe_addr(char* buf, size_t cch, uint32_t addr)
{
    const ModRange* mi = module_at(addr);
    if (!mi)
    {
        _snprintf_s(buf, cch, _TRUNCATE, "0x%08X", addr);
        return;
    }
    char sym[96] = {};
    if (export_at(addr, sym, sizeof(sym)) && _strnicmp(sym, "Fake+", 5) != 0)
        _snprintf_s(buf, cch, _TRUNCATE, "%s+0x%X (%s)", mi->name, addr - mi->base, sym);
    else
        _snprintf_s(buf, cch, _TRUNCATE, "%s+0x%X", mi->name, addr - mi->base);
}

struct StackScan { uint32_t ptrs[30]; uint32_t n; uint32_t spinHits; };

// 只读扫主线程栈（ESP 向上 0x800 字节），不可读即停；收集落在任意已加载模块
// 内的代码指针（去重，前 30）并统计 Delphi MM 自旋特征值。POD+SEH。
// 不限定 exe/dll：真挂死可能停在 ntdll/kernel32 的系统调用里，只认自家模块
// 会把最有价值的返回地址滤掉。优先收集 exe 与 GMSave.dll 的指针——它们是
// "谁调用的"这条链的主体，系统 DLL 的返回地址只作补充。
static StackScan scan_stack(uint32_t esp)
{
    StackScan r = {};
    uint32_t ownFirst[30];
    uint32_t ownCount = 0;
    uint32_t other[30];
    uint32_t otherCount = 0;
    uint32_t exeB = (uint32_t)(uintptr_t)gm_base();
    const ModRange* self = module_at((uint32_t)(uintptr_t)&scan_stack);
    for (uint32_t off = 0; off < 0x800; off += 4)
    {
        uint32_t v;
        __try { v = *(volatile const uint32_t*)(esp + off); }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (v == kSpinFree || v == kSpinAlloc) r.spinHits++;
        const ModRange* mi = module_at(v);
        if (!mi) continue;
        bool own = (mi->base == exeB) || (self && mi->base == self->base);
        uint32_t* list = own ? ownFirst : other;
        uint32_t& n = own ? ownCount : otherCount;
        bool seen = false;
        for (uint32_t i = 0; i < n; i++) if (list[i] == v) { seen = true; break; }
        if (!seen && n < 30) list[n++] = v;
    }
    for (uint32_t i = 0; i < ownCount && r.n < 30; i++) r.ptrs[r.n++] = ownFirst[i];
    for (uint32_t i = 0; i < otherCount && r.n < 30; i++) r.ptrs[r.n++] = other[i];
    return r;
}

// 判挂死后的转储：主线程寄存器、栈上代码指针、池表快照、CAS 目标分型。
// 同时写日志与 %TEMP%\GMSave_Hang 下的独立文件——日志是 append 的，标记文件
// 在新进程首个干净 tick 会被清掉，只有独立文件能长期留作证据。
static void hang_forensics(HWND main, bool flow_active, uint32_t unresponsive_ms)
{
    uint8_t* base = gm_base();
    if (!base) { gm_log("MMAudit: forensics aborted, no exe base"); return; }
    snapshot_modules();

    DWORD tid = GetWindowThreadProcessId(main, NULL);
    HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
        THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!ht)
    {
        gm_log("MMAudit: forensics aborted, OpenThread(%u) err=%u", tid, GetLastError());
        return;
    }
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    SuspendThread(ht);
    BOOL gotCtx = GetThreadContext(ht, &ctx);
    ResumeThread(ht);
    CloseHandle(ht);
    if (!gotCtx)
    {
        gm_log("MMAudit: forensics aborted, GetThreadContext err=%u", GetLastError());
        return;
    }

    gm_log("MMAudit: MAIN THREAD UNRESPONSIVE — forensics (tid=%u, flow_active=%d, %u ms)",
        tid, flow_active ? 1 : 0, unresponsive_ms);
    const char* stage = (const char*)InterlockedCompareExchangePointer(
        (void* volatile*)&g_stage, NULL, NULL);
    gm_log("MMAudit:   stage='%s'", stage ? stage : "");
    char eip[160];
    describe_addr(eip, sizeof(eip), ctx.Eip);
    gm_log("MMAudit:   EIP=0x%08X %s", ctx.Eip, eip);
    gm_log("MMAudit:   EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    gm_log("MMAudit:   ESI=0x%08X EDI=0x%08X ESP=0x%08X EBP=0x%08X",
        ctx.Esi, ctx.Edi, ctx.Esp, ctx.Ebp);

    StackScan ss = scan_stack(ctx.Esp);
    for (uint32_t i = 0; i < ss.n; i += 3)
    {
        char l1[160], l2[160], l3[160];
        describe_addr(l1, sizeof(l1), ss.ptrs[i]);
        describe_addr(l2, sizeof(l2), i + 1 < ss.n ? ss.ptrs[i + 1] : 0);
        describe_addr(l3, sizeof(l3), i + 2 < ss.n ? ss.ptrs[i + 2] : 0);
        gm_log("MMAudit:   stack: %s | %s | %s", l1, l2, l3);
    }
    if (ss.spinHits)
        gm_log("MMAudit:   MM spin signatures on stack: %u (0x%X / 0x%X) — Delphi MM self-spin confirmed",
            ss.spinHits, kSpinFree, kSpinAlloc);

    // CAS 目标分型：池表内=池锁楔死；主线程栈地址=堆块元数据损坏；其余=未知。
    // 只在主线程确实停在 MM 自旋里时才有意义：栈上没有自旋签名时 EBX 只是
    // 某个系统调用的普通参数，据此分型会得出错误结论。
    uint32_t poolB = (uint32_t)(base + ADDR_MM_POOL_TABLE);
    uint32_t poolE = poolB + ADDR_MM_POOL_COUNT * 8;
    uint32_t ebx = ctx.Ebx;
    const wchar_t* en; const wchar_t* zh;
    if (!ss.spinHits)
    {
        en = L"not in the Delphi MM spin (no spin return address on the stack) - CAS target is unrelated";
        zh = L"未停在 Delphi MM 自旋内（栈上无自旋返回地址）——CAS 目标与堆锁无关";
    }
    else if (ebx >= poolB && ebx < poolE)
    {
        en = L"CAS target is inside the Delphi MM pool table - pool lock wedge";
        zh = L"CAS 目标落在 Delphi MM 池表内——池锁楔死（机理①）";
    }
    else if (ebx >= ctx.Esp - 0x10000 && ebx - ctx.Esp < 0x110000)
    {
        en = L"CAS target is an address inside the main thread's stack - heap block metadata corruption";
        zh = L"CAS 目标是主线程栈内的地址——堆块元数据损坏（机理②）";
    }
    else
    {
        en = L"CAS target is unrecognized";
        zh = L"CAS 目标无法识别";
    }
    // gm_log 走窄字符 vsnprintf：%s 收窄串、%S 收宽串。这里 en 是宽串，写成
    // %s 只会读出首字符。中文进宽字符的现场文件。
    gm_log("MMAudit:   CAS target EBX=0x%08X -> %S", ebx, en);

    mm_audit::StuckPool stuck[8];
    uint32_t ns = mm_audit::scan_now(stuck, 8);
    char locks[160] = "all zero";
    uint32_t o = 0;
    for (uint32_t i = 0; i < ns; i++)
        o += _snprintf_s(locks + o, sizeof(locks) - o, _TRUNCATE, "%s idx=%u v=0x%02X",
            i ? "," : " ", stuck[i].index, stuck[i].value);
    uint8_t glock = *(volatile const uint8_t*)(base + ADDR_MM_GLOBAL_LOCK);
    gm_log("MMAudit:   pool locks after hang: %s; global=0x%02X", locks, glock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    // 宽字符 printf 里 %s 收宽串、%S 收窄串：EIP 描述、池锁摘要、阶段名都是窄串。
    wchar_t body[2400];
    _snwprintf_s(body, _TRUNCATE,
        L"%s\r\n\r\n"
        L"%s: %u s\r\n"
        L"%s: %s\r\n"
        L"%s: %S\r\n"
        L"%s: 0x%08X %S\r\n"
        L"%s: EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\r\n"
        L"  ESI=0x%08X EDI=0x%08X ESP=0x%08X EBP=0x%08X\r\n"
        L"%s: %s\r\n"
        L"%s: %S\r\n\r\n"
        L"%s: pid=%u %04u-%02u-%02u %02u:%02u:%02u\r\n\r\n"
        L"%s\r\n",
        tr(L"GMSave: the Game Maker main thread has stopped responding (the IDE is hung).",
           L"GMSave：Game Maker 主线程已无响应（IDE 已挂死）。"),
        tr(L"Unresponsive for", L"已无响应"), unresponsive_ms / 1000,
        tr(L"In merge/reload flow", L"处于合并/重载流程"), flow_active ? L"yes" : L"no",
        tr(L"Stage", L"阶段"), stage ? stage : "",
        tr(L"EIP", L"指令指针"), ctx.Eip, eip,
        tr(L"Registers", L"寄存器"),
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx,
        ctx.Esi, ctx.Edi, ctx.Esp, ctx.Ebp,
        tr(L"Diagnosis", L"判定"), tr(en, zh),
        tr(L"Pool locks", L"池锁"), locks,
        tr(L"IDE", L"IDE"), GetCurrentProcessId(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        tr(L"Forensics were written to this file and to the log (%TEMP%\\GMSave.log).\r\n"
           L"The .gm80 project on disk is normally up to date - kill the process and reopen the project.",
           L"现场已写入本文件与日志（%TEMP%\\GMSave.log）。\r\n"
           L"磁盘上的 .gm80 工程一般已是最新；请直接结束 Game Maker 进程后重新打开工程。"));

    wchar_t dump[MAX_PATH];
    hang_dump_path(dump, MAX_PATH);
    write_utf16_file(dump, body);
    char dumpA[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_ACP, 0, dump, -1, dumpA, sizeof(dumpA), NULL, NULL);
    gm_log("MMAudit:   dump written to '%s'", dumpA);

    write_marker_text(body);
}

// 主窗体探针。SMTO_ABORTIFHUNG 在目标线程不泵消息时立即超时，因此这里测的
// 是"主线程还活着吗"，与窗口是否真忙无关。
//
// 判挂死按真实经过时间而非轮数：一轮是 1 秒节拍加最多 800 毫秒探测，轮数与
// 时长不成正比，按轮数算阈值会让实际等待翻倍。
//
// 阈值按流程内/外分级：流程内（合并、暂存保存、重载）每一步都会泵消息，30 秒
// 不响应即真挂死；流程外的长阻塞主要是 GM 自己编译工程，整段不泵消息，用宽
// 阈值避开误报。
//
// 恢复响应后重新武装：一次挂死只留一份现场，但同一进程可以多次挂死，且误报
// 不能消耗掉后续真挂死的取证机会。
static void hang_watchdog()
{
    HWND main = FindWindowW(L"TMainForm", NULL);
    if (!main)
    {
        g_unresponsive_since = 0;
        g_hang_dumped = false;
        return;
    }
    DWORD_PTR res = 0;
    LRESULT ok = SendMessageTimeoutW(main, WM_NULL, 0, 0,
        SMTO_ABORTIFHUNG | SMTO_BLOCK, 800, &res);
    if (ok)
    {
        g_unresponsive_since = 0;
        g_hang_dumped = false;
        return;
    }
    ULONGLONG now = GetTickCount64();
    if (!g_unresponsive_since) g_unresponsive_since = now;
    uint32_t elapsed = (uint32_t)(now - g_unresponsive_since);
    bool flow_active = InterlockedCompareExchange(&g_flow_flag, 0, 0) != 0;
    uint32_t need = flow_active ? kHangMsInFlow : kHangMsIdle;
    if (elapsed < need) return;
    if (g_hang_dumped || g_dump_count >= kMaxDumps) return;
    g_hang_dumped = true;
    g_dump_count++;
    hang_forensics(main, flow_active, elapsed);
}

void mm_audit::start()
{
    static bool started = false;
    if (started) return;
    started = true;
    HANDLE h = CreateThread(NULL, 0,
        [](LPVOID) -> DWORD {
            for (;;)
            {
                Sleep(1000);
                tick_core(InterlockedCompareExchange(&g_flow_flag, 0, 0) != 0);
                hang_watchdog();
            }
        }, NULL, 0, NULL);
    if (h) CloseHandle(h);
    gm_log("MMAudit: background audit thread started (1s tick + hang watchdog)");
}
