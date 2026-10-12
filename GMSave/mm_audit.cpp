#include "pch.h"
#include "mm_audit.h"
#include "gm80_addresses.h"
#include "gm_log.h"
#include "i18n.h"
#include <cstdio>

// 池表布局与锁语义见 mm_audit.h。索引步 4（= 记录步长 32 字节 / 8）。
static const uint32_t kIndexStep = 4;
static const uint32_t kSlots = ADDR_MM_POOL_COUNT / kIndexStep;
// GM8 Delphi MM 的 CAS 自旋循环返回地址（free/alloc 路径）——栈上出现即坐实
// 主线程卡在 MM 锁/块头自旋里。
static const uint32_t kSpinFree = 0x401CFE;
static const uint32_t kSpinAlloc = 0x4019B3;
// 看门狗判挂死需要的连续超时次数（1s 节拍 + 800ms 探测超时 ⇒ 约 9 秒）。
static const uint32_t kHangStreakNeeded = 5;

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
static volatile LONG g_hang_streak = 0;  // 看门狗连续超时次数（后台线程私有）
static bool g_hang_reported = false;     // 挂死取证每进程只做一次

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

// 标记文件：给（不一定看日志的）用户的持久提示 + 给我方后续诊断的现场记录。
// UTF-16LE + BOM（Notepad 可直接识别，不受系统代码页影响）。
static void write_marker_text(const wchar_t* body)
{
    wchar_t path[MAX_PATH];
    mm_audit::marker_path(path, MAX_PATH);
    if (!path[0]) return;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    static const uint8_t bom[2] = { 0xFF, 0xFE };
    DWORD wrote = 0;
    WriteFile(h, bom, 2, &wrote, NULL);
    WriteFile(h, body, (DWORD)(wcslen(body) * sizeof(wchar_t)), &wrote, NULL);
    CloseHandle(h);
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

// ==== 挂死看门狗（机理②兜底 + 自动取证）====

static uint32_t module_end(HMODULE h)
{
    if (!h) return 0;
    const uint8_t* b = (const uint8_t*)h;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return (uint32_t)b + nt->OptionalHeader.SizeOfImage;
}

// "0x%08X (module+0x%X)" / "0x%08X"
static void loc_str(char* buf, size_t cch, uint32_t a, uint32_t exeB, uint32_t exeE,
    uint32_t dllB, uint32_t dllE)
{
    if (a >= exeB && a < exeE)
        _snprintf_s(buf, cch, _TRUNCATE, "Game_Maker.exe+0x%X", a - exeB);
    else if (dllB && a >= dllB && a < dllE)
        _snprintf_s(buf, cch, _TRUNCATE, "GMSave.dll+0x%X", a - dllB);
    else
        _snprintf_s(buf, cch, _TRUNCATE, "0x%08X", a);
}

struct StackScan { uint32_t ptrs[30]; uint32_t n; uint32_t spinHits; };

// 只读扫主线程栈（ESP 向上 0x800 字节），不可读即停；收集 exe/dll 范围内的
// 代码指针（去重，前 30）并统计 Delphi MM 自旋特征值。POD+SEH。
static StackScan scan_stack(uint32_t esp, uint32_t exeB, uint32_t exeE,
    uint32_t dllB, uint32_t dllE)
{
    StackScan r = {};
    for (uint32_t off = 0; off < 0x800; off += 4)
    {
        uint32_t v;
        __try { v = *(volatile const uint32_t*)(esp + off); }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (v == kSpinFree || v == kSpinAlloc) r.spinHits++;
        bool inExe = v >= exeB && v < exeE;
        bool inDll = dllB && v >= dllB && v < dllE;
        if (!inExe && !inDll) continue;
        bool seen = false;
        for (uint32_t i = 0; i < r.n; i++) if (r.ptrs[i] == v) { seen = true; break; }
        if (!seen && r.n < 30) r.ptrs[r.n++] = v;
    }
    return r;
}

// 判挂死后一次性转储：主线程寄存器、栈上代码指针、池表快照、CAS 目标分型。
static void hang_forensics(HWND main)
{
    uint8_t* base = gm_base();
    HMODULE self = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&hang_forensics, &self);
    if (!base) { gm_log("MMAudit: forensics aborted, no exe base"); return; }
    uint32_t exeB = (uint32_t)base, exeE = module_end((HMODULE)base);
    uint32_t dllB = (uint32_t)self, dllE = module_end(self);

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

    gm_log("MMAudit: MAIN THREAD UNRESPONSIVE — forensics (tid=%u)", tid);
    char loc[64];
    loc_str(loc, sizeof(loc), ctx.Eip, exeB, exeE, dllB, dllE);
    gm_log("MMAudit:   EIP=0x%08X (%s)", ctx.Eip, loc);
    gm_log("MMAudit:   EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    gm_log("MMAudit:   ESI=0x%08X EDI=0x%08X ESP=0x%08X EBP=0x%08X",
        ctx.Esi, ctx.Edi, ctx.Esp, ctx.Ebp);

    StackScan ss = scan_stack(ctx.Esp, exeB, exeE, dllB, dllE);
    for (uint32_t i = 0; i < ss.n; i += 3)
    {
        char l1[64], l2[64], l3[64];
        loc_str(l1, sizeof(l1), ss.ptrs[i], exeB, exeE, dllB, dllE);
        loc_str(l2, sizeof(l2), i + 1 < ss.n ? ss.ptrs[i + 1] : 0,
            exeB, exeE, dllB, dllE);
        loc_str(l3, sizeof(l3), i + 2 < ss.n ? ss.ptrs[i + 2] : 0,
            exeB, exeE, dllB, dllE);
        gm_log("MMAudit:   stack: %s | %s | %s", l1, l2, l3);
    }
    if (ss.spinHits)
        gm_log("MMAudit:   MM spin signatures on stack: %u (0x%X / 0x%X) — Delphi MM self-spin confirmed",
            ss.spinHits, kSpinFree, kSpinAlloc);

    // CAS 目标分型：池表内=池锁楔死；主线程栈地址=堆块元数据损坏；其余=未知
    uint32_t poolB = (uint32_t)(base + ADDR_MM_POOL_TABLE);
    uint32_t poolE = poolB + ADDR_MM_POOL_COUNT * 8;
    uint32_t ebx = ctx.Ebx;
    const wchar_t* en; const wchar_t* zh;
    if (ebx >= poolB && ebx < poolE)
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
    gm_log("MMAudit:   CAS target EBX=0x%08X -> %S", ebx, zh);

    mm_audit::StuckPool stuck[8];
    uint32_t ns = mm_audit::scan_now(stuck, 8);
    char locks[128] = "all zero";
    uint32_t o = 0;
    for (uint32_t i = 0; i < ns; i++)
        o += _snprintf_s(locks + o, sizeof(locks) - o, _TRUNCATE, "%s idx=%u v=0x%02X",
            i ? "," : " ", stuck[i].index, stuck[i].value);
    uint8_t glock = *(volatile const uint8_t*)(base + ADDR_MM_GLOBAL_LOCK);
    gm_log("MMAudit:   pool locks after hang: %s; global=0x%02X", locks, glock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t body[1400];
    _snwprintf_s(body, _TRUNCATE,
        L"%s\r\n\r\n"
        L"%s: ~%u s\r\n"
        L"%s (CAS target=0x%08X)\r\n"
        L"%s: pid=%u %04u-%02u-%02u %02u:%02u:%02u\r\n\r\n"
        L"%s\r\n",
        tr(L"GMSave: the Game Maker main thread has stopped responding (the IDE is hung).",
           L"GMSave：Game Maker 主线程已无响应（IDE 已挂死）。"),
        tr(L"Unresponsive for", L"已无响应"), kHangStreakNeeded,
        tr(en, zh), ebx,
        tr(L"IDE", L"IDE"), GetCurrentProcessId(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        tr(L"Forensics were written to the log (%TEMP%\\GMSave.log).\r\n"
           L"The .gm80 project on disk is normally up to date - kill the process and reopen the project.",
           L"现场已写入日志（%TEMP%\\GMSave.log）。\r\n"
           L"磁盘上的 .gm80 工程一般已是最新；请直接结束 Game Maker 进程后重新打开工程。"));
    write_marker_text(body);
}

static void hang_watchdog()
{
    if (g_hang_reported) return;
    HWND main = FindWindowW(L"TMainForm", NULL);
    if (!main) { g_hang_streak = 0; return; }
    DWORD_PTR res = 0;
    LRESULT ok = SendMessageTimeoutW(main, WM_NULL, 0, 0,
        SMTO_ABORTIFHUNG | SMTO_BLOCK, 800, &res);
    if (ok) { g_hang_streak = 0; return; }
    g_hang_streak++;
    if (g_hang_streak < kHangStreakNeeded) return;
    g_hang_reported = true;
    hang_forensics(main);
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
