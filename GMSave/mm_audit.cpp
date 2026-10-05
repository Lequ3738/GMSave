#include "pch.h"
#include "mm_audit.h"
#include "gm80_addresses.h"
#include "gm_log.h"
#include "i18n.h"
#include <cstdio>

// 池表布局与锁语义见 mm_audit.h。索引步 4（= 记录步长 32 字节 / 8）。
static const uint32_t kIndexStep = 4;
static const uint32_t kSlots = ADDR_MM_POOL_COUNT / kIndexStep;

// 巡检状态（仅主线程读写：WM_TIMER tick 与流程入口守卫都在主线程）
static uint16_t g_streak[kSlots];        // 连续观测到非 0 的次数
static uint16_t g_global_streak = 0;     // 全局锁连续观测次数
static bool g_reported[kSlots];          // 每池每进程只报一次
static bool g_global_reported = false;
static bool g_any_recent_nonzero = false;
static mm_audit::StuckPool g_last_nonzero = {}; // 上一轮 tick 首个非零池（日志用）
static bool g_marker_swept = false;      // 本进程已做过遗留标记文件清理

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
static void write_marker(uint32_t index, uint16_t size, uint8_t value, uint32_t held_ticks)
{
    wchar_t path[MAX_PATH];
    mm_audit::marker_path(path, MAX_PATH);
    if (!path[0]) return;
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
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    static const uint8_t bom[2] = { 0xFF, 0xFE };
    DWORD wrote = 0;
    WriteFile(h, bom, 2, &wrote, NULL);
    WriteFile(h, body, (DWORD)(wcslen(body) * sizeof(wchar_t)), &wrote, NULL);
    CloseHandle(h);
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
    if (slot < kSlots)
    {
        if (g_reported[slot]) return;
        g_reported[slot] = true;
    }
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

void mm_audit::tick(bool flow_active)
{
    const uint8_t* base = gm_base();
    if (!base) return;
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
                report_once(idx, *(volatile const uint16_t*)(p + 2), v, 2, "tick",
                    flow_active ? 1 : 0);
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
            gm_log("MMAudit: GLOBAL lock byte=0x%02X held >=4 ticks (flow_active=%d)",
                gv, flow_active ? 1 : 0);
            write_marker(0xFFFFFFFF, 0, gv, 4);
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
        marker_path(path, MAX_PATH);
        if (path[0]) DeleteFileW(path);
    }
}

bool mm_audit::last_nonzero(StuckPool* out)
{
    if (g_any_recent_nonzero && out) *out = g_last_nonzero;
    return g_any_recent_nonzero;
}
