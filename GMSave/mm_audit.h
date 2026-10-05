// GM8 Delphi MM 池锁巡检 —— 外部改动重载"未响应"的根因监控（详见记忆
// gmsave-reload-hang）：GM8 老式 Delphi MM 的小块池表是静态区一张表
// （ADDR_MM_POOL_TABLE，池记录 32 字节步长、索引步 4），锁字节在 pool+0，
// 合法值只有 0（未持有）与 1（持有，仅几十条指令的临界区）。任何池锁字节
// 长期非 0 且无释放者 ⇒ 下一次该池的 alloc/free 在 GM 自己的 CAS 自旋里
// 永久死循环（free 路径 0x401CFE / alloc 路径 0x4019B3），表现为重载时
// "加载游戏数据"进度窗永久未响应。中/大块路径另有一把全局锁。
//
// 本模块只读进程内存（无分配、无 Delphi MM 调用、不 sleep 竞争），主线程
// 每 1 秒巡检一次的代价约为几百纳秒，可在 WM_TIMER 里随意调用。
#pragma once
#include <cstdint>

namespace mm_audit {

struct StuckPool
{
    uint32_t index;      // 表索引，地址 = base + ADDR_MM_POOL_TABLE + 8*index
    uint16_t block_size; // pool+2（块尺寸，日志/标记文件用）
    uint8_t value;       // 观察到的锁字节值（非 0）
};

// 立即扫描一轮，把非 0 锁的池写入 out（最多 max 项）。
// 返回实际写入的项数（不是总命中数——守卫只关心能不能判定）。
uint32_t scan_now(StuckPool* out, uint32_t max);

// 持续判据，给流程入口守卫用：两次采样（间隔约 25ms）里同一个池的锁都非 0
// ⇒ 不可能是合法瞬时持有（临界区为微秒级）。返回 true 时 out 填该池，
// 同时写日志与 %TEMP%\GMSave_MMBroken.txt 标记文件（每池每进程一次）。
bool any_stuck_sustained(StuckPool* out);

// 1 秒 tick 巡检（主线程，随 watcher 的 WM_TIMER 调用）：
//   同一池锁连续 2 次（≥1s）非 0 ⇒ 判定卡死，写日志 + 标记文件（每池一次）；
//   全局锁门槛放宽到 4 次（合法持有可到毫秒级）；flow_active 仅供日志。
//   本进程首次观测到全部干净时删除遗留的标记文件（重启后自愈）。
void tick(bool flow_active);

// 上一轮 tick 是否观测到非 0 锁；true 时 out 填那一次观测到的池（供日志）。
// O(1)，tick 流程守卫的廉价初筛。
bool last_nonzero(StuckPool* out);

// 标记文件路径（%TEMP%\GMSave_MMBroken.txt）；无 %TEMP% 时返回空。
void marker_path(wchar_t* buf, uint32_t cch);

} // namespace mm_audit
