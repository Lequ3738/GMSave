// GM8 Delphi MM 巡检与挂死看门狗 —— 重载"未响应"的根因监控（详见记忆
// gmsave-reload-hang）。已知两类挂死机理，症状同形（重载时 IDE 永久未响应）：
//
//   ① 池锁卡死：小块池表（ADDR_MM_POOL_TABLE，池记录 32 字节步长、索引步 4）
//      的锁字节在 pool+0，合法值只有 0（未持有）与 1（持有，微秒级临界区）。
//      任何池锁长期非 0 且无释放者 ⇒ 下一次该池的 alloc/free 在 GM 自己的
//      CAS 自旋里永久死循环（free 路径 0x401CFE / alloc 路径 0x4019B3）。
//      中/大块路径另有一把全局锁（ADDR_MM_GLOBAL_LOCK）。
//   ② 堆块元数据损坏：越界写把栈地址等垃圾写进堆块头 ⇒ SysFreeMem 拿垃圾当
//      池记录做 CAS。此时所有锁字节为 0，①的判据结构性查不出——只能靠
//      "主线程不再泵消息"这一外部症状兜底。
//
// 本模块自建一条常驻后台线程（start，随 watcher 首次启动拉起），每秒：
//   tick  —— 池表/全局锁 streak 巡检（①判据，连续 2 次非 0 即告警）；
//   看门狗 —— SendMessageTimeoutW(WM_NULL, SMTO_ABORTIFHUNG) 探主窗体，连续
//      5 次超时（约 9 秒全程不泵消息）判挂死。保存/重载/合并各段都有进度窗
//      泵消息，最长不泵段 <2s，正常流程不会误报；
//   取证 —— 判挂死时一次性转储主线程寄存器、栈上代码指针、池表快照进日志，
//      按 CAS 目标分型（池锁 / 堆损坏 / 未知），写 %TEMP%\GMSave_MMBroken.txt。
//
// 主线程不参与巡检：主线程一卡，WM_TIMER 即停摆（失明教训）。巡检全程只读
// 进程内存，无分配、无 Delphi MM 调用，与游戏线程无竞争。
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

// 持续判据，给流程入口守卫用（主线程）：两次采样（间隔约 25ms）里同一个池
// 的锁都非 0 ⇒ 不可能是合法瞬时持有。返回 true 时 out 填该池，同时写日志与
// %TEMP%\GMSave_MMBroken.txt 标记文件（每池每进程一次）。
bool any_stuck_sustained(StuckPool* out);

// 上一轮后台 tick 是否观测到非 0 锁；true 时 out 填那一次观测到的池（供日志）。
// O(1)，流程守卫的廉价初筛。
bool last_nonzero(StuckPool* out);

// 标记文件路径（%TEMP%\GMSave_MMBroken.txt）；无 %TEMP% 时返回空。
void marker_path(wchar_t* buf, uint32_t cch);

// 幂等启动常驻巡检线程（watcher 首次启动时调用；主线程上下文，非 DllMain）。
void start();

// 流程进行中标志，仅供巡检日志的 flow_active 字段；主线程在流程进出处同步。
void note_flow_active(bool active);

} // namespace mm_audit
