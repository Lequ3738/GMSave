# GM 8.0 IDE VCL 菜单注入指南

> 2026-09-20 由"检测死资源"菜单项（`dead_asset_check.cpp`）的完整逆向与实测沉淀。
> 所有地址已在 IDB 命名并 `idb_save`（前缀 `GM80_`），代码内宏见 `dead_asset_check.cpp` 头部。
> 结论先行：**这套 IDE 是标准 Delphi VCL 菜单体系（TMainMenu/TMenuItem，单元 Menus），
> 但编译器版本比典型 Delphi 7 新，偏移一律以本二进制的 RTTI 取证为准，不要抄任何书上的 VCL 布局表。**

## 一、权威取证方法（新偏移一律这样拿，不要猜）

### 1. 定位一个类的 VMT

1. 类名是 Pascal 短字符串（长度前缀、无 null 结尾），IDA 的 strings 视图搜不到，
   用 `find_bytes` 搜字节序列，如 `09 54 4D 61 69 6E 46 6F 72 6D` = `09 "TMainForm"`。
2. 在数据段（0x450000–0x600000）扫 dword 等于该字符串地址 → 命中处即 **vmtClassName 槽 = VMT − 0x2C**
   → VMT = 命中地址 + 0x2C。
3. 注意：这套 VCL 的 **VMT+0 不是自指指针**（是方法槽），别用"自指"校验 VMT。
   用三个独立证据交叉确认：className 槽指向类名字符串、InstanceSize（VMT−0x28）合理、
   FieldTable（VMT−0x38）解析出合理字段。

### 2. FieldTable（published 字段：名字 + 偏移）

- 位置：`*(VMT − 0x38)`。
- 头部 12 字节（count 在最前，其后是指向类名字符串尾的指针等），**首个条目在 FieldTable+0xC**。
- 条目 = `len + name + offset(u16) + pad(u16) + type(u16)`，步进 `7 + len`。
- ⚠️ FieldTable 只含 published **字段**（DFM 流化的组件引用，如 File1/Scripts1）；
  property 的 private 字段（Caption、OnClick…）不在其中。
- ⚠️ **实测教训**：TMainForm FieldTable 声称 `Scripts1 @ +0x52C`，但代码往它挂菜单项时
  项落进了"导入脚本"——字段表存在错位/失真。**注入目标一律用 Caption 运行时匹配，
  不要硬信 FieldTable 偏移**（方法见下文"三"）。

### 3. property 表（published 属性：事件/简单属性的字段偏移）——最权威

- 位置：`vmtTypeInfo = *(VMT − 0x3C)`。
- 结构（本 VCL）：`Kind(byte) + 类名(短串) + Parent(dword) + 2×dword + word + 单元名(短串)
  + PropCount(u16) + TPropInfo[]`。
- 每个 `TPropInfo`（本 VCL 头 **26 字节**，比 D7 多 4）：
  `PropType(dword) GetProc(dword) SetProc(dword) Index(dword) Default(dword) Extra(dword)
  NameIdx(u16) 名字(短串)`，名字在 +0x1A。
- **字段偏移编码**：GetProc/SetProc 高字节 = `0xFF` 表示直接字段访问，偏移 = **值 & 0xFFFFFF
  （直接就是偏移，不右移）**，如 Caption 的 Set=0xFF000030 → +0x30。校准锚点：Caption=+0x30
  （SetCaption 反编译写 [self+0x30]）、ImageIndex=+0x40（Create 反编译默认写 −1）。
  （解析脚本若画蛇添足右移一位会得到减半的值，注意。）
- TMenuItem property 表解码结果（2026-09-20，`0x453F88` 处，22 项）：

| 属性 | 字段偏移 | 说明 |
|---|---|---|
| Tag（继承自 TComponent） | +0x0C | |
| Caption | **+0x30** | AnsiString，SetCaption=0x4573F8（LStrAsg） |
| Checked / Enabled（位打包） | +0x38 | byte 标志位 |
| Default / AutoHotkeys（位打包） | +0x3A | |
| RadioItem / AutoLineReduction（位打包） | +0x3C | |
| GroupIndex / Visible（位打包） | +0x3E | |
| ImageIndex | **+0x40** | Create 默认 −1，无需再设 |
| HelpContext | +0x54 | |
| Hint | +0x58 | AnsiString |
| ShortCut | **+0x60** | |
| **OnClick** | **+0x88（method）/ +0x8C（data）** | TNotifyEvent；8.0/8.1 相同 |
| OnDrawItem | +0x90 / +0x94 | |
| OnAdvancedDrawItem | +0x98 / +0x9C | |
| OnMeasureItem | +0xA0 / +0xA4 | |

## 二、注入一个菜单项（完整序列，全部实测）

目标：往 IDE 顶部某个下拉菜单（如"脚本(S)"）末尾加一项。

```cpp
// 0. 拿主窗体（注意：二级指针！）
void** slot = *(void***)(base + 0x1EA5AC);   // 0x5EA5AC 处存的是"指针槽的地址"
void* mainForm = slot ? *slot : nullptr;     // TMainForm 实例在 *(0x5EA5AC 的值)
// GM 自己 35 处引用全是双重解引用（如 0x4F117D）。少解一层 = 拿到数据段地址，
// 后续全部读垃圾 —— 三个注入版本的全部失败皆因于此。

// 1. 找目标菜单（Caption 运行时匹配，见"三"）
void* scriptsMenu = /* 见下文 */;

// 2. 创建 TMenuItem（照抄 GM 调用点 0x59EB76 的序列）
uint32_t classref = *(uint32_t*)(base + 0x53EA0);  // 值 0x453EEC = TMenuItem VMT
void* item = nullptr;
__asm {
    mov dl, 1
    mov eax, classref
    xor ecx, ecx        // ★ ecx = AOwner！不清零 = 垃圾指针被 InsertComponent
    call fnCreate       //   解引用 → 闪退。GM 调用点的残留恰好无害，别学。
    mov item, eax
}                       // Create=0x455414；内部已置 ImageIndex=-1(+0x40) 等

// 3. 设标题（伪 AnsiString 常量：data-8=refcnt −1、data-4=长度；LStrAsg 对常量只存指针）
__asm { mov edx, capStr; mov eax, item; call fnCaption }   // SetCaption=0x4573F8

// 4. 事件（TNotifyEvent：method ptr + self，两半分开写）
*(uint32_t*)((uint8_t*)item + 0x88) = (uint32_t)&thunk;    // OnClick method
*(uint32_t*)((uint8_t*)item + 0x8C) = (uint32_t)item;      // OnClick self
// ★ 只写 0x88/0x8C。GM 动态建菜单的调用点 0x45884D 写的 +0x80/+0x84 是
//   私有内部字段——写进去后菜单系统绘制时把它当内部指针调用，
//   表现为"悬停即触发"。这是实测踩过的坑。

// 5. 挂到菜单（Add = Insert(GetCount(self), item)，eax=目标菜单项、edx=新项）
__asm { mov edx, item; mov eax, scriptsMenu; call fnAdd }  // Add=0x457914
```

### 时序（什么时候注入）

- DllMain 时主窗体还不存在。
- **DLL attach 时 `SetWinEventHook(EVENT_OBJECT_SHOW, ..., WINEVENT_OUTOFCONTEXT)`**
  过滤窗口类名 `TMainForm`，首次显示即注入，成功后 `UnhookWinEvent` 一次性收尾；
  回调经主线程消息泵派发。
- 兜底：watcher 启动 + 隐藏 timer 窗口的 WM_TIMER（1s）幂等重试，直到 `menu_ready`。
- 教训：UI 注入时机不能依赖用户工作流（"用户会先打开工程"不成立）。

## 三、找"目标菜单"本身（Caption 匹配，不要信字段表）

候选字段（主窗体 published TMenuItem 字段，围绕 FieldTable 声称的区域 ± 若干）逐个：

1. VMT 校验：`*(uint32_t*)p == *(uint32_t*)(base + 0x53EA0)`（都是 TMenuItem 实例）；
2. 读 Caption：`*(const char**)(p + 0x30)`（Pascal 记法 AnsiString 数据指针），
   `ansi_to_wide` 转宽、剥 `&` 加速符；
3. 与 `tr(L"Scripts", L"脚本")` 前缀匹配（兼容 `脚本(&S)`/`Scripts` 两种形态）。

全部落空时把各候选的 Caption 打进日志一次性 dump（Debug 版），
一眼看出每个字段的真实身份。**不要硬编码 FieldTable 的偏移当事实。**

## 四、菜单项渲染文本语言

Caption 用 `tr(en, zh)` + `WideCharToMultiByte(CP_ACP)` 转 GBK 伪 AnsiString；
汉化版 IDE 全 ANSI 字符串，GBK 与其一致。弹窗正文同理走 `MessageBoxW` + `tr`。

## 五、其它坑（全都踩过）

| 坑 | 症状 | 规则 |
|---|---|---|
| naked asm 引用 C 函数未先定义 | C2094 | 定义放调用者之后，前向声明不带 naked |
| naked 用于声明 | C2488 | 只能修饰定义 |
| 局部变量名撞 x87 助记符（如 `sub`） | C4405 | 改名 |
| `__DATE__/__TIME__` 构建戳 | 三段日志同戳 | 增量编译不重编 dllmain 就不更新，别拿它判版本 |
| gm_log Release 无日志 | 日志缺行≠没发生 | 开发期部署 Debug，稳定才 Release（用户设计意图，不改 gm_log） |
| 日志跨会话累积 | 新旧混杂 | 部署流程固定：编译 → 删 `%TEMP%\GMSave.log` → cp → md5 |

## 六、地址速查（RVA = 绝对 − 0x400000；8.0）

| 名称 | RVA | 绝对 | IDB 命名 |
|---|---|---|---|
| 主窗体指针槽的地址（二级） | 0x1EA5AC | 0x5EA5AC | GM80_MainFormPtrPtr |
| 主窗体指针槽本体 | — | 0x60ADE8 | GM80_MainForm（IDB 已迁移此语义） |
| TMenuItem classref | 0x53EA0 | 0x453EA0 | GM80_classref_TMenuItem |
| TMenuItem VMT | — | 0x453EEC | GM80_vmt_TMenuItem |
| TMenuItem.Create | 0x55414 | 0x455414 | GM80_MenuItem_Create |
| TMenuItem.SetCaption | 0x573F8 | 0x4573F8 | GM80_MenuItem_SetCaption |
| TMenuItem.Add | 0x57914 | 0x457914 | GM80_MenuItem_Add |
| TMenuItem.GetCount | 0x57594 | 0x457594 | GM80_MenuItem_GetCount |
| TMenuItem.Insert | 0x57720 | 0x457720 | GM80_MenuItem_Insert |
| TMainMenu VMT | — | 0x45440C | GM80_vmt_TMainMenu |
| TMenu VMT | — | 0x454310 | GM80_vmt_TMenu |
| TMainForm VMT | — | 0x5D7358 | GM80_vmt_TMainForm |
| TMainForm classref | — | 0x5D730C | GM80_classref_TMainForm |
| TApplication.CreateForm | 0x7F310 | 0x47F310 | GM80_Application_CreateForm |
| 工程路径全局 char* | 0x1EA27C | 0x5EA27C | （GM80_ProjectPath） |

## 七、换一个菜单挂（步骤）

1. 用"一、3"的 property 表方法拿到 TMenuItem 已知偏移（本表已全量，无需重做）；
2. 用"三"的方法把主窗体候选字段的 Caption dump 一遍，确定目标菜单在哪个字段
   （或直接从现有 `offs[]` 数组加候选）；
3. 其余序列与"二"完全一致；OnClick 的 thunk 换成你的处理函数。
