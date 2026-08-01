// GM 8.0 IDE memory addresses — verified via IDA similarity search against GM 8.1
// All values are offsets from GetModuleHandle(NULL) base.
// Format: A_D_D_R_E_S_S absolute = base + O_F_F_S_E_T
#pragma once

// ==== Delphi RTL (Delphi 7 AnsiString era) ====
#define ADDR_COMPARETEXT           0xA0C8     // CompareText — case-insensitive AnsiString compare
#define ADDR_LSTRASG              0x005528   // @LStrAsg — AnsiString assign
#define ADDR_LSTRCAT              0x005544   // @LStrCat — AnsiString concat (+0x1C from LStrAsg)
#define ADDR_LSTRCLR              0x0047E8   // @LStrClr — AnsiString free
#define ADDR_MEMSTREAM_CREATE     0x004560   // TMemoryStream.Create
#define ADDR_TOBJECT_FREE         0x004590   // TObject.Free
#define ADDR_GETCURRENTTIME       0x0CF18    // Now() / GetCurrentTime — returns double

// ==== Save / Load / Init ====
#define ADDR_SAVE_PROJECT         0x19B620   // Save project to stream (section dispatcher)
#define ADDR_SAVE_OUTER           0x19BA38   // Save project outer (backup + stream creation)
#define ADDR_LOAD_PROJECT         0x1D453C   // Load project from stream (section dispatcher)
#define ADDR_CMPTEXT_SAVE_HOOK    0x1DACEC   // CALL CompareText(ext, ".gmk") — direct save check
#define ADDR_GMK_STRING_DATA      0x1DAD58   // ".gmk" Delphi AnsiString data ptr for save check
#define ADDR_DIRECT_SAVE_CALL     0x1DAD19   // CALL sub_59BA38 — direct save (Ctrl+S path)
#define ADDR_RELOAD_ACTIONS       0x1A93B4   // Reload action libraries (project init hook point)
#define ADDR_SAVE_PREFERENCES     0x0EC4D8   // Registry write (save preferences)
#define ADDR_LOAD_PREFERENCES     0x0EC690   // Registry read (load preferences)

// ==== Section serializers (called from ADDR_SAVE_PROJECT) ====
#define ADDR_SAVE_SETTINGS        0x19E648
#define ADDR_SAVE_SPRITES         0x15D2F0
#define ADDR_SAVE_SOUNDS          0x173618
#define ADDR_SAVE_BACKGROUNDS     0x1462F0
#define ADDR_SAVE_PATHS           0x14032C
#define ADDR_SAVE_SCRIPTS         0x136A74
#define ADDR_SAVE_FONTS           0x156E14
#define ADDR_SAVE_TIMELINES       0x15BB9C
#define ADDR_SAVE_OBJECTS         0x158C54
#define ADDR_SAVE_ROOMS           0x162638
#define ADDR_SAVE_INCLUDED_FILES  0x1965B0
#define ADDR_SAVE_EXTENSIONS      0x153E20
#define ADDR_SAVE_GAME_INFO       0x19AE20
#define ADDR_SAVE_LIBRARY_INIT    0x1A7D4C
#define ADDR_SAVE_ROOM_ORDER      0x1991A0
#define ADDR_SAVE_RESOURCE_TREE   0x1A96A8

// ==== Resource Timestamp Updates ====
#define ADDR_UPDATE_SPRITE_TS     0x140810
#define ADDR_UPDATE_SOUND_TS      0x16F5F8  // verified via similarity (high confidence)
#define ADDR_UPDATE_BG_TS         0x146F68   // verified via similarity
#define ADDR_UPDATE_PATH_TS       0x13FFD0   // verified via similarity
#define ADDR_UPDATE_SCRIPT_TS     0x136F5C
#define ADDR_UPDATE_FONT_TS       0x1590C4
#define ADDR_UPDATE_TIMELINE_TS   0x157284
#define ADDR_UPDATE_OBJECT_TS     0x196AE0
#define ADDR_UPDATE_ROOM_TS       0x162AA4

// ==== Resource Arrays (verified from save function decomplilation) ====
// Each resource has: array of pointers (4B/entry), count (u32),
// timestamps array (double/8B), updated flag (byte)
struct GM80ResourceGlobals {
    uint32_t off_array;
    uint32_t off_count;
    uint32_t off_timestamps;
    uint32_t off_updated_flag;
};

#define RESOURCE_SPRITES      {0x1E92E8, 0x1E92EC, 0x1EFD1C, 0x1EFCA0}  // sub_55D2F0
#define RESOURCE_SOUNDS       {0x1E92FC, 0x1E932C, 0x1F1CA0, 0x1EFC64}  // sub_573618
#define RESOURCE_BACKGROUNDS  {0x1E9278, 0x1E9288, 0x1E9284, 0x1EFC88}  // sub_5462F0
#define RESOURCE_PATHS        {0x1E9108, 0x1E911C, 0x1E9114, 0x1EFC1C}  // sub_54032C
#define RESOURCE_SCRIPTS      {0x1E9094, 0x1E90A8, 0x1E90A0, 0x1EFC38}  // sub_536A74
#define RESOURCE_FONTS        {0x1E92AC, 0x1E92BC, 0x1E92B8, 0x1EFCFC}  // sub_556E14
#define RESOURCE_TIMELINES    {0x1E92C0, 0x1E92D0, 0x1E92CC, 0x1EFD04}  // sub_558C54
#define RESOURCE_OBJECTS      {0x1E9354, 0x1E9364, 0x1E9360, 0x1F61E8}  // sub_558C54
#define RESOURCE_ROOMS        {0x1E9300, 0x1E9310, 0x1E930C, 0x1EFD3C}  // sub_562638
#define RESOURCE_EXTENSIONS   {0x1E9294, 0x1E92A4, 0x1E92A0, 0x1EFD40}  // sub_553E20
#define RESOURCE_TRIGGERS     {0x1E9320, 0x1E9330, 0x1E9328, 0x1EFD80}
#define RESOURCE_CONSTANTS    {0x1E91C8, 0x1E91D8, 0x1E91D0, 0x1EFDCC}
#define RESOURCE_INCLUDED     {0x1E9248, 0x1E9258, 0x1E9250, 0x1EFE10}

// ==== Settings Globals (verified from sub_59E648) ====
#define ADDR_SETTING_FULLSCREEN      0x1E93B0   // u32 bool
#define ADDR_SETTING_INTERPOLATE     0x1E93B4   // u32 bool
#define ADDR_SETTING_COLOR_DEPTH     0x1E93BC   // u32
#define ADDR_SETTING_RESOLUTION      0x1E93C4   // u32
#define ADDR_SETTING_FREQUENCY       0x1E93C8   // u32
#define ADDR_SETTING_SCALING         0x1E93CC   // i32
#define ADDR_SETTING_CLEAR_COLOR     0x1E93D0   // u32 RGBA
#define ADDR_SETTING_PRIORITY        0x1E93D4   // u32
#define ADDR_SETTING_LOADING_BAR     0x1E93D8   // u32
// String globals verified from GM80_SaveSettings disasm (0x59E960-0x59EA08)
#define ADDR_SETTING_AUTHOR          0x1E9430   // dword_5E9430 → sub_4EA9E4
#define ADDR_SETTING_VERSION         0x1E9434   // off_5E9434 → sub_4EA9E4
#define ADDR_SETTING_INFO            0x1E9438   // dword_5E9438 → sub_4EA9E4
#define ADDR_SETTING_COMPANY         0x1E944C   // dword_5E944C → sub_4EA9E4
#define ADDR_SETTING_PRODUCT         0x1E9450   // dword_5E9450 → sub_4EA9E4
#define ADDR_SETTING_COPYRIGHT       0x1E9454   // dword_5E9454 → sub_4EA9E4
#define ADDR_SETTING_DESCRIPTION     0x1E9458   // dword_5E9458 → sub_4EA9E4
#define ADDR_SETTINGS_TIMESTAMP      0x1E93A4   // double

// ==== Game ID & Global Settings ====
#define ADDR_GAME_ID             0x1F6218   // dword_5F6218
#define ADDR_GUID_STORAGE        0x1F6220   // 16-byte GUID follows game ID

// ==== Dirty flags cleared by sub_59BA38 after successful save (16 flags) ====
// These control the '*' in the title bar and "unsaved changes" state
// Verified: IDA int_convert from off_* pointer values → RVAs
#define ADDR_DIRTY_FLAGS { \
    0x1E945C, 0x1F61E8, 0x1EFCE8, 0x1EFCA0, \
    0x1EFCF4, 0x1EFC38, 0x1EFCFC, 0x1EFD0C, \
    0x1EFD04, 0x1EFD3C, 0x1F61F8, 0x1F6248, \
    0x2000B4, 0x1F6210, 0x1EFD14, 0x1F1C98  \
}

// ==== VCL / IDE UI ====
#define ADDR_CONTROL_SETTEXT     0x060B90   // TControl.SetText
#define ADDR_APP_MESSAGEBOX      0x07F57C   // TApplication.MessageBox
#define ADDR_GET_SCRIPT_BY_NAME  0x15BF50   // Find script by name → returns index

// ==== Main Form (offsets from MainForm pointer) ====
// MainForm pointer stored at base+0x1F0100
// TMainForm.ResourceTree at MainForm+0x3B8  (verified: same Delphi 7 VCL layout)
// TMainForm.HelpBtn at MainForm+0x3FC
// MainForm address NOT at 0x1F0100 (runtime null). Need to find via IDA.
// Try: sub_59ABBC uses Form+0x368 which accesses resource tree component.
// MainForm might be found via Application.MainForm or at a different RVA.
//#define ADDR_MAINFORM            0x1F0100   // WRONG — runtime null
#define OFF_MAINFORM_RESOURCETREE 0x3B8
#define OFF_MAINFORM_HELPBTN     0x3FC
#define OFF_MAINFORM_ROOMITEM    0x3B8

// ==== Preferences Form ====
#define ADDR_PREFS_FORM          0x19A7F4   // Preferences form global pointer
#define OFF_PREFS_SOUNDS_CB     0x42C
#define OFF_PREFS_AUTOSAVE_CB   0x4C4
#define OFF_PREFS_COMPATIBLE_CB 0x4C8

// ==== TMenuItem helpers ====
// TMenuItem.Add — vtable method, call via asm
// TMenuItem.SetChecked: offset 0xF0 in vtable (Delphi 7)
// TMenuItem.GetChecked: offset 0xEC in vtable
#define OFF_MENUITEM_ADD         0x0DD244   // TMenuItem.Add (function address)
#define OFF_MENUITEM_SETCHECKED  0x0C0238   // SetChecked method address
#define OFF_MENUITEM_GETCHECKED  0x0C01F8   // GetChecked method address

// ==== String & UI Helpers ====
#define ADDR_SHOWMESSAGE         0x07F5AC   // ShowMessage (simple)
#define ADDR_MESSAGEDLG          0x0E437C   // MessageDlgPosHelp
#define ADDR_EXTRACTFILEPATH     0x00735C   // ExtractFilePath
#define ADDR_FORCEDIRECTORIES    0x006EAC   // ForceDirectories
#define ADDR_USTRASG             0x007EB8   // @UStrAsg (WideString, rarely used in GM8.0)
#define ADDR_USTRCAT             0x0082DC   // @UStrCat
#define ADDR_USTRCOPY            0x0086A8   // @UStrCopy

// ==== Temp / Exe Path ====
#define ADDR_TEMP_DIR            0x1F8974   // Temp directory string pointer
#define ADDR_APP_EXENAME         0x120290   // TApplication.GetExeName

// ==== Room Editor ====
#define ADDR_LAST_INSTANCE_ID    0x1F9320   // Last used instance ID
#define ADDR_LAST_TILE_ID        0x1F9324   // Last used tile ID

// ==== Resource Tree Helper ====
#define ADDR_TREENODE_COUNT      0x0AD490   // TTreeNode.GetCount
#define ADDR_TREENODE_ADDCHILD   0x0AD4E0   // TTreeNode.AddChild
#define ADDR_TREENODE_SETDATA    0x0AD520   // TTreeNode.SetData

// ==== Image / Thumbnail ====
#define ADDR_IMAGELIST_ONCHANGE  0x081B8    // ImageList OnChange notification

// ==== Code Editor ====
#define ADDR_CODE_EDITOR_SHOW    0x0B2000   // Show resource at cursor
