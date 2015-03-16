#ifndef _FORMS_H_
#define _FORMS_H_


#define TIPS																											\
	TEXT("欢迎测试 RProtec 主动防御软件！注意事项：\r\n\r\n")															\
	TEXT("1、 本软件只在干净的 Windows 7 Professional x64 系统上测试过，在其它环境下不保证正常运行；\r\n\r\n")			\
	TEXT("2、 本软件仅供演示、研究，暂不包含安装卸载功能。使用本软件时请选用第三方工具加载驱动后运行程序；卸载本程序")	\
	TEXT("时请关闭本程序后使用第三方工具卸载驱动；\r\n\r\n")															\
	TEXT("3、 本软件使用过程中不会产生任何日志文件、注册表信息等残留垃圾，因此也不会保存用户使用过程中的配置信息，例")	\
	TEXT("如黑白名单等。请放心使用；\r\n\r\n")																			\
	TEXT("4、 本软件的界面目前非常残念，请做好心理准备；\r\n\r\n")


#define HANDLE_DLGMSG(hwnd, message, fn)                 \
   case (message): return (SetDlgMsgResult(hwnd, uMsg,     \
   HANDLE_##message((hwnd), (wParam), (lParam), (fn))))

extern HWND g_hMain;

extern HWND g_hTab1_Setup;
extern HWND g_hTab2_Proc;
extern HWND g_hTab3_File;
extern HWND g_hTab4_Reg;
extern HWND g_hTab5_Sys;

extern HANDLE g_hEvtUIReady;

VOID DlgPageInit();
VOID DlgPageOnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);
INT_PTR WINAPI DlgPageProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR WINAPI MainDlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR WINAPI EventDlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
#endif
