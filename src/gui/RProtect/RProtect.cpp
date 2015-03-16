#include "Common.h"
#include "Forms.h"
#include "EventHandler.h"

HINSTANCE g_hInst = NULL;
HANDLE g_hDev = NULL;
BOOL g_bOver = FALSE;

int WINAPI _tWinMain(HINSTANCE hinstExe, HINSTANCE, PTSTR pszCmdLine, int) {

	g_hInst = hinstExe;

	MessageBox(NULL, TIPS, TEXT("RProtect"), MB_OK);

	g_hDev = CreateFile(TEXT("\\\\.\\RProtect"),
						GENERIC_READ | GENERIC_WRITE,
						0,
						NULL,
						OPEN_EXISTING,
						0,
						NULL
					);

	if (g_hDev == INVALID_HANDLE_VALUE) {
		MessageBox(	NULL,
					TEXT("出错：驱动未加载！\r\n")
					TEXT("本程序为半成品演示版，并没有安装驱动的功能，请使用第三方软件加载驱动程序后后再运行本程序！\r\n")
					TEXT("另外：本程序所带驱动没有数字签名，请开机F8禁用数字签名后再进行。\r\n"),
					TEXT("error"),
					MB_OK
				);
		return 0;
	}


	g_hEvtUIReady = CreateEvent(NULL, FALSE, FALSE, NULL);

	HANDLE hThread = BEGINTHREADEX(	NULL,
									0,
									EventHandler,
									NULL,
									0,
									NULL
									);
	if (!hThread)
		MessageBox(NULL, TEXT("无法创建通讯线程！"), TEXT("err"), MB_OK);

	DialogBox(hinstExe, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlg_Proc);

	// terminate communication thread
	g_bOver = TRUE;
	WaitForSingleObject(hThread, INFINITE);
	//TerminateThread(hThread, 0);

	CloseHandle(hThread);
	CloseHandle(g_hDev);
	return 0;
}

//int WINAPI _tWinMain(HINSTANCE hinstExe, HINSTANCE, PTSTR pszCmdLine, int) {
//
//	MessageBox(	NULL,
//				TEXT("注意：\r\n")
//				TEXT("本程序为演示版本，并没有安装驱动的功能，请使用\r\n")
//				TEXT("第三方软件加载驱动程序后后再运行本程序！\r\n"),
//				TEXT("RProtect"),
//				MB_OK
//			);
//	DialogBox(hinstExe, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlg_Proc);
//
//
//	return 0;
//}