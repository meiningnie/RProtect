#include "Common.h"
#include "RProtect.h"
#include "Forms.h"
#include "EventHandler.h"

USEREVENTDATA g_UsrEvtData;

DWORD WINAPI EventHandler(LPVOID lpParameter) {

	WaitForSingleObject(g_hEvtUIReady, INFINITE);	// 无需关心这个函数是否成功

	while (!g_bOver) {
		JUDGMENTDATA JudgData;
		DWORD dwRet;

		BOOL bRet = DeviceIoControl(g_hDev,
									IOCTL_GET_EVENT,
									NULL,
									0,
									&g_UsrEvtData,
									sizeof(USEREVENTDATA),
									&dwRet,
									NULL
								);
		if (!bRet) {
			continue;
		}
		DeviceNameToDosName(g_UsrEvtData.wzCriminal);
		DeviceNameToDosName(g_UsrEvtData.wzVictim);

		JudgData.ulEvtData = g_UsrEvtData.ulEvtData;
		// +++
		JudgData.ulJudgment = (ULONG)DialogBox(g_hInst, MAKEINTRESOURCE(IDD_EVENT), NULL, EventDlg_Proc);
		// ---

		DeviceIoControl(	g_hDev,
							IOCTL_GIVE_JUDGMENT,
							&JudgData,
							sizeof(JUDGMENTDATA),
							NULL,
							0,
							&dwRet,
							NULL
						);
	}
	return 0;
}

VOID DeviceNameToDosName(PTSTR tcsDevName)
{

	if (!tcsDevName)
		return;

	TCHAR tzTemp[512] = TEXT("");

	if (GetLogicalDriveStrings(512 - 1, tzTemp))
	{
		TCHAR tzName[MAX_PATH];
		TCHAR tzDrive[3] = TEXT(" :");
		BOOL bFound = FALSE;
		TCHAR* p = tzTemp;

		do
		{
			// Copy the drive letter to the template string
			*tzDrive = *p;

			// Look up each device name
			if (QueryDosDevice(tzDrive, tzName, 512))
            {
				ULONG ulNameLen = (ULONG)_tcslen(tzName);
				if (_tcslen(tzName) < MAX_PATH)
				{
					bFound = (_tcsnicmp(tcsDevName, tzName, ulNameLen) == 0);
					if (bFound)
					{
						// Reconstruct pszFilename using szTempFile
						// Replace device path with DOS path
						TCHAR tzTempFile[MAX_PATH];
						_stprintf_s(tzTempFile, MAX_PATH, TEXT("%s%s"), tzDrive, tcsDevName + ulNameLen);
						_tcscpy_s(tcsDevName, MAX_PATH, tzTempFile);
					}
				}
			}
			while (*p++);
		} while (!bFound && *p); // end of string
	}
}


VOID GetDetail(ULONG ulCrimeType, PTSTR tcsMsg, ULONG usMsgLen)
{
	switch (ulCrimeType)  {
		////////////////////////////////////////////////////////////
		//
		//		CRIME_FILE
		//
		case CRIME_MINOR_NtCreateFile:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图访问受保护的文件：%s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtOpenFile:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图访问受保护的文件：%s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtDeleteFile:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图删除受保护的文件：%s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtSetInformationFile:
			if (FILE_INFORMATION_CLASS(g_UsrEvtData.ulExtraInfo) == FileLinkInformation)
			{
				_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图创建受保护文件 %s 的硬链接"),
							g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
						);
			}
			else if (FILE_INFORMATION_CLASS(g_UsrEvtData.ulExtraInfo) == FileRenameInformation)
			{
				_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图更改受保护文件 %s 的文件名"),
							g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
						);
			}
			else if (FILE_INFORMATION_CLASS(g_UsrEvtData.ulExtraInfo) == FileShortNameInformation)
			{
				_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图更改受保护文件 %s 的短名"),
							g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
						);
			}
			break;
		////////////////////////////////////////////////////////////
		//
		//		CRIME_REG
		//

		////////////////////////////////////////////////////////////
		//
		//		CRIME_PROC
		//
		//case CRIME_MINOR_NtCreateSection:
		case CRIME_MINOR_NtCreateUserProcess:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图创建进程：%s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtCreateThread:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图在 %s 中创建线程"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtSuspendThread:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图挂起 %s 的线程"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtSuspendProcess:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图挂起 %s 的进程"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtGetContextThread:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图获取 %s 中的线程寄存器内容"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtSetContextThread:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图改写 %s 中的线程寄存器内容"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtTerminateProcess:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图终止进程：%s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtTerminateThread:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图终止 %s 中的线程"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtReadVirtualMemory:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图读取 %s 中的内存地址：0x%p"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim, g_UsrEvtData.ulExtraInfo
					);
			break;
		case CRIME_MINOR_NtWriteVirtualMemory:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图改写 %s 中的内存地址：0x%p"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim, g_UsrEvtData.ulExtraInfo
					);
			break;
		case CRIME_MINOR_NtProtectVirtualMemory:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图改变 %s 中，0x%p 处的页面访问权限"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim, g_UsrEvtData.ulExtraInfo
					);
			break;
		case CRIME_MINOR_NtOpenThread:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图获取 %s 中的线程句柄"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtOpenProcess:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图获取 %s 中的进程句柄"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtAssignProcessToJobObject:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图将 %s 添加为作业"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		////////////////////////////////////////////////////////////
		//
		//		CRIME_SYS
		//
		case CRIME_MINOR_NtLoadDriver:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图加载驱动： %s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtUnloadDriver:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图卸载驱动： %s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtSetSystemInformation:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图加载驱动： %s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtOpenSection:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图访问物理内存对象"),
						g_UsrEvtData.wzCriminal/*, g_UsrEvtData.wzVictim*/
					);
			break;
		case CRIME_MINOR_NtCreateSymbolicLinkObject:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图创建符号链接 %s"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);
			break;
		case CRIME_MINOR_NtSystemDebugControl:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图调用危险函数：ZwSystemDebugControl"),
						g_UsrEvtData.wzCriminal/*, g_UsrEvtData.wzVictim*/
					);
			break;
		case CRIME_MINOR_NtUserSetWindowsHookEx:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图创建xx钩子，钩子所在模块：%s，钩子函数地址：0x%p"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim,
						g_UsrEvtData.ulExtraInfo
					);
			break;
		case CRIME_MINOR_NtDuplicateObject:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("%s 试图获取 %s 中的句柄"),
						g_UsrEvtData.wzCriminal, g_UsrEvtData.wzVictim
					);			break;
		////////////////////////////////////////////////////////////
		//
		//		CRIME_UNKNOWN
		//
		default:
			_stprintf_s(tcsMsg, usMsgLen, TEXT("未知"));
			break;
	}
}
