#include "Common.h"
#include "QueryStatus.h"


BOOL IsMonOn(ULONG ulCrimeType) {

	USER_MAJOR_PROTECTED_INFO UsrMjProInfo;

	UsrMjProInfo.ulCrimeType = ulCrimeType;
	UsrMjProInfo.ulIsProtected = (ULONG)FALSE;

	DWORD dwRet;

	BOOL bRet = DeviceIoControl(
		g_hDev,
		IOCTL_GET_MAJOR_PROTECTED_INFO,
		&UsrMjProInfo,
		sizeof(USER_MAJOR_PROTECTED_INFO),
		&UsrMjProInfo,
		sizeof(USER_MAJOR_PROTECTED_INFO),
		&dwRet,
		NULL
		);

	if (bRet)
		return (ULONG)UsrMjProInfo.ulIsProtected;
	else
		return FALSE;
}

BOOL SetMon(ULONG ulCrimeType, BOOL bIsOn) {

	PUSER_MAJOR_PROTECTED_INFO pUsrMjProInfo = (PUSER_MAJOR_PROTECTED_INFO)
		VirtualAlloc(NULL, sizeof(USER_MAJOR_PROTECTED_INFO), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!pUsrMjProInfo)
		return 0;

	pUsrMjProInfo->ulCrimeType = ulCrimeType;
	pUsrMjProInfo->ulIsProtected = (ULONG)bIsOn;

	HANDLE hThread = BEGINTHREADEX(	NULL,
									0,
									SetMonInternal,
									pUsrMjProInfo,
									0,
									NULL
								);
	if (!hThread)
		return FALSE;

	CloseHandle(hThread);
	return TRUE;
}

DWORD WINAPI SetMonInternal(PUSER_MAJOR_PROTECTED_INFO pUsrMjProInfo) {
	DWORD dwRet;

	DeviceIoControl(g_hDev,
					IOCTL_SET_MAJOR_PROTECTED,
					pUsrMjProInfo,
					sizeof(USER_MAJOR_PROTECTED_INFO),
					NULL,
					0,
					&dwRet,
					NULL
				);

	VirtualFree(pUsrMjProInfo, 0, MEM_RESERVE);
	return dwRet;
}

PTSTR QueryWhiteBlackList(ULONG ulCrimeType, ULONG ulNodeType) {
	// XXXXX

	return NULL;
}


BOOLEAN AddToWhiteBlackList(PTSTR strNodeName, ULONG ulCrimeType, ULONG ulNodeType) {
	// XXXXX

	return NULL;
}
