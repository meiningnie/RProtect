/*++

Module Name:

	Common.c - 公共模块

Abstract:

	该模块导出一些其它各模块都会用到的公共变量、公共算法等。

Author:

	Fypher

	2012/02/27

--*/
#include <ntifs.h>
#include <ntimage.h>
#include "Common.h"
#include "Hook.h"
#include "FkMS.h"
#include "SysCallFlt.h"
#include "EventHandler.h"
#include "WhiteBlackList.h"

ULONG_PTR __readmsr(int);

#pragma intrinsic(__readmsr)

//#pragma data_seg("PAGE")
ULONG g_ulOsVersion = OS_VERSION_ERROR;

ULONG_PTR g_ulpKiSystemCall64 = 0;

ULONG_PTR g_ulpKeServiceDescriptorTable = 0;
ULONG_PTR g_ulpKiServiceTable = 0;
ULONG g_ulServiceNumber = 0;


ULONG_PTR g_ulpKeServiceDescriptorTableShadow = 0;
ULONG_PTR g_ulpW32pServiceTable = 0;
ULONG g_ulShadowServiceNumber = 0;

ULONG_PTR g_ulpNtdllBase = 0;
ULONG g_ulNtDllSize = 0;

/*
fffff800`03c7501d 4d631c82 		movsxd	r11,dword ptr [r10+rax*4]	;4d 63 1c 82
fffff800`03c75021 498bc3		mov		rax,r11					;49 8b c3
fffff800`03c75024 49c1fb04		sar		r11,4					;49 c1 fb 04
fffff800`03c75028 4d03d3		add		r10,r11					;4d 03 d3
fffff800`03c7502b 83ff20		cmp		edi,20h					;83 ff 20
*/
PVOID g_pPhysicalMemoryObj = NULL;

// hard coded
ULONG g_ulShadowId_NtUserSetWindowsHookEx = 0;

// for self protect
PEPROCESS g_pProtected = NULL;
//#pragma data_seg()

ULONG_PTR g_ulpHookPoint = 0;
ULONG_PTR g_ulpJmpBackPoint = 0;

UCHAR g_Signature[17] = {0x4d, 0x63, 0x1c, 0x82, 0x49, 0x8b, 0xc3, 0x49, 0xc1, 0xfb, 0x04, 0x4d, 0x03, 0xd3, 0x83, 0xff, 0x20};
UCHAR g_HookCodes[17] = {0x68, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90};



ULONG GetOsVersion()
{

	ULONG ulOsVersion;
	RTL_OSVERSIONINFOW OsVersionInfo;

	PAGED_CODE();

	OsVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	if (!NT_SUCCESS(RtlGetVersion(&OsVersionInfo)))
		return OS_VERSION_ERROR;

	switch (OsVersionInfo.dwBuildNumber) {
		case 2195:
			ulOsVersion = OS_VERSION_2000;
			break;

		case 2600:
			ulOsVersion = OS_VERSION_XP;
			break;

		case 3790:
			ulOsVersion = OS_VERSION_SERVER_2003;
			break;

		case 6000:
			ulOsVersion = OS_VERSION_VISTA;
			break;

		case 6001:
			ulOsVersion = OS_VERSION_VISTA_SP1;
			break;

		case 6002:
			ulOsVersion = OS_VERSION_VISTA_SP2;
			break;

		case 7600:
			ulOsVersion = OS_VERSION_WIN7;
			break;

		case 7601:
			ulOsVersion = OS_VERSION_WIN7_SP1;
			break;

		default:
			ulOsVersion = OS_VERSION_ERROR;
	}

	return ulOsVersion;
}



BOOLEAN InitCommonVars()
/*++

Routine Description:

	全局变量的初始化工作


Arguments:

	None.


Return Value:

	TRUE if successful, and FALSE if not.


Author:

	Fypher

--*/
{
	RTL_PROCESS_MODULE_INFORMATION SysModInfo;

	// InitRegKeys();

	ULONG_PTR g_ulpAddr;

	PAGED_CODE();

	g_pProtected = NULL;

	if (!InitEventHandler())
		return FALSE;

	if (!InitWhiteBlackHashTable())
		return FALSE;

	g_ulpKiSystemCall64 = __readmsr(0xC0000082);

	for (g_ulpAddr = g_ulpKiSystemCall64; g_ulpAddr != g_ulpKiSystemCall64 + PAGE_SIZE / 2; ++g_ulpAddr)
	{
		if (!MmIsAddressValid((PVOID)g_ulpAddr) || !MmIsAddressValid((PVOID)(g_ulpAddr + 32 * sizeof(ULONG_PTR)))) {
			break;
		}

		if (*(PUSHORT)g_ulpAddr == 0x8d4c && *(PUSHORT)(g_ulpAddr + 7) == 0x8d4c) {
			g_ulpKeServiceDescriptorTable = g_ulpAddr + *(PULONG)(g_ulpAddr + 3) + 7;
			g_ulpKeServiceDescriptorTableShadow = (g_ulpAddr + 7) + *(PULONG)(g_ulpAddr + 7 + 3) + 7;

			if (MmIsAddressValid((PVOID)g_ulpKeServiceDescriptorTable)) {
				g_ulpKiServiceTable = *(PULONG_PTR)g_ulpKeServiceDescriptorTable;
				g_ulServiceNumber = *(PULONG)(g_ulpKeServiceDescriptorTable + 2 * sizeof(ULONG_PTR));
			}

			if (MmIsAddressValid((PVOID)g_ulpKeServiceDescriptorTableShadow)) {
				g_ulpW32pServiceTable = *(PULONG_PTR)(g_ulpKeServiceDescriptorTableShadow + 4 * sizeof(ULONG_PTR));
				g_ulShadowServiceNumber = *(PULONG)(g_ulpKeServiceDescriptorTableShadow + 6 * sizeof(ULONG_PTR));
			}
		}

		if ( *(PULONG_PTR)g_ulpAddr == *(PULONG_PTR)g_Signature ) {
			g_ulpHookPoint = g_ulpAddr;
			g_ulpJmpBackPoint = g_ulpAddr + 17;	//!!

			*(PULONG)(g_HookCodes + 1) = (ULONG)((ULONG_PTR)SuperDetour & 0xFFFFFFFF);
			*(PULONG)(g_HookCodes + 9) = (ULONG)(((ULONG_PTR)SuperDetour >> 32) & 0xFFFFFFFF);

			break;
		}

	}

	if ( GetSysModInfoByName("ntdll.dll", &SysModInfo) )
	{
        g_ulpNtdllBase = (ULONG_PTR)SysModInfo.ImageBase;
        g_ulNtDllSize = SysModInfo.ImageSize;
	}

	g_pPhysicalMemoryObj = GetSectionObjectByName(L"\\Device\\PhysicalMemory");
	if (g_pPhysicalMemoryObj)
		ObDereferenceObject(g_pPhysicalMemoryObj);

	// verify
	// +++
	if (!MmIsAddressValid((PVOID)g_ulpKiSystemCall64)		||

		!MmIsAddressValid((PVOID)g_ulpKiServiceTable)		||
		!g_ulServiceNumber									||

		!g_ulpW32pServiceTable								||
		!g_ulShadowServiceNumber							||

		!MmIsAddressValid((PVOID)g_ulpNtdllBase)			||
		!g_ulNtDllSize										||

		!MmIsAddressValid((PVOID)g_ulpHookPoint)			||
		!MmIsAddressValid((PVOID)g_ulpJmpBackPoint)				)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
	// ---
}


BOOLEAN InitShadowServiceId()
/*++

Routine Description:

	寻找需要监控的 SSDT Shadow 中的系统调用的功能号。


Arguments:

	None.


Return Value:

	TRUE if successful, and FALSE if not.


Comments:

	目前采用根据系统版本进行硬编码的方法。这种方法不好，需要改进。


Author:

	Fypher

--*/
{
	BOOLEAN bRet = FALSE;

	PAGED_CODE();

	switch (g_ulOsVersion) {
		case OS_VERSION_2000:
			g_ulShadowId_NtUserSetWindowsHookEx = 0x212;
			bRet = TRUE;
			break;

		case OS_VERSION_XP:
			g_ulShadowId_NtUserSetWindowsHookEx = 0x225;
			bRet = TRUE;
			break;

		case OS_VERSION_SERVER_2003:
			g_ulShadowId_NtUserSetWindowsHookEx = 0x221;
			bRet = TRUE;
			break;

		case OS_VERSION_VISTA:
		case OS_VERSION_VISTA_SP1:
		case OS_VERSION_VISTA_SP2:
			g_ulShadowId_NtUserSetWindowsHookEx = 0x23d;
			bRet = TRUE;
			break;

		case OS_VERSION_WIN7:
		case OS_VERSION_WIN7_SP1:
			g_ulShadowId_NtUserSetWindowsHookEx = 0x8c;
			bRet = TRUE;
			break;

		default:
			break;
	}

	return bRet;
}

PRTL_PROCESS_MODULES GetSystemModules()
/*++

Routine Description:

	获取系统模块信息


Arguments:

	None.


Return Value:

	成功则返回系统模块信息，失败返回 NULL 。


Comments:

	该函数返回的系统模块信息使用完毕后，需要由调用者进行释放（ExFreePool）。


Author:

	Fypher

--*/
{
	PRTL_PROCESS_MODULES pSysMods = NULL;
	ULONG ulSize = 512;
	NTSTATUS status;

	PAGED_CODE();

	while ( TRUE )
	{
		pSysMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, ulSize, ALLOC_TAG);
		if ( !pSysMods )
			return NULL;

		status = ZwQuerySystemInformation(SystemModuleInformation, pSysMods, ulSize, &ulSize);
		if ( status != STATUS_INFO_LENGTH_MISMATCH )
			break;

		ExFreePool(pSysMods);
	}

	if ( !NT_SUCCESS(status) ) {
		ExFreePool(pSysMods);
		pSysMods = NULL;
	}

	return pSysMods;
}


BOOLEAN GetSysModInfoByName(IN char * strModName, OUT PRTL_PROCESS_MODULE_INFORMATION pSysModInfo)
/*++

Routine Description:

	获取指定名称的模块信息


Arguments:

	strModName - 指定模块的名称

	pSysModInfo - 返回指定的模块信息


Return Value:

	TRUE if successful, and FALSE if not.


Author:

	Fypher

--*/
{
	PRTL_PROCESS_MODULES pSysMods;
	PRTL_PROCESS_MODULE_INFORMATION pModInfo;
	ULONG i, ulModNum;
	BOOLEAN bRet = FALSE;

	PAGED_CODE();

	pSysMods = GetSystemModules();
	if (!pSysMods)
		return FALSE;

	ulModNum = pSysMods->NumberOfModules;
	pModInfo = pSysMods->Modules;

	for (i = 0; i < ulModNum; ++i) {
		if (pModInfo->FullPathName) {
			char * strFileName = strrchr(pModInfo->FullPathName, '\\');
			if (strFileName)
				strFileName++;
			else
				strFileName = pModInfo->FullPathName;

			if (!_stricmp(strModName, strFileName)) {
				RtlCopyMemory(pSysModInfo, pModInfo, sizeof(RTL_PROCESS_MODULE_INFORMATION));
				bRet = TRUE;
				break;
			}
		}
		pModInfo += 1;
	}
	ExFreePool(pSysMods);

	return bRet;
}


PSYSTEM_PROCESS_INFORMATION GetSystemProcesses()
/*++

Routine Description:

	获取系统中的进程信息


Arguments:

	None.


Return Value:

	成功则返回系统中的进程信息，失败返回 NULL。


Comments:

	该函数返回的进程信息使用完毕后，需要由调用者进行释放（ExFreePool）。


Author:

	Fypher

--*/
{
	ULONG ulSize = 512;
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo;
	NTSTATUS status;

	PAGED_CODE();

	while ( TRUE )
	{
		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, ALLOC_TAG);
		if ( !pSysProcInfo )
			return NULL;

		status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pSysProcInfo, ulSize, &ulSize);
		if ( status != STATUS_INFO_LENGTH_MISMATCH )
			break;
		ExFreePool(pSysProcInfo);
	}

	if ( !NT_SUCCESS(status) ) {
		ExFreePool(pSysProcInfo);
		return NULL;
	}

	return pSysProcInfo;
}

//HANDLE GetProcIdByName(WCHAR * wcsProcName)
//{
//	HANDLE Pid = (HANDLE)0;
//	PSYSTEM_PROCESS_INFORMATION pSysProcInfo, pBuf;
//	NTSTATUS status;
//	UNICODE_STRING uniProcName;
//
//	PAGED_CODE();
//
//	pBuf = pSysProcInfo = GetSystemProcesses();
//	if (!pBuf)
//		return 0;
//
//	RtlInitUnicodeString(&uniProcName, wcsProcName);
//
//	while (TRUE) {
//		if (RtlEqualUnicodeString(&uniProcName, &pSysProcInfo->ImageName, TRUE)) {
//			Pid = pSysProcInfo->UniqueProcessId;
//			break;
//		}
//
//		if (pSysProcInfo->NextEntryOffset == 0)
//			break;
//
//		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( (PCHAR)pSysProcInfo + pSysProcInfo->NextEntryOffset );
//	}
//	ExFreePool(pBuf);
//
//	return Pid;
//}


//ULONG GetThreadNumOfProcess(HANDLE Pid)
//{
//	PSYSTEM_PROCESS_INFORMATION pSysProcInfo, pBuf;
//	NTSTATUS status;
//	ULONG ulThreadNum = 0;
//
//	PAGED_CODE();
//
//	pBuf = pSysProcInfo = GetSystemProcesses();
//	if (!pBuf)
//		return 0;
//
//	while (TRUE) {
//		if (Pid == pSysProcInfo->UniqueProcessId) {
//			ulThreadNum = pSysProcInfo->NumberOfThreads;
//			break;
//		}
//
//		if (pSysProcInfo->NextEntryOffset == 0)
//			break;
//
//		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( (PCHAR)pSysProcInfo + pSysProcInfo->NextEntryOffset );
//	}
//	ExFreePool(pBuf);
//
//	return ulThreadNum;
//}


ULONG GetHandleCountOfProcess(IN HANDLE Pid)
/*++

Routine Description:

	获取特定进程所拥有的句柄数


Arguments:

	Pid - 指定进程的Pid


Return Value:

	TRUE if successful, and FALSE if not.


Comments:

	该函数可用于判断特定进程是否启动完毕。


Author:

	Fypher

--*/
{
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo, pBuf;
	NTSTATUS status;
	ULONG ulHandleCount = 0;

	PAGED_CODE();

	pBuf = pSysProcInfo = GetSystemProcesses();
	if (!pBuf)
		return 0;

	while (TRUE) {
		if (Pid == pSysProcInfo->UniqueProcessId) {
			ulHandleCount = pSysProcInfo->HandleCount;
			break;
		}

		if (pSysProcInfo->NextEntryOffset == 0)
			break;

		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( (PCHAR)pSysProcInfo + pSysProcInfo->NextEntryOffset );
	}
	ExFreePool(pBuf);

	return ulHandleCount;
}



PVOID GetSectionObjectByName(IN WCHAR * wcsObjName)
/*++

Routine Description:

	获取指定名称的Section对象


Arguments:

	wcsObjName - 指定Section对象的名称


Return Value:

	成功则返回Section Object，失败返回 NULL


Comments:

	该函数返回的Section对象需要由调用者负责ObDereferenceObject。


Author:

	Fypher

--*/
{
	UNICODE_STRING usObjName;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS NtStatus;
	HANDLE hSection;
	PVOID pSecObj;

	PAGED_CODE();

	RtlInitUnicodeString(&usObjName, wcsObjName);
	InitializeObjectAttributes(	&oa,
								&usObjName,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL
							);
	NtStatus = ZwOpenSection(&hSection, 0, &oa);
	if (!NT_SUCCESS(NtStatus))
		return NULL;

	NtStatus = ObReferenceObjectByHandle(hSection, 0, NULL, KernelMode, &pSecObj, NULL);
	ZwClose(hSection);
	if (!NT_SUCCESS(NtStatus))
		return NULL;

	return pSecObj;
}


ULONG_PTR MyGetProcAddress(IN ULONG_PTR ulpModBase, IN CHAR * strRoutineName)
/*++

Routine Description:

	从指定模块中获取指定的导出函数地址


Arguments:

	ulpModBase - 指定模块的加载地址

	strRoutineName - 指定函数的名称


Return Value:

	成功则返回函数地址，失败返回 NULL


Comments:

	该函数目前只能针对64位PE模块工作，需要完善。


Author:

	Fypher

--*/
{
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_OPTIONAL_HEADER pOptHdr;
	PIMAGE_EXPORT_DIRECTORY pExportTable;

	PULONG pulFuncAddrArray;
	PULONG pulFuncNameArray;
	PUSHORT pusFuncOrdinalsArray;

	ULONG ulIndex;
	PCHAR strFuncName;

	ULONG i;

	PAGED_CODE();

	pDosHdr = (PIMAGE_DOS_HEADER)ulpModBase;
	pOptHdr = (PIMAGE_OPTIONAL_HEADER)(ulpModBase + pDosHdr->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)/*24*/);
	pExportTable = (PIMAGE_EXPORT_DIRECTORY)(ulpModBase + pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    pulFuncAddrArray = (PULONG)(ulpModBase + pExportTable->AddressOfFunctions);

    pulFuncNameArray = (PULONG)(ulpModBase + pExportTable->AddressOfNames);

    pusFuncOrdinalsArray = (PUSHORT)(ulpModBase + pExportTable->AddressOfNameOrdinals);

    for (i = 0; i < pExportTable->NumberOfNames; i++) {
		ulIndex = pusFuncOrdinalsArray[i] + pExportTable->Base - 1;
		strFuncName = (PCHAR)(ulpModBase + pulFuncNameArray[i]);
		if (!_stricmp(strFuncName, strRoutineName))
			return ulpModBase + pulFuncAddrArray[ulIndex];
    }

	return 0;
}

BOOLEAN IsCurrentProcRProcess()
/*++

Routine Description:

	当前进程是否是客户端


Arguments:

	None.


Return Value:

	TRUE if successful, and FALSE if not.


Comments:

	该函数用于自我保护，不过目前没有实现具体功能。


Author:

	Fypher

--*/
{
	PAGED_CODE();

	/*
	PUNICODE_STRING pusCurProcName = GetProcNameByEproc(PsGetCurrentProcess());
	BOOLEAN bRet = IsUniStrEndWithWcs(pusCurProcName, DRV_NAME);

	if (pusCurProcName)
		ExFreePool(pusCurProcName);

	return bRet;
	*/
	return TRUE;		// always return TRUE
}

PUNICODE_STRING GetProcNameByEproc(IN PEPROCESS pEproc)
/*++

Routine Description:

	获取指定进程的完整进程名


Arguments:

	pEproc - 指定进程的EPROCESS地址


Return Value:

	成功则返回进程名，失败返回NULL


Comments:

	该函数返回的进程名，由调用则负责释放（ExFreePool）。


Author:

	Fypher

--*/
{
	NTSTATUS NtStatus;
	HANDLE hProc = NULL;
	PBYTE pBuf = NULL;
	ULONG ulSize = 32;

	PAGED_CODE();

	//
	// 1. pEproc --> handle
	//
	NtStatus = ObOpenObjectByPointer(	pEproc,
										OBJ_KERNEL_HANDLE,
										NULL,
										0,
										NULL,
										KernelMode,
										&hProc
									);

	if (!NT_SUCCESS(NtStatus))
		return NULL;

	//
	// 2. ZwQueryInformationProcess
	//
	while ( TRUE )
	{
		pBuf = ExAllocatePoolWithTag(NonPagedPool, ulSize, ALLOC_TAG);
		if ( !pBuf ) {
			ZwClose(hProc);
			return NULL;
		}

		NtStatus = ZwQueryInformationProcess(	hProc,
												ProcessImageFileName,
												pBuf,
												ulSize,
												&ulSize);
		if ( NtStatus != STATUS_INFO_LENGTH_MISMATCH )
			break;

		ExFreePool(pBuf);
	}

	ZwClose(hProc);

	if ( !NT_SUCCESS(NtStatus) ) {
		ExFreePool(pBuf);
		return NULL;
	}

	//
	// 4. over
	//
	return (PUNICODE_STRING)pBuf;
}


BOOLEAN IsUniStrEndWithWcs(IN PUNICODE_STRING puniXXX, IN PWSTR wcsSubXXX)
/*++

Routine Description:

	判断某UnicodeString是否以某个PWSTR结尾


Arguments:

	puniXXX - ...
	wcsSubXXX - ...


Return Value:

	TRUE or FALSE


Comments:

	TRUE if successful, and FALSE if not.


Author:

	Fypher

--*/
{
	USHORT usUniXXXLen, usWcsXXXLen;
	PWSTR wcsPos;

	//PAGED_CODE();

	if (!puniXXX || !puniXXX->Buffer || !puniXXX->Length/* || !wcsSubXXX*/)
		return FALSE;

	usUniXXXLen = puniXXX->Length / sizeof(WCHAR);
	usWcsXXXLen = (USHORT)wcslen(wcsSubXXX);

	if (usWcsXXXLen > usUniXXXLen || !usWcsXXXLen)
		return FALSE;

	wcsPos = puniXXX->Buffer + (usUniXXXLen - usWcsXXXLen);

	if (_wcsnicmp(wcsPos, wcsSubXXX, usWcsXXXLen)) {
		return FALSE;
	}

	return TRUE;
}


/*
#pragma PAGEDCODE
BOOLEAN IsWcsEndWithWcs(PWSTR pwcsXXX, PWSTR wcsSubXXX, ULONG ulXXXLen) {
	//USHORT usUniXXXLen, usWcsXXXLen;
	ULONG ulSubXXXLen;
	PWSTR wcsPos;

	if (!pwcsXXX || !ulXXXLen)
		return FALSE;

	ulSubXXXLen = wcslen(wcsSubXXX);

	if (ulSubXXXLen > ulXXXLen || !ulSubXXXLen)
		return FALSE;

#ifdef DBG
	if (!pwcsXXX[ulXXXLen - 1]) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "in IsWcsEndWithWcs, 0-term: %ws\r\n", pwcsXXX));
	}
#endif
	wcsPos = pwcsXXX + (ulXXXLen - ulSubXXXLen);

	if (_wcsnicmp(wcsPos, wcsSubXXX, ulSubXXXLen)) {
		return FALSE;
	}

	return TRUE;
}
*/

VOID MyProbeForRead(IN PVOID pAddr,IN ULONG ulLen,IN ULONG ulAlignment,IN ULONG ulMemType)
/*++

Routine Description:

	判断某内存地址是否可读


Arguments:

	pAddr - 内存地址

	ulLen - 内存长度

	ulAlignment - 对齐值

	ulMemType - MEM_TYPE_KERNELMODE 或 MEM_TYPE_USERMODE


Return Value:

	None.


Comments:

	当指定内存不可读时，将抛出异常。调用方应该将此函数包含在try块中。


Author:

	Fypher

--*/
{
	PAGED_CODE();

	if (pAddr >= MmSystemRangeStart)			// kernel space
	{
		ULONG_PTR ulpBegPage = ((ULONG_PTR)pAddr / PAGE_SIZE) * PAGE_SIZE;
		ULONG_PTR ulpEndPage = (((ULONG_PTR)pAddr + ulLen)/ PAGE_SIZE) * PAGE_SIZE;

		if (!(ulMemType & MEM_TYPE_KERNELMODE)) {
			ExRaiseAccessViolation();
			return;
		}

		if ((ULONG_PTR)pAddr & (ulAlignment - 1))
			ExRaiseDatatypeMisalignment();

		while (ulpBegPage <= ulpEndPage) {
			if (!MmIsAddressValid((PVOID)ulpBegPage)) {
				ExRaiseAccessViolation();
				return;
			}
			ulpBegPage += PAGE_SIZE;
		}
	}
	else										// user space
	{
		if (!(ulMemType & MEM_TYPE_USERMODE)) {
			ExRaiseAccessViolation();
			return;
		}
		ProbeForRead(pAddr, ulLen, ulAlignment);
	}
}

VOID MyProbeForWrite(IN PVOID pAddr,IN ULONG ulLen,IN ULONG ulAlignment,IN ULONG ulMemType)
/*++

Routine Description:

	判断某内存地址是否可写


Arguments:

	pAddr - 内存地址

	ulLen - 内存长度

	ulAlignment - 对齐值

	ulMemType - MEM_TYPE_KERNELMODE 或 MEM_TYPE_USERMODE


Return Value:

	None.


Comments:

	当指定内存不可写时，将抛出异常。调用方应该将此函数包含在try块中。


Author:

	Fypher

--*/
{
	PAGED_CODE();

	if (pAddr >= MmSystemRangeStart)			// kernel space
	{
		ULONG_PTR ulpBegPage = ((ULONG_PTR)pAddr / PAGE_SIZE) * PAGE_SIZE;
		ULONG_PTR ulpEndPage = (((ULONG_PTR)pAddr + ulLen)/ PAGE_SIZE) * PAGE_SIZE;

		if (!(ulMemType & MEM_TYPE_KERNELMODE)) {
			ExRaiseAccessViolation();
			return;
		}

		if ((ULONG_PTR)pAddr & (ulAlignment - 1))
			ExRaiseDatatypeMisalignment();

		while (ulpBegPage <= ulpEndPage) {
			if (!MmIsAddressValid((PVOID)ulpBegPage)) {
				ExRaiseAccessViolation();
				return;
			}
			ulpBegPage += PAGE_SIZE;
		}
	}
	else										// user space
	{
		if (!(ulMemType & MEM_TYPE_USERMODE)) {
			ExRaiseAccessViolation();
			return;
		}
		ProbeForWrite(pAddr, ulLen, ulAlignment);
	}
}

//#pragma PAGEDCODE
//BOOLEAN GetHash(PBYTE pBuffer, ULONG ulSize, PULONG_PTR pulpHash)
//{
//	PAGED_CODE();
//
//	ULONG i;
//	ULONG ulStep = ulSize / sizeof(ULONG_PTR);
//	if (ulStep == 0)
//		return FALSE;
//
//	*pulpHash = 0;
//
//	for (i = 0; i <sizeof(ULONG_PTR); i++) {
//
//		*pulpHash |= ((*pBuffer & 1) << i);
//
//		pBuffer += ulStep;
//	}
//
//	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "GetHash: %p\r\n", *pulpHash));
//	return TRUE;
//}
