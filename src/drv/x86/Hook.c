/*++

Module Name:

	Hook.c - Hook模块

Abstract:

	该模块负责Hook和Unhook

Author:

	Fypher

	2012/02/27

--*/
#include <ntddk.h>
#include "Common.h"
#include "Hook.h"
#include "FakeSysCalls.h"
#include "SysCallFlt.h"
#include "EventHandler.h"

//#pragma data_seg("PAGE")
PHOOK_OBJECT g_pHookTable_SSDT[NUM_OF_HOOK_OBJECTS] = {0};
PHOOK_OBJECT g_pHookTable_SSDTShadow[NUM_OF_HOOK_OBJECTS] = {0};

HOOK_OBJECT g_HookObj_NtCreateFile = {0};
HOOK_OBJECT g_HookObj_NtOpenFile = {0};
HOOK_OBJECT g_HookObj_NtDeleteFile = {0};
//
HOOK_OBJECT g_HookObj_NtSetInformationFile = {0};
HOOK_OBJECT g_HookObj_NtCreateKey = {0};
HOOK_OBJECT g_HookObj_NtDeleteKey = {0};
HOOK_OBJECT g_HookObj_NtQueryValueKey = {0};
HOOK_OBJECT g_HookObj_NtSetValueKey = {0};
HOOK_OBJECT g_HookObj_NtDeleteValueKey = {0};
HOOK_OBJECT g_HookObj_NtEnumerateValueKey = {0};
HOOK_OBJECT g_HookObj_NtCreateSection = {0};		// win7, better to hook NtCreateUserProcess
HOOK_OBJECT g_HookObj_NtCreateUserProcess = {0};
HOOK_OBJECT g_HookObj_NtCreateSymbolicLinkObject = {0};
HOOK_OBJECT g_HookObj_NtDuplicateObject = {0};
HOOK_OBJECT g_HookObj_NtLoadDriver = {0};
HOOK_OBJECT g_HookObj_NtUnloadDriver = {0};
HOOK_OBJECT g_HookObj_NtSetSystemInformation = {0};
HOOK_OBJECT g_HookObj_NtOpenSection = {0};
HOOK_OBJECT g_HookObj_NtProtectVirtualMemory = {0};
HOOK_OBJECT g_HookObj_NtOpenProcess = {0};
HOOK_OBJECT g_HookObj_NtTerminateProcess = {0};
HOOK_OBJECT g_HookObj_NtAssignProcessToJobObject = {0};
//HOOK_OBJECT g_HookObj_NtAdjustGroupsToken = {0};
//HOOK_OBJECT g_HookObj_NtAdjustPrivilegesToken = {0};
//HOOK_OBJECT g_HookObj_NtRequestWaitReplyPort = {0};
HOOK_OBJECT g_HookObj_NtCreateThread = {0};
HOOK_OBJECT g_HookObj_NtOpenThread = {0};
HOOK_OBJECT g_HookObj_NtSuspendThread = {0};
HOOK_OBJECT g_HookObj_NtSuspendProcess = {0};
HOOK_OBJECT g_HookObj_NtTerminateThread = {0};
HOOK_OBJECT g_HookObj_NtGetContextThread  = {0};
HOOK_OBJECT g_HookObj_NtSetContextThread = {0};
HOOK_OBJECT g_HookObj_NtReadVirtualMemory = {0};
HOOK_OBJECT g_HookObj_NtWriteVirtualMemory = {0};
HOOK_OBJECT g_HookObj_NtSystemDebugControl = {0};

HOOK_OBJECT g_HookObj_NtUserGetAsyncKeyState = {0};
HOOK_OBJECT g_HookObj_NtUserSendInput = {0};
HOOK_OBJECT g_HookObj_NtUserBuildHwndList = {0};
HOOK_OBJECT g_HookObj_NtUserFindWindowEx = {0};
HOOK_OBJECT g_HookObj_NtUserGetForegroundWindow = {0};
HOOK_OBJECT g_HookObj_NtUserMoveWindow = {0};
HOOK_OBJECT g_HookObj_NtUserQueryWindow = {0};
HOOK_OBJECT g_HookObj_NtUserSetParent = {0};
HOOK_OBJECT g_HookObj_NtUserSetWindowLong = {0};
HOOK_OBJECT g_HookObj_NtUserSetWindowPlacement = {0};
HOOK_OBJECT g_HookObj_NtUserSetWindowPos = {0};
HOOK_OBJECT g_HookObj_NtUserShowWindow = {0};
HOOK_OBJECT g_HookObj_NtUserShowWindowAsync = {0};
HOOK_OBJECT g_HookObj_NtUserWindowFromPoint = {0};
HOOK_OBJECT g_HookObj_NtUserMessageCall = {0};
HOOK_OBJECT g_HookObj_NtUserPostMessage = {0};
HOOK_OBJECT g_HookObj_NtUserCallHwndParamLock = {0};
HOOK_OBJECT g_HookObj_NtUserDestroyWindow = {0};
//
HOOK_OBJECT g_HookObj_NtUserSetWindowsHookEx = {0};

//#pragma data_seg()

KSPIN_LOCK g_HookDpcSpinLock;
volatile ULONG g_ulNumberOfRaisedCpu;
KDPC g_Dpcs[NUM_OF_DPCS];

ULONG FindHookPoint()
{

	ULONG ulKiSystemService;
	ULONG ulAddr;

	if (!MmIsAddressValid((PVOID)g_ulMmUserProbeAddress))
		return 0;
	*((PULONG)(g_Signature + 4)) = g_ulMmUserProbeAddress;

	for (ulAddr = g_ulKiSystemService; ulAddr < g_ulKiSystemService + (PAGE_SIZE / 4); ++ulAddr) {
		if (!MmIsAddressValid((PVOID)ulAddr))
			break;

		if ( RtlCompareMemory((PVOID)ulAddr, &g_Signature, sizeof(g_Signature)) == sizeof(g_Signature) )
			return ulAddr;
	}
	return 0;
}


BOOLEAN InitFakeSysCallTable ()
{
	ULONG ulRoutineAddr;
	PAGED_CODE();
	//
	// SSDT
	//

	// NtCreateFile
	g_HookObj_NtCreateFile.ulFakeSysCall = (ULONG)Fake_NtCreateFile;
	g_HookObj_NtCreateFile.ulPreFilter = (ULONG)PreFlt_NtCreateFile;
	g_HookObj_NtCreateFile.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtCreateFile.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwCreateFile");

 	if (ulRoutineAddr) {
 		g_HookObj_NtCreateFile.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtCreateFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateFile.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateFile.ulCrimeType = CRIME_MINOR_NtCreateFile;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtCreateFile.ulSyscallId],
								(ULONG)&g_HookObj_NtCreateFile);

 	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateFile Failed!\r\n"));
	}
#endif

	// NtOpenFile
	g_HookObj_NtOpenFile.ulFakeSysCall = (ULONG)Fake_NtOpenFile;
	g_HookObj_NtOpenFile.ulPreFilter = (ULONG)PreFlt_NtXXX;
	g_HookObj_NtOpenFile.ulPostFilter = (ULONG)PostFlt_NtOpenFile;
	g_HookObj_NtOpenFile.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwOpenFile");
	if (ulRoutineAddr) {
		g_HookObj_NtOpenFile.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtOpenFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenFile.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenFile.ulCrimeType = CRIME_MINOR_NtOpenFile;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtOpenFile.ulSyscallId],
								(ULONG)&g_HookObj_NtOpenFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenFile Failed!\r\n"));
	}
#endif

	// NtDeleteFile
	g_HookObj_NtDeleteFile.ulFakeSysCall = (ULONG)Fake_NtDeleteFile;
	g_HookObj_NtDeleteFile.ulPreFilter = (ULONG)PreFlt_NtDeleteFile;
	g_HookObj_NtDeleteFile.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtDeleteFile.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwDeleteFile");
	if (ulRoutineAddr) {
		g_HookObj_NtDeleteFile.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtDeleteFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtDeleteFile.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtDeleteFile.ulCrimeType = CRIME_MINOR_NtDeleteFile;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtDeleteFile.ulSyscallId],
								(ULONG)&g_HookObj_NtDeleteFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtDeleteFile Failed!\r\n"));
	}
#endif

	// NtSetInformationFile
	g_HookObj_NtSetInformationFile.ulFakeSysCall = (ULONG)Fake_NtSetInformationFile;
	g_HookObj_NtSetInformationFile.ulPreFilter = (ULONG)PreFlt_NtSetInformationFile;
	g_HookObj_NtSetInformationFile.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtSetInformationFile.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwSetInformationFile");
	if (ulRoutineAddr) {
		g_HookObj_NtSetInformationFile.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtSetInformationFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSetInformationFile.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSetInformationFile.ulCrimeType = CRIME_MINOR_NtSetInformationFile;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtSetInformationFile.ulSyscallId],
								(ULONG)&g_HookObj_NtSetInformationFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSetInformationFile Failed!\r\n"));
	}
#endif

	// NtLoadDriver
	g_HookObj_NtLoadDriver.ulFakeSysCall = (ULONG)Fake_NtLoadDriver;
	g_HookObj_NtLoadDriver.ulPreFilter = (ULONG)PreFlt_NtLoadDriver;
	g_HookObj_NtLoadDriver.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtLoadDriver.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwLoadDriver");
	if (ulRoutineAddr) {
		g_HookObj_NtLoadDriver.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtLoadDriver.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtLoadDriver.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtLoadDriver.ulCrimeType = CRIME_MINOR_NtLoadDriver;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtLoadDriver.ulSyscallId],
								(ULONG)&g_HookObj_NtLoadDriver);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtLoadDriver Failed!\r\n"));
	}
#endif

#ifndef RP_DBG
	// NtUnloadDriver
	g_HookObj_NtUnloadDriver.ulFakeSysCall = (ULONG)Fake_NtUnloadDriver;
	g_HookObj_NtUnloadDriver.ulPreFilter = (ULONG)PreFlt_NtUnloadDriver;
	g_HookObj_NtUnloadDriver.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtUnloadDriver.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwUnloadDriver");
	if (ulRoutineAddr) {
		g_HookObj_NtUnloadDriver.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtUnloadDriver.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtUnloadDriver.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtUnloadDriver.ulCrimeType = CRIME_MINOR_NtUnloadDriver;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtUnloadDriver.ulSyscallId],
								(ULONG)&g_HookObj_NtUnloadDriver);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtUnloadDriver Failed!\r\n"));
	}
#endif
#endif

	// NtSetSystemInformation
	g_HookObj_NtSetSystemInformation.ulFakeSysCall = (ULONG)Fake_NtSetSystemInformation;
	g_HookObj_NtSetSystemInformation.ulPreFilter = (ULONG)PreFlt_NtSetSystemInformation;
	g_HookObj_NtSetSystemInformation.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtSetSystemInformation.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwSetSystemInformation");
	if (ulRoutineAddr) {
		g_HookObj_NtSetSystemInformation.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtSetSystemInformation.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSetSystemInformation.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSetSystemInformation.ulCrimeType = CRIME_MINOR_NtSetSystemInformation;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtSetSystemInformation.ulSyscallId],
								(ULONG)&g_HookObj_NtSetSystemInformation);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSetSystemInformation Failed!\r\n"));
	}
#endif

	// NtCreateThread
	g_HookObj_NtCreateThread.ulFakeSysCall = (ULONG)Fake_NtCreateThread;
	g_HookObj_NtCreateThread.ulPreFilter = (ULONG)PreFlt_NtCreateThread;
	g_HookObj_NtCreateThread.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtCreateThread.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwCreateThread");
	if (ulRoutineAddr) {
		g_HookObj_NtCreateThread.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtCreateThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateThread.ulCrimeType = CRIME_MINOR_NtCreateThread;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtCreateThread.ulSyscallId],
								(ULONG)&g_HookObj_NtCreateThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateThread Failed!\r\n"));
	}
#endif

	// NtOpenThread
	g_HookObj_NtOpenThread.ulFakeSysCall = (ULONG)Fake_NtOpenThread;
	g_HookObj_NtOpenThread.ulPreFilter = (ULONG)PreFlt_NtXXX;
	g_HookObj_NtOpenThread.ulPostFilter = (ULONG)PostFlt_NtOpenThread;
	g_HookObj_NtOpenThread.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwOpenThread");
	if (ulRoutineAddr) {
		g_HookObj_NtOpenThread.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtOpenThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenThread.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenThread.ulCrimeType = CRIME_MINOR_NtOpenThread;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtOpenThread.ulSyscallId],
								(ULONG)&g_HookObj_NtOpenThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenThread Failed!\r\n"));
	}
#endif

	// NtOpenProcess
	g_HookObj_NtOpenProcess.ulFakeSysCall = (ULONG)Fake_NtOpenProcess;
	g_HookObj_NtOpenProcess.ulPreFilter = (ULONG)PreFlt_NtXXX;
	g_HookObj_NtOpenProcess.ulPostFilter = (ULONG)PostFlt_NtOpenProcess;
	g_HookObj_NtOpenProcess.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwOpenProcess");
	if (ulRoutineAddr) {
		g_HookObj_NtOpenProcess.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtOpenProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenProcess.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenProcess.ulCrimeType = CRIME_MINOR_NtOpenProcess;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtOpenProcess.ulSyscallId],
								(ULONG)&g_HookObj_NtOpenProcess);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenProcess Failed!\r\n"));
	}
#endif

#ifndef RP_DBG
	// NtSuspendThread
	g_HookObj_NtSuspendThread.ulFakeSysCall = (ULONG)Fake_NtSuspendThread;
	g_HookObj_NtSuspendThread.ulPreFilter = (ULONG)PreFlt_NtSuspendThread;
	g_HookObj_NtSuspendThread.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtSuspendThread.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwSuspendThread");
	if (ulRoutineAddr) {
		g_HookObj_NtSuspendThread.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtSuspendThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSuspendThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSuspendThread.ulCrimeType = CRIME_MINOR_NtSuspendThread;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtSuspendThread.ulSyscallId],
								(ULONG)&g_HookObj_NtSuspendThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSuspendThread Failed!\r\n"));
	}
#endif
#endif

	// NtSuspendProcess
	g_HookObj_NtSuspendProcess.ulFakeSysCall = (ULONG)Fake_NtSuspendProcess;
	g_HookObj_NtSuspendProcess.ulPreFilter = (ULONG)PreFlt_NtSuspendProcess;
	g_HookObj_NtSuspendProcess.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtSuspendProcess.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwSuspendProcess");
	if (ulRoutineAddr) {
		g_HookObj_NtSuspendProcess.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtSuspendProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSuspendProcess.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSuspendProcess.ulCrimeType = CRIME_MINOR_NtSuspendProcess;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtSuspendProcess.ulSyscallId],
								(ULONG)&g_HookObj_NtSuspendProcess);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSuspendProcess Failed!\r\n"));
	}
#endif

	// NtGetContextThread
	g_HookObj_NtGetContextThread.ulFakeSysCall = (ULONG)Fake_NtGetContextThread;
	g_HookObj_NtGetContextThread.ulPreFilter = (ULONG)PreFlt_NtGetContextThread;
	g_HookObj_NtGetContextThread.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtGetContextThread.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwGetContextThread");
	if (ulRoutineAddr) {
		g_HookObj_NtGetContextThread.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtGetContextThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtGetContextThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtGetContextThread.ulCrimeType = CRIME_MINOR_NtGetContextThread;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtGetContextThread.ulSyscallId],
								(ULONG)&g_HookObj_NtGetContextThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtGetContextThread Failed!\r\n"));
	}
#endif

	// NtSetContextThread
	g_HookObj_NtSetContextThread.ulFakeSysCall = (ULONG)Fake_NtSetContextThread;
	g_HookObj_NtSetContextThread.ulPreFilter = (ULONG)PreFlt_NtSetContextThread;
	g_HookObj_NtSetContextThread.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtSetContextThread.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwSetContextThread");
	if (ulRoutineAddr) {
		g_HookObj_NtSetContextThread.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtSetContextThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSetContextThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSetContextThread.ulCrimeType = CRIME_MINOR_NtSetContextThread;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtSetContextThread.ulSyscallId],
								(ULONG)&g_HookObj_NtSetContextThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSetContextThread Failed!\r\n"));
	}
#endif

	// NtTerminateProcess
	g_HookObj_NtTerminateProcess.ulFakeSysCall = (ULONG)Fake_NtTerminateProcess;
	g_HookObj_NtTerminateProcess.ulPreFilter = (ULONG)PreFlt_NtTerminateProcess;
	g_HookObj_NtTerminateProcess.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtTerminateProcess.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwTerminateProcess");
	if (ulRoutineAddr) {
		g_HookObj_NtTerminateProcess.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtTerminateProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtTerminateProcess.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtTerminateProcess.ulCrimeType = CRIME_MINOR_NtTerminateProcess;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtTerminateProcess.ulSyscallId],
								(ULONG)&g_HookObj_NtTerminateProcess);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtTerminateProcess Failed!\r\n"));
	}
#endif

	// NtTerminateThread
	g_HookObj_NtTerminateThread.ulFakeSysCall = (ULONG)Fake_NtTerminateThread;
	g_HookObj_NtTerminateThread.ulPreFilter = (ULONG)PreFlt_NtTerminateThread;
	g_HookObj_NtTerminateThread.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtTerminateThread.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwTerminateThread");
	if (ulRoutineAddr) {
		g_HookObj_NtTerminateThread.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtTerminateThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtTerminateThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtTerminateThread.ulCrimeType = CRIME_MINOR_NtTerminateThread;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtTerminateThread.ulSyscallId],
								(ULONG)&g_HookObj_NtTerminateThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtTerminateThread Failed!\r\n"));
	}
#endif

	// NtAssignProcessToJobObject
	g_HookObj_NtAssignProcessToJobObject.ulFakeSysCall = (ULONG)Fake_NtAssignProcessToJobObject;
	g_HookObj_NtAssignProcessToJobObject.ulPreFilter = (ULONG)PreFlt_NtAssignProcessToJobObject;
	g_HookObj_NtAssignProcessToJobObject.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtAssignProcessToJobObject.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwAssignProcessToJobObject");
	if (ulRoutineAddr) {
		g_HookObj_NtAssignProcessToJobObject.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtAssignProcessToJobObject.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtAssignProcessToJobObject.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtAssignProcessToJobObject.ulCrimeType = CRIME_MINOR_NtAssignProcessToJobObject;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtAssignProcessToJobObject.ulSyscallId],
								(ULONG)&g_HookObj_NtAssignProcessToJobObject);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtAssignProcessToJobObject Failed!\r\n"));
	}
#endif

	// Win7, It's better to hook NtCreateUserProcess than NtCreateSection
	// NtCreateSection
	if (g_ulOsVersion < OS_VERSION_VISTA)
	{
		g_HookObj_NtCreateSection.ulFakeSysCall = (ULONG)Fake_NtCreateSection;
		g_HookObj_NtCreateSection.ulPreFilter = (ULONG)PreFlt_NtCreateSection;
		g_HookObj_NtCreateSection.ulPostFilter = (ULONG)PostFlt_NtXXX;
		g_HookObj_NtCreateSection.ulUserRef = 0;

		ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwCreateSection");
		if (ulRoutineAddr) {
			g_HookObj_NtCreateSection.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
			if (g_HookObj_NtCreateSection.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
				return FALSE;

			g_HookObj_NtCreateSection.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
			g_HookObj_NtCreateSection.ulCrimeType = CRIME_MINOR_NtCreateSection;
			InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtCreateSection.ulSyscallId],
									(ULONG)&g_HookObj_NtCreateSection);

		}
#ifdef DBG
		else {
			KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateSection Failed!\r\n"));
		}
#endif
	}
	else
	{
	// NtCreateUserProcess
		g_HookObj_NtCreateUserProcess.ulFakeSysCall = (ULONG)Fake_NtCreateUserProcess;
		g_HookObj_NtCreateUserProcess.ulPreFilter = (ULONG)PreFlt_NtCreateUserProcess;
		g_HookObj_NtCreateUserProcess.ulPostFilter = (ULONG)PostFlt_NtXXX;
		g_HookObj_NtCreateUserProcess.ulUserRef = 0;

		ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwCreateUserProcess");
		if (ulRoutineAddr) {
			g_HookObj_NtCreateUserProcess.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
			if (g_HookObj_NtCreateUserProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
				return FALSE;

			g_HookObj_NtCreateUserProcess.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
			g_HookObj_NtCreateUserProcess.ulCrimeType = CRIME_MINOR_NtCreateUserProcess;
			InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtCreateUserProcess.ulSyscallId],
									(ULONG)&g_HookObj_NtCreateUserProcess);

		}
#ifdef DBG
		else {
			KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateUserProcess Failed!\r\n"));
		}
#endif
	}

	// NtOpenSection
	g_HookObj_NtOpenSection.ulFakeSysCall = (ULONG)Fake_NtOpenSection;
	g_HookObj_NtOpenSection.ulPreFilter = (ULONG)PreFlt_NtXXX;
	g_HookObj_NtOpenSection.ulPostFilter = (ULONG)PostFlt_NtOpenSection;
	g_HookObj_NtOpenSection.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwOpenSection");
	if (ulRoutineAddr) {
		g_HookObj_NtOpenSection.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtOpenSection.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenSection.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenSection.ulCrimeType = CRIME_MINOR_NtOpenSection;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtOpenSection.ulSyscallId],
								(ULONG)&g_HookObj_NtOpenSection);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenSection Failed!\r\n"));
	}
#endif

	// NtCreateSymbolicLinkObject
	g_HookObj_NtCreateSymbolicLinkObject.ulFakeSysCall = (ULONG)Fake_NtCreateSymbolicLinkObject;
	g_HookObj_NtCreateSymbolicLinkObject.ulPreFilter = (ULONG)PreFlt_NtCreateSymbolicLinkObject;
	g_HookObj_NtCreateSymbolicLinkObject.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtCreateSymbolicLinkObject.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwCreateSymbolicLinkObject");
	if (ulRoutineAddr) {
		g_HookObj_NtCreateSymbolicLinkObject.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtCreateSymbolicLinkObject.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateSymbolicLinkObject.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateSymbolicLinkObject.ulCrimeType = CRIME_MINOR_NtCreateSymbolicLinkObject;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtCreateSymbolicLinkObject.ulSyscallId],
								(ULONG)&g_HookObj_NtCreateSymbolicLinkObject);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateSymbolicLinkObject Failed!\r\n"));
	}
#endif


	// NtReadVirtualMemory
	g_HookObj_NtReadVirtualMemory.ulFakeSysCall = (ULONG)Fake_NtReadVirtualMemory;
	g_HookObj_NtReadVirtualMemory.ulPreFilter = (ULONG)PreFlt_NtXXX;
	g_HookObj_NtReadVirtualMemory.ulPostFilter = (ULONG)PostFlt_NtReadVirtualMemory;
	g_HookObj_NtReadVirtualMemory.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwReadVirtualMemory");
	if (ulRoutineAddr) {
		g_HookObj_NtReadVirtualMemory.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtReadVirtualMemory.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtReadVirtualMemory.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtReadVirtualMemory.ulCrimeType = CRIME_MINOR_NtReadVirtualMemory;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtReadVirtualMemory.ulSyscallId],
								(ULONG)&g_HookObj_NtReadVirtualMemory);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtReadVirtualMemory Failed!\r\n"));
	}
#endif

	// NtWriteVirtualMemory
	g_HookObj_NtWriteVirtualMemory.ulFakeSysCall = (ULONG)Fake_NtWriteVirtualMemory;
	g_HookObj_NtWriteVirtualMemory.ulPreFilter = (ULONG)PreFlt_NtWriteVirtualMemory;
	g_HookObj_NtWriteVirtualMemory.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtWriteVirtualMemory.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwWriteVirtualMemory");
	if (ulRoutineAddr) {
		g_HookObj_NtWriteVirtualMemory.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtWriteVirtualMemory.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtWriteVirtualMemory.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtWriteVirtualMemory.ulCrimeType = CRIME_MINOR_NtWriteVirtualMemory;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtWriteVirtualMemory.ulSyscallId],
								(ULONG)&g_HookObj_NtWriteVirtualMemory);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtWriteVirtualMemory Failed!\r\n"));
	}
#endif

	// NtProtectVirtualMemory
	g_HookObj_NtProtectVirtualMemory.ulFakeSysCall = (ULONG)Fake_NtProtectVirtualMemory;
	g_HookObj_NtProtectVirtualMemory.ulPreFilter = (ULONG)PreFlt_NtProtectVirtualMemory;
	g_HookObj_NtProtectVirtualMemory.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtProtectVirtualMemory.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwProtectVirtualMemory");
	if (ulRoutineAddr) {
		g_HookObj_NtProtectVirtualMemory.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtProtectVirtualMemory.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtProtectVirtualMemory.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtProtectVirtualMemory.ulCrimeType = CRIME_MINOR_NtProtectVirtualMemory;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtProtectVirtualMemory.ulSyscallId],
								(ULONG)&g_HookObj_NtProtectVirtualMemory);
	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtProtectVirtualMemory Failed!\r\n"));
	}
#endif

	// NtSystemDebugControl
	g_HookObj_NtSystemDebugControl.ulFakeSysCall = (ULONG)Fake_NtSystemDebugControl;
	g_HookObj_NtSystemDebugControl.ulPreFilter = (ULONG)PreFlt_NtSystemDebugControl;
	g_HookObj_NtSystemDebugControl.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtSystemDebugControl.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwSystemDebugControl");
	if (ulRoutineAddr) {
		g_HookObj_NtSystemDebugControl.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtSystemDebugControl.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSystemDebugControl.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSystemDebugControl.ulCrimeType = CRIME_MINOR_NtSystemDebugControl;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtSystemDebugControl.ulSyscallId],
								(ULONG)&g_HookObj_NtSystemDebugControl);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSystemDebugControl Failed!\r\n"));
	}
#endif

	// NtDuplicateObject
	g_HookObj_NtDuplicateObject.ulFakeSysCall = (ULONG)Fake_NtDuplicateObject;
	g_HookObj_NtDuplicateObject.ulPreFilter = (ULONG)PreFlt_NtXXX;
	g_HookObj_NtDuplicateObject.ulPostFilter = (ULONG)PostFlt_NtDuplicateObject;
	g_HookObj_NtDuplicateObject.ulUserRef = 0;

	ulRoutineAddr = MyGetProcAddress(g_ulNtdllBase, "ZwDuplicateObject");
	if (ulRoutineAddr) {
		g_HookObj_NtDuplicateObject.ulSyscallId = *((PULONG)(ulRoutineAddr + 1));
		if (g_HookObj_NtDuplicateObject.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtDuplicateObject.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtDuplicateObject.ulCrimeType = CRIME_MINOR_NtDuplicateObject;
		InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtDuplicateObject.ulSyscallId],
								(ULONG)&g_HookObj_NtDuplicateObject);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtDuplicateObject Failed!\r\n"));
	}
#endif


	//
	//	Shadow SSDT
	//

	// NtUserSetWindowsHookEx
	g_HookObj_NtUserSetWindowsHookEx.ulFakeSysCall = (ULONG)Fake_NtUserSetWindowsHookEx;
	g_HookObj_NtUserSetWindowsHookEx.ulPreFilter = (ULONG)PreFlt_NtUserSetWindowsHookEx;
	g_HookObj_NtUserSetWindowsHookEx.ulPostFilter = (ULONG)PostFlt_NtXXX;
	g_HookObj_NtUserSetWindowsHookEx.ulUserRef = 0;

	g_HookObj_NtUserSetWindowsHookEx.ulSyscallId = g_ulShadowId_NtUserSetWindowsHookEx;
	if (g_HookObj_NtUserSetWindowsHookEx.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
		return FALSE;

	g_HookObj_NtUserSetWindowsHookEx.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
	g_HookObj_NtUserSetWindowsHookEx.ulCrimeType = CRIME_MINOR_NtUserSetWindowsHookEx;
	InterlockedExchange(	(PULONG)&g_pHookTable_SSDT[g_HookObj_NtUserSetWindowsHookEx.ulSyscallId],
							(ULONG)&g_HookObj_NtUserSetWindowsHookEx);




	// over
	return TRUE;

}

BOOLEAN Hook (ULONG ulHookPoint, ULONG ulDetourAddr)
{
	PMDL pMdl;
	ULONG ulNewVirtualAddr;
	ULONG i;
	KAFFINITY CpuAffinity;
	ULONG ulNumberOfActiveCpu;
	KIRQL OldIrql;
	BOOLEAN bRet = FALSE;

	ULONG ulCurrentCpu;

	pMdl = MakeAddrWritable(ulHookPoint, 17, &ulNewVirtualAddr);
	if (!pMdl)
		return FALSE;

	// +++
	CpuAffinity = KeQueryActiveProcessors();
	ulNumberOfActiveCpu = 0;

	for (i = 0; i < 32; ++i) {
		if ( (CpuAffinity >> i) & 1 )
			++ulNumberOfActiveCpu;
	}

	if ( ulNumberOfActiveCpu == 1 )	// one cpu!
	{
		OldIrql = KeRaiseIrqlToDpcLevel();

		// hook
		memcpy(g_OriginalBytes, (PVOID)ulNewVirtualAddr, 8);
		HookInternal(ulNewVirtualAddr, 0xe9909090, ulDetourAddr - ulHookPoint - 8);

		KeLowerIrql(OldIrql);
		bRet = TRUE;
	}
	else							// mutiple cpu!
	{
		KeInitializeSpinLock(&g_HookDpcSpinLock);
		for (i = 0; i < NUM_OF_DPCS; ++i) {
			KeInitializeDpc(&g_Dpcs[i], DpcRoutine, NULL);
		}

		g_ulNumberOfRaisedCpu = 0;
		KeAcquireSpinLock(&g_HookDpcSpinLock, &OldIrql);

		ulCurrentCpu = KeGetCurrentProcessorNumber();
		ulNumberOfActiveCpu = 0;

		for (i = 0; i < 32; ++i) {
			if ((CpuAffinity >> i) & 1) {
				++ulNumberOfActiveCpu;
				if (i != ulCurrentCpu) {
					KeSetTargetProcessorDpc(&g_Dpcs[i], (CCHAR)i);
					KeSetImportanceDpc(&g_Dpcs[i], HighImportance);
					KeInsertQueueDpc(&g_Dpcs[i], NULL, NULL);
				}
			}
		}

		//for (i = 0; i < 16; i ++) {
			//ULONG ulTmp = 1000000;
			//while (ulTmp)
			//	ulTmp--;
		while (1) {
			if ( g_ulNumberOfRaisedCpu == ulNumberOfActiveCpu - 1 ) {
				// hook
				memcpy(g_OriginalBytes, (PVOID)ulNewVirtualAddr, 8);
				HookInternal(ulNewVirtualAddr, 0xe9909090, ulDetourAddr - ulHookPoint - 8);

				bRet = TRUE;
				break;
			}
		}

		KeReleaseSpinLock(&g_HookDpcSpinLock, OldIrql);
	}
	// ---

	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return bRet;
}

BOOLEAN UnHook ()
{
	PMDL pMdl;
	ULONG ulNewVirtualAddr;
	ULONG i;
	KAFFINITY CpuAffinity;
	ULONG ulNumberOfActiveCpu;
	KIRQL OldIrql;
	BOOLEAN bRet = FALSE;

	ULONG ulCurrentCpu;

	pMdl = MakeAddrWritable(g_ulHookPoint, 17, &ulNewVirtualAddr);
	if (!pMdl)
		return FALSE;

	// +++
	CpuAffinity = KeQueryActiveProcessors();
	ulNumberOfActiveCpu = 0;

	for (i = 0; i < 32; ++i) {
		if ( (CpuAffinity >> i) & 1 )
			++ulNumberOfActiveCpu;
	}

	if ( ulNumberOfActiveCpu == 1 )	// one cpu!
	{
		OldIrql = KeRaiseIrqlToDpcLevel();

		// hook
		MyMemCpy_NoPaged((PUCHAR)g_ulHookPoint, (PUCHAR)g_OriginalBytes, 8);

		KeLowerIrql(OldIrql);
		bRet = TRUE;
	}
	else							// mutiple cpu!
	{
		KeInitializeSpinLock(&g_HookDpcSpinLock);
		for (i = 0; i < NUM_OF_DPCS; ++i) {
			KeInitializeDpc(&g_Dpcs[i], DpcRoutine, NULL);
		}

		g_ulNumberOfRaisedCpu = 0;
		KeAcquireSpinLock(&g_HookDpcSpinLock, &OldIrql);

		ulCurrentCpu = KeGetCurrentProcessorNumber();
		ulNumberOfActiveCpu = 0;

		for (i = 0; i < 32; ++i) {
			if ((CpuAffinity >> i) & 1) {
				++ulNumberOfActiveCpu;
				if (i != ulCurrentCpu) {
					KeSetTargetProcessorDpc(&g_Dpcs[i], (CCHAR)i);
					KeSetImportanceDpc(&g_Dpcs[i], HighImportance);
					KeInsertQueueDpc(&g_Dpcs[i], NULL, NULL);
				}
			}
		}

		//for (i = 0; i < 16; i ++) {
			//ULONG ulTmp = 1000000;
			//while (ulTmp)
			//	ulTmp--;
		while (1) {
			if ( g_ulNumberOfRaisedCpu == ulNumberOfActiveCpu - 1 ) {
				// hook
				MyMemCpy_NoPaged((PUCHAR)g_ulHookPoint, (PUCHAR)g_OriginalBytes, 8);

				bRet = TRUE;
				break;
			}
		}

		KeReleaseSpinLock(&g_HookDpcSpinLock, OldIrql);
	}
	// ---

	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return bRet;
}


VOID DpcRoutine(PKDPC pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	KIRQL OldIrql;

	OldIrql = KeRaiseIrqlToDpcLevel();
	InterlockedIncrement(&g_ulNumberOfRaisedCpu);

	KeAcquireSpinLockAtDpcLevel(&g_HookDpcSpinLock);
	KeReleaseSpinLockFromDpcLevel(&g_HookDpcSpinLock);
	KeLowerIrql(OldIrql);
}

VOID HookInternal(ULONG ulHookPoint, ULONG ulE9909090, ULONG ulJmpOffSet) {
	__asm {
		mov edi, ulHookPoint;

		mov eax, [edi];                 // orig ins
		mov edx, [edi + 4];             // orig ins

		mov ebx, ulE9909090;
		mov ecx, ulJmpOffSet;

		// Compare EDX:EAX with m64. If equal, set ZF and load ECX:EBX into m64.
		// Else, clear ZF and load m64 into EDX:EAX.
		lock cmpxchg8b qword ptr [edi];
	}
}


PMDL MakeAddrWritable (ULONG ulOldAddress, ULONG ulSize, PULONG pulNewAddress)
{
	PVOID pNewAddr;
	PMDL pMdl = IoAllocateMdl((PVOID)ulOldAddress, ulSize, FALSE, TRUE, NULL);
	if (!pMdl)
		return NULL;
	PAGED_CODE();

	__try {
		MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(pMdl);
		return NULL;
	}

	if ( pMdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL ))
		pNewAddr = pMdl->MappedSystemVa;
	else                                            // Map a new VA!!!
		pNewAddr = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

	if ( !pNewAddr ) {
		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);
		return NULL;
	}

	if ( pulNewAddress )
		*pulNewAddress = (ULONG)pNewAddr;

	return pMdl;
}


ULONG __stdcall KiFastCallEntry_Filter(ULONG ulSyscallId, ULONG ulSyscallAddr, ULONG ulSyscallTableAddr)
{
	PHOOK_OBJECT pHookObject = NULL;

	if ( ulSyscallId >= NUM_OF_HOOK_OBJECTS)
		return ulSyscallAddr;

	if ( ulSyscallTableAddr == g_ulKiServiceTable && ulSyscallId <= g_ulServiceNumber )
	{
		pHookObject = g_pHookTable_SSDT[ulSyscallId];		// SSDT
	}
	else if (ulSyscallTableAddr == g_ulKeServiceDescriptorTable && ulSyscallId <= g_ulServiceNumber)
	{
		pHookObject = g_pHookTable_SSDT[ulSyscallId];		// SSDT
	}
	else if (ulSyscallTableAddr == g_ulW32pServiceTable && ulSyscallId <= g_ulShadowServiceNumber)
	{
		pHookObject = g_pHookTable_SSDTShadow[ulSyscallId]; // ShadowSSDT
	}

	if (pHookObject && pHookObject->ulFakeSysCall)
	{
		if (!(pHookObject->ulFltType & FLT_TYPE_KERNELMODE))
		{
			// no kernel filter
			if (ExGetPreviousMode() == KernelMode)
				return ulSyscallAddr;
		}
		if (!(pHookObject->ulFltType & FLT_TYPE_USERMODE))
		{
			// no user filter
			if (ExGetPreviousMode() == UserMode)
				return ulSyscallAddr;
		}
		// ok
		pHookObject->ulOrigSysCall = ulSyscallAddr;
		return pHookObject->ulFakeSysCall;
	}

	return ulSyscallAddr;
}


BOOLEAN IsAllHookObjectNotInUse()
{
	ULONG i;

	PAGED_CODE();

	for (i = 0; i < NUM_OF_HOOK_OBJECTS; ++i)
	{
		PHOOK_OBJECT pHookObj_SSDT = g_pHookTable_SSDT[i];
		PHOOK_OBJECT pHookObj_SSDTShadow = g_pHookTable_SSDTShadow[i];
		if ( (pHookObj_SSDT && 0 != pHookObj_SSDT->ulUserRef) 				||
			 (pHookObj_SSDTShadow && 0 != pHookObj_SSDTShadow->ulUserRef)	 )
		{
			KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "IsAllHookObjectNotInUse() == FALSE"));
			return FALSE;
		}
	}
	return TRUE;
}

