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
//HOOK_OBJECT g_HookObj_NtCreateSection = {0};	win7, better to hook NtCreateUserProcess
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


BOOLEAN InitFakeSysCallTable ()
{
	ULONG_PTR ulpRoutineAddr;
	PAGED_CODE();
	//
	// SSDT
	//

	// NtCreateFile
	g_HookObj_NtCreateFile.ulpFakeSysCall = (ULONG_PTR)Fake_NtCreateFile;
	g_HookObj_NtCreateFile.ulpPreFilter = (ULONG_PTR)PreFlt_NtCreateFile;
	g_HookObj_NtCreateFile.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtCreateFile.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwCreateFile");

	if (ulpRoutineAddr) {
		g_HookObj_NtCreateFile.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtCreateFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateFile.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateFile.ulCrimeType = CRIME_MINOR_NtCreateFile;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtCreateFile.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtCreateFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateFile Failed!\r\n"));
	}
#endif

	// NtOpenFile
	g_HookObj_NtOpenFile.ulpFakeSysCall = (ULONG_PTR)Fake_NtOpenFile;
	g_HookObj_NtOpenFile.ulpPreFilter = (ULONG_PTR)PreFlt_NtXXX;
	g_HookObj_NtOpenFile.ulpPostFilter = (ULONG_PTR)PostFlt_NtOpenFile;
	g_HookObj_NtOpenFile.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwOpenFile");
	if (ulpRoutineAddr) {
		g_HookObj_NtOpenFile.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtOpenFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenFile.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenFile.ulCrimeType = CRIME_MINOR_NtOpenFile;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtOpenFile.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtOpenFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenFile Failed!\r\n"));
	}
#endif

	// NtDeleteFile
	g_HookObj_NtDeleteFile.ulpFakeSysCall = (ULONG_PTR)Fake_NtDeleteFile;
	g_HookObj_NtDeleteFile.ulpPreFilter = (ULONG_PTR)PreFlt_NtDeleteFile;
	g_HookObj_NtDeleteFile.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtDeleteFile.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwDeleteFile");
	if (ulpRoutineAddr) {
		g_HookObj_NtDeleteFile.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtDeleteFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtDeleteFile.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtDeleteFile.ulCrimeType = CRIME_MINOR_NtDeleteFile;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtDeleteFile.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtDeleteFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtDeleteFile Failed!\r\n"));
	}
#endif

	// NtSetInformationFile
	g_HookObj_NtSetInformationFile.ulpFakeSysCall = (ULONG_PTR)Fake_NtSetInformationFile;
	g_HookObj_NtSetInformationFile.ulpPreFilter = (ULONG_PTR)PreFlt_NtSetInformationFile;
	g_HookObj_NtSetInformationFile.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtSetInformationFile.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwSetInformationFile");
	if (ulpRoutineAddr) {
		g_HookObj_NtSetInformationFile.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtSetInformationFile.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSetInformationFile.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSetInformationFile.ulCrimeType = CRIME_MINOR_NtSetInformationFile;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtSetInformationFile.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtSetInformationFile);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSetInformationFile Failed!\r\n"));
	}
#endif

	// NtLoadDriver
	g_HookObj_NtLoadDriver.ulpFakeSysCall = (ULONG_PTR)Fake_NtLoadDriver;
	g_HookObj_NtLoadDriver.ulpPreFilter = (ULONG_PTR)PreFlt_NtLoadDriver;
	g_HookObj_NtLoadDriver.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtLoadDriver.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwLoadDriver");
	if (ulpRoutineAddr) {
		g_HookObj_NtLoadDriver.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtLoadDriver.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtLoadDriver.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtLoadDriver.ulCrimeType = CRIME_MINOR_NtLoadDriver;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtLoadDriver.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtLoadDriver);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtLoadDriver Failed!\r\n"));
	}
#endif

#ifndef RP_DBG
	// NtUnloadDriver
	g_HookObj_NtUnloadDriver.ulpFakeSysCall = (ULONG_PTR)Fake_NtUnloadDriver;
	g_HookObj_NtUnloadDriver.ulpPreFilter = (ULONG_PTR)PreFlt_NtUnloadDriver;
	g_HookObj_NtUnloadDriver.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtUnloadDriver.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwUnloadDriver");
	if (ulpRoutineAddr) {
		g_HookObj_NtUnloadDriver.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtUnloadDriver.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtUnloadDriver.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtUnloadDriver.ulCrimeType = CRIME_MINOR_NtUnloadDriver;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtUnloadDriver.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtUnloadDriver);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtUnloadDriver Failed!\r\n"));
	}
#endif
#endif

	// NtSetSystemInformation
	g_HookObj_NtSetSystemInformation.ulpFakeSysCall = (ULONG_PTR)Fake_NtSetSystemInformation;
	g_HookObj_NtSetSystemInformation.ulpPreFilter = (ULONG_PTR)PreFlt_NtSetSystemInformation;
	g_HookObj_NtSetSystemInformation.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtSetSystemInformation.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwSetSystemInformation");
	if (ulpRoutineAddr) {
		g_HookObj_NtSetSystemInformation.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtSetSystemInformation.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSetSystemInformation.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSetSystemInformation.ulCrimeType = CRIME_MINOR_NtSetSystemInformation;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtSetSystemInformation.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtSetSystemInformation);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSetSystemInformation Failed!\r\n"));
	}
#endif

	// NtCreateThread
	g_HookObj_NtCreateThread.ulpFakeSysCall = (ULONG_PTR)Fake_NtCreateThread;
	g_HookObj_NtCreateThread.ulpPreFilter = (ULONG_PTR)PreFlt_NtCreateThread;
	g_HookObj_NtCreateThread.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtCreateThread.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwCreateThread");
	if (ulpRoutineAddr) {
		g_HookObj_NtCreateThread.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtCreateThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateThread.ulCrimeType = CRIME_MINOR_NtCreateThread;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtCreateThread.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtCreateThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateThread Failed!\r\n"));
	}
#endif

	// NtOpenThread
	g_HookObj_NtOpenThread.ulpFakeSysCall = (ULONG_PTR)Fake_NtOpenThread;
	g_HookObj_NtOpenThread.ulpPreFilter = (ULONG_PTR)PreFlt_NtXXX;
	g_HookObj_NtOpenThread.ulpPostFilter = (ULONG_PTR)PostFlt_NtOpenThread;
	g_HookObj_NtOpenThread.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwOpenThread");
	if (ulpRoutineAddr) {
		g_HookObj_NtOpenThread.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtOpenThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenThread.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenThread.ulCrimeType = CRIME_MINOR_NtOpenThread;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtOpenThread.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtOpenThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenThread Failed!\r\n"));
	}
#endif

	// NtOpenProcess
	g_HookObj_NtOpenProcess.ulpFakeSysCall = (ULONG_PTR)Fake_NtOpenProcess;
	g_HookObj_NtOpenProcess.ulpPreFilter = (ULONG_PTR)PreFlt_NtXXX;
	g_HookObj_NtOpenProcess.ulpPostFilter = (ULONG_PTR)PostFlt_NtOpenProcess;
	g_HookObj_NtOpenProcess.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwOpenProcess");
	if (ulpRoutineAddr) {
		g_HookObj_NtOpenProcess.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtOpenProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenProcess.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenProcess.ulCrimeType = CRIME_MINOR_NtOpenProcess;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtOpenProcess.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtOpenProcess);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenProcess Failed!\r\n"));
	}
#endif

#ifndef RP_DBG
	// NtSuspendThread
	g_HookObj_NtSuspendThread.ulpFakeSysCall = (ULONG_PTR)Fake_NtSuspendThread;
	g_HookObj_NtSuspendThread.ulpPreFilter = (ULONG_PTR)PreFlt_NtSuspendThread;
	g_HookObj_NtSuspendThread.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtSuspendThread.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwSuspendThread");
	if (ulpRoutineAddr) {
		g_HookObj_NtSuspendThread.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtSuspendThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSuspendThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSuspendThread.ulCrimeType = CRIME_MINOR_NtSuspendThread;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtSuspendThread.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtSuspendThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSuspendThread Failed!\r\n"));
	}
#endif
#endif

	// NtSuspendProcess
	g_HookObj_NtSuspendProcess.ulpFakeSysCall = (ULONG_PTR)Fake_NtSuspendProcess;
	g_HookObj_NtSuspendProcess.ulpPreFilter = (ULONG_PTR)PreFlt_NtSuspendProcess;
	g_HookObj_NtSuspendProcess.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtSuspendProcess.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwSuspendProcess");
	if (ulpRoutineAddr) {
		g_HookObj_NtSuspendProcess.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtSuspendProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSuspendProcess.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSuspendProcess.ulCrimeType = CRIME_MINOR_NtSuspendProcess;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtSuspendProcess.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtSuspendProcess);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSuspendProcess Failed!\r\n"));
	}
#endif

	// NtGetContextThread
	g_HookObj_NtGetContextThread.ulpFakeSysCall = (ULONG_PTR)Fake_NtGetContextThread;
	g_HookObj_NtGetContextThread.ulpPreFilter = (ULONG_PTR)PreFlt_NtGetContextThread;
	g_HookObj_NtGetContextThread.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtGetContextThread.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwGetContextThread");
	if (ulpRoutineAddr) {
		g_HookObj_NtGetContextThread.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtGetContextThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtGetContextThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtGetContextThread.ulCrimeType = CRIME_MINOR_NtGetContextThread;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtGetContextThread.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtGetContextThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtGetContextThread Failed!\r\n"));
	}
#endif

	// NtSetContextThread
	g_HookObj_NtSetContextThread.ulpFakeSysCall = (ULONG_PTR)Fake_NtSetContextThread;
	g_HookObj_NtSetContextThread.ulpPreFilter = (ULONG_PTR)PreFlt_NtSetContextThread;
	g_HookObj_NtSetContextThread.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtSetContextThread.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwSetContextThread");
	if (ulpRoutineAddr) {
		g_HookObj_NtSetContextThread.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtSetContextThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSetContextThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSetContextThread.ulCrimeType = CRIME_MINOR_NtSetContextThread;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtSetContextThread.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtSetContextThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSetContextThread Failed!\r\n"));
	}
#endif

	// NtTerminateProcess
	g_HookObj_NtTerminateProcess.ulpFakeSysCall = (ULONG_PTR)Fake_NtTerminateProcess;
	g_HookObj_NtTerminateProcess.ulpPreFilter = (ULONG_PTR)PreFlt_NtTerminateProcess;
	g_HookObj_NtTerminateProcess.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtTerminateProcess.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwTerminateProcess");
	if (ulpRoutineAddr) {
		g_HookObj_NtTerminateProcess.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtTerminateProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtTerminateProcess.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtTerminateProcess.ulCrimeType = CRIME_MINOR_NtTerminateProcess;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtTerminateProcess.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtTerminateProcess);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtTerminateProcess Failed!\r\n"));
	}
#endif

	// NtTerminateThread
	g_HookObj_NtTerminateThread.ulpFakeSysCall = (ULONG_PTR)Fake_NtTerminateThread;
	g_HookObj_NtTerminateThread.ulpPreFilter = (ULONG_PTR)PreFlt_NtTerminateThread;
	g_HookObj_NtTerminateThread.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtTerminateThread.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwTerminateThread");
	if (ulpRoutineAddr) {
		g_HookObj_NtTerminateThread.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtTerminateThread.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtTerminateThread.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtTerminateThread.ulCrimeType = CRIME_MINOR_NtTerminateThread;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtTerminateThread.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtTerminateThread);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtTerminateThread Failed!\r\n"));
	}
#endif

	// NtAssignProcessToJobObject
	g_HookObj_NtAssignProcessToJobObject.ulpFakeSysCall = (ULONG_PTR)Fake_NtAssignProcessToJobObject;
	g_HookObj_NtAssignProcessToJobObject.ulpPreFilter = (ULONG_PTR)PreFlt_NtAssignProcessToJobObject;
	g_HookObj_NtAssignProcessToJobObject.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtAssignProcessToJobObject.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwAssignProcessToJobObject");
	if (ulpRoutineAddr) {
		g_HookObj_NtAssignProcessToJobObject.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtAssignProcessToJobObject.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtAssignProcessToJobObject.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtAssignProcessToJobObject.ulCrimeType = CRIME_MINOR_NtAssignProcessToJobObject;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtAssignProcessToJobObject.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtAssignProcessToJobObject);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtAssignProcessToJobObject Failed!\r\n"));
	}
#endif

/* Win7, It's better to hook NtCreateUserProcess than NtCreateSection
	// NtCreateSection
	g_HookObj_NtCreateSection.ulpFakeSysCall = (ULONG_PTR)Fake_NtCreateSection;
	g_HookObj_NtCreateSection.ulpPreFilter = (ULONG_PTR)PreFlt_NtCreateSection;
	g_HookObj_NtCreateSection.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtCreateSection.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwCreateSection");
	if (ulpRoutineAddr) {
		g_HookObj_NtCreateSection.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtCreateSection.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateSection.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateSection.ulCrimeType = CRIME_MINOR_NtCreateSection;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtCreateSection.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtCreateSection);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateSection Failed!\r\n"));
	}
#endif
*/
	// NtCreateUserProcess
	g_HookObj_NtCreateUserProcess.ulpFakeSysCall = (ULONG_PTR)Fake_NtCreateUserProcess;
	g_HookObj_NtCreateUserProcess.ulpPreFilter = (ULONG_PTR)PreFlt_NtCreateUserProcess;
	g_HookObj_NtCreateUserProcess.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtCreateUserProcess.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwCreateUserProcess");
	if (ulpRoutineAddr) {
		g_HookObj_NtCreateUserProcess.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtCreateUserProcess.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateUserProcess.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateUserProcess.ulCrimeType = CRIME_MINOR_NtCreateUserProcess;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtCreateUserProcess.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtCreateUserProcess);

	}
#ifdef DBG
		else {
			KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateUserProcess Failed!\r\n"));
		}
#endif


	// NtOpenSection
	g_HookObj_NtOpenSection.ulpFakeSysCall = (ULONG_PTR)Fake_NtOpenSection;
	g_HookObj_NtOpenSection.ulpPreFilter = (ULONG_PTR)PreFlt_NtXXX;
	g_HookObj_NtOpenSection.ulpPostFilter = (ULONG_PTR)PostFlt_NtOpenSection;
	g_HookObj_NtOpenSection.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwOpenSection");
	if (ulpRoutineAddr) {
		g_HookObj_NtOpenSection.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtOpenSection.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtOpenSection.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtOpenSection.ulCrimeType = CRIME_MINOR_NtOpenSection;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtOpenSection.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtOpenSection);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtOpenSection Failed!\r\n"));
	}
#endif

	// NtCreateSymbolicLinkObject
	g_HookObj_NtCreateSymbolicLinkObject.ulpFakeSysCall = (ULONG_PTR)Fake_NtCreateSymbolicLinkObject;
	g_HookObj_NtCreateSymbolicLinkObject.ulpPreFilter = (ULONG_PTR)PreFlt_NtCreateSymbolicLinkObject;
	g_HookObj_NtCreateSymbolicLinkObject.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtCreateSymbolicLinkObject.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwCreateSymbolicLinkObject");
	if (ulpRoutineAddr) {
		g_HookObj_NtCreateSymbolicLinkObject.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtCreateSymbolicLinkObject.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtCreateSymbolicLinkObject.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtCreateSymbolicLinkObject.ulCrimeType = CRIME_MINOR_NtCreateSymbolicLinkObject;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtCreateSymbolicLinkObject.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtCreateSymbolicLinkObject);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtCreateSymbolicLinkObject Failed!\r\n"));
	}
#endif


	// NtReadVirtualMemory
	g_HookObj_NtReadVirtualMemory.ulpFakeSysCall = (ULONG_PTR)Fake_NtReadVirtualMemory;
	g_HookObj_NtReadVirtualMemory.ulpPreFilter = (ULONG_PTR)PreFlt_NtXXX;
	g_HookObj_NtReadVirtualMemory.ulpPostFilter = (ULONG_PTR)PostFlt_NtReadVirtualMemory;
	g_HookObj_NtReadVirtualMemory.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwReadVirtualMemory");
	if (ulpRoutineAddr) {
		g_HookObj_NtReadVirtualMemory.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtReadVirtualMemory.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtReadVirtualMemory.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtReadVirtualMemory.ulCrimeType = CRIME_MINOR_NtReadVirtualMemory;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtReadVirtualMemory.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtReadVirtualMemory);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtReadVirtualMemory Failed!\r\n"));
	}
#endif

	// NtWriteVirtualMemory
	g_HookObj_NtWriteVirtualMemory.ulpFakeSysCall = (ULONG_PTR)Fake_NtWriteVirtualMemory;
	g_HookObj_NtWriteVirtualMemory.ulpPreFilter = (ULONG_PTR)PreFlt_NtWriteVirtualMemory;
	g_HookObj_NtWriteVirtualMemory.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtWriteVirtualMemory.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwWriteVirtualMemory");
	if (ulpRoutineAddr) {
		g_HookObj_NtWriteVirtualMemory.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtWriteVirtualMemory.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtWriteVirtualMemory.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtWriteVirtualMemory.ulCrimeType = CRIME_MINOR_NtWriteVirtualMemory;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtWriteVirtualMemory.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtWriteVirtualMemory);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtWriteVirtualMemory Failed!\r\n"));
	}
#endif

	// NtProtectVirtualMemory
	g_HookObj_NtProtectVirtualMemory.ulpFakeSysCall = (ULONG_PTR)Fake_NtProtectVirtualMemory;
	g_HookObj_NtProtectVirtualMemory.ulpPreFilter = (ULONG_PTR)PreFlt_NtProtectVirtualMemory;
	g_HookObj_NtProtectVirtualMemory.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtProtectVirtualMemory.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwProtectVirtualMemory");
	if (ulpRoutineAddr) {
		g_HookObj_NtProtectVirtualMemory.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtProtectVirtualMemory.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtProtectVirtualMemory.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtProtectVirtualMemory.ulCrimeType = CRIME_MINOR_NtProtectVirtualMemory;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtProtectVirtualMemory.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtProtectVirtualMemory);
	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtProtectVirtualMemory Failed!\r\n"));
	}
#endif

	// NtSystemDebugControl
	g_HookObj_NtSystemDebugControl.ulpFakeSysCall = (ULONG_PTR)Fake_NtSystemDebugControl;
	g_HookObj_NtSystemDebugControl.ulpPreFilter = (ULONG_PTR)PreFlt_NtSystemDebugControl;
	g_HookObj_NtSystemDebugControl.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtSystemDebugControl.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwSystemDebugControl");
	if (ulpRoutineAddr) {
		g_HookObj_NtSystemDebugControl.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtSystemDebugControl.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtSystemDebugControl.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
		g_HookObj_NtSystemDebugControl.ulCrimeType = CRIME_MINOR_NtSystemDebugControl;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtSystemDebugControl.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtSystemDebugControl);

	}
#ifdef DBG
	else {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hook NtSystemDebugControl Failed!\r\n"));
	}
#endif

	// NtDuplicateObject
	g_HookObj_NtDuplicateObject.ulpFakeSysCall = (ULONG_PTR)Fake_NtDuplicateObject;
	g_HookObj_NtDuplicateObject.ulpPreFilter = (ULONG_PTR)PreFlt_NtXXX;
	g_HookObj_NtDuplicateObject.ulpPostFilter = (ULONG_PTR)PostFlt_NtDuplicateObject;
	g_HookObj_NtDuplicateObject.ulUserRef = 0;

	ulpRoutineAddr = MyGetProcAddress(g_ulpNtdllBase, "ZwDuplicateObject");
	if (ulpRoutineAddr) {
		g_HookObj_NtDuplicateObject.ulSyscallId = *((PULONG)(ulpRoutineAddr + 4));
		if (g_HookObj_NtDuplicateObject.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
			return FALSE;

		g_HookObj_NtDuplicateObject.ulFltType = FLT_TYPE_POST | FLT_TYPE_USERMODE;
		g_HookObj_NtDuplicateObject.ulCrimeType = CRIME_MINOR_NtDuplicateObject;
		InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtDuplicateObject.ulSyscallId],
								(ULONG_PTR)&g_HookObj_NtDuplicateObject);

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
	g_HookObj_NtUserSetWindowsHookEx.ulpFakeSysCall = (ULONG_PTR)Fake_NtUserSetWindowsHookEx;
	g_HookObj_NtUserSetWindowsHookEx.ulpPreFilter = (ULONG_PTR)PreFlt_NtUserSetWindowsHookEx;
	g_HookObj_NtUserSetWindowsHookEx.ulpPostFilter = (ULONG_PTR)PostFlt_NtXXX;
	g_HookObj_NtUserSetWindowsHookEx.ulUserRef = 0;

	g_HookObj_NtUserSetWindowsHookEx.ulSyscallId = g_ulShadowId_NtUserSetWindowsHookEx;
	if (g_HookObj_NtUserSetWindowsHookEx.ulSyscallId >= NUM_OF_HOOK_OBJECTS)
		return FALSE;

	g_HookObj_NtUserSetWindowsHookEx.ulFltType = FLT_TYPE_PRE | FLT_TYPE_USERMODE;
	g_HookObj_NtUserSetWindowsHookEx.ulCrimeType = CRIME_MINOR_NtUserSetWindowsHookEx;
	InterlockedExchange64(	(PULONG_PTR)&g_pHookTable_SSDT[g_HookObj_NtUserSetWindowsHookEx.ulSyscallId],
							(ULONG_PTR)&g_HookObj_NtUserSetWindowsHookEx);




	// over
	return TRUE;

}

BOOLEAN Hook (ULONG_PTR ulpHookPoint, PBYTE pHookCode, ULONG ulHookCodeSize)
{
	PMDL pMdl;
	ULONG_PTR ulpNewVirtualAddr;
	ULONG i;
	KAFFINITY CpuAffinity;
	ULONG ulNumberOfActiveCpu;
	KIRQL OldIrql;
	BOOLEAN bRet = FALSE;

	ULONG ulCurrentCpu;

	pMdl = MakeAddrWritable(ulpHookPoint, 17, &ulpNewVirtualAddr);
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
		RtlCopyMemory((PULONG_PTR)ulpNewVirtualAddr, pHookCode, ulHookCodeSize);

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
				RtlCopyMemory((PULONG_PTR)ulpNewVirtualAddr, pHookCode, ulHookCodeSize);
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

PMDL MakeAddrWritable (ULONG_PTR ulpOldAddress, ULONG ulSize, PULONG_PTR pulpNewAddress)
{
	PVOID pNewAddr;
	PMDL pMdl = IoAllocateMdl((PVOID)ulpOldAddress, ulSize, FALSE, TRUE, NULL);
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

	if ( pulpNewAddress )
		*pulpNewAddress = (ULONG_PTR)pNewAddr;

	return pMdl;
}


ULONG_PTR SuperFilter(ULONG_PTR ulpServiceId, ULONG_PTR ulpServiceAddr, ULONG_PTR ulpServiceOffset) {

	ULONG_PTR ulpTableAddr = ulpServiceAddr - ulpServiceOffset;
	PHOOK_OBJECT pHookObject = NULL;

	//PAGED_CODE();

	if ( ulpServiceId >= NUM_OF_HOOK_OBJECTS)
		return ulpServiceAddr;

	if ( ulpTableAddr == g_ulpKiServiceTable && ulpServiceId <= g_ulServiceNumber )
	{
		pHookObject = g_pHookTable_SSDT[ulpServiceId];			// SSDT
	}
	else if	(ulpTableAddr == g_ulpW32pServiceTable && ulpServiceId <= g_ulShadowServiceNumber)
	{
		pHookObject = g_pHookTable_SSDTShadow[ulpServiceId];	// ShadowSSDT
	}

#ifdef DBG
	else if (ulpTableAddr == g_ulpKeServiceDescriptorTable && ulpServiceId <= g_ulServiceNumber)
	{
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"!!!!! ulSyscallTableAddr == g_KeServiceDescriptorTable !!!!!\r\n"));
	}
	else if (ulpTableAddr == g_ulpKeServiceDescriptorTableShadow && ulpServiceId <= g_ulShadowServiceNumber)
	{
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"!!!!! ulSyscallTableAddr == g_ulpKeServiceDescriptorTableShadow !!!!!\r\n"));
	}
#endif

	if (pHookObject && pHookObject->ulpFakeSysCall)
	{
		if (!(pHookObject->ulFltType & FLT_TYPE_KERNELMODE))
		{
			// no kernel filter
			if (ExGetPreviousMode() == KernelMode)
				return ulpServiceAddr;
		}
		if (!(pHookObject->ulFltType & FLT_TYPE_USERMODE))
		{
			// no user filter
			if (ExGetPreviousMode() == UserMode)
				return ulpServiceAddr;
		}
		// ok
		pHookObject->ulpOrigSysCall = ulpServiceAddr;
		return pHookObject->ulpFakeSysCall;
	}

	return ulpServiceAddr;
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
