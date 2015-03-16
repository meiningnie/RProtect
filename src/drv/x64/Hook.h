#ifndef _HOOK_H_
#define _HOOK_H_

#define NUM_OF_HOOK_OBJECTS 1024
#define NUM_OF_DPCS			0x100

#define FLT_TYPE_NONE			0x0
#define FLT_TYPE_PRE			0x1
#define FLT_TYPE_POST			0x2
#define FLT_TYPE_USERMODE		0x4
#define FLT_TYPE_KERNELMODE		0x8

#define MEM_TYPE_USERMODE		FLT_TYPE_USERMODE
#define MEM_TYPE_KERNELMODE		FLT_TYPE_KERNELMODE

typedef struct _HOOK_OBJECT_ {
	ULONG		ulSyscallId;
	ULONG_PTR	ulpOrigSysCall;
	ULONG_PTR	ulpFakeSysCall;
	ULONG_PTR	ulpPreFilter;
	ULONG_PTR	ulpPostFilter;
	ULONG		ulFltType;
	ULONG		ulCrimeType;
	ULONG		ulUserRef;
} HOOK_OBJECT, *PHOOK_OBJECT, **PPHOOK_OBJECT;




/*
extern PHOOK_OBJECT g_pHookTable_SSDT[];
extern PHOOK_OBJECT g_pHookTable_SSDTShadow[];
*/

extern HOOK_OBJECT g_HookObj_NtCreateFile;
extern HOOK_OBJECT g_HookObj_NtOpenFile;
extern HOOK_OBJECT g_HookObj_NtDeleteFile;
extern HOOK_OBJECT g_HookObj_NtSetInformationFile;
extern HOOK_OBJECT g_HookObj_NtCreateKey;
extern HOOK_OBJECT g_HookObj_NtDeleteKey;
extern HOOK_OBJECT g_HookObj_NtQueryValueKey;
extern HOOK_OBJECT g_HookObj_NtSetValueKey;
extern HOOK_OBJECT g_HookObj_NtDeleteValueKey;
extern HOOK_OBJECT g_HookObj_NtEnumerateValueKey;
//extern HOOK_OBJECT g_HookObj_NtCreateSection;
extern HOOK_OBJECT g_HookObj_NtCreateUserProcess;
extern HOOK_OBJECT g_HookObj_NtCreateSymbolicLinkObject;
extern HOOK_OBJECT g_HookObj_NtDuplicateObject;
extern HOOK_OBJECT g_HookObj_NtLoadDriver;
extern HOOK_OBJECT g_HookObj_NtUnloadDriver;
extern HOOK_OBJECT g_HookObj_NtSetSystemInformation;
extern HOOK_OBJECT g_HookObj_NtOpenSection;
extern HOOK_OBJECT g_HookObj_NtProtectVirtualMemory;
extern HOOK_OBJECT g_HookObj_NtOpenProcess;
extern HOOK_OBJECT g_HookObj_NtTerminateProcess;
extern HOOK_OBJECT g_HookObj_NtAssignProcessToJobObject;
//extern HOOK_OBJECT g_HookObj_NtAdjustGroupsToken;
//extern HOOK_OBJECT g_HookObj_NtAdjustPrivilegesToken;
//extern HOOK_OBJECT g_HookObj_NtRequestWaitReplyPort;
extern HOOK_OBJECT g_HookObj_NtCreateThread;
extern HOOK_OBJECT g_HookObj_NtOpenThread;
extern HOOK_OBJECT g_HookObj_NtSuspendThread;
extern HOOK_OBJECT g_HookObj_NtSuspendProcess;
extern HOOK_OBJECT g_HookObj_NtTerminateThread;
extern HOOK_OBJECT g_HookObj_NtGetContextThread ;
extern HOOK_OBJECT g_HookObj_NtSetContextThread;
extern HOOK_OBJECT g_HookObj_NtReadVirtualMemory;
extern HOOK_OBJECT g_HookObj_NtWriteVirtualMemory;
extern HOOK_OBJECT g_HookObj_NtSystemDebugControl;
//
extern HOOK_OBJECT g_HookObj_NtUserGetAsyncKeyState;
extern HOOK_OBJECT g_HookObj_NtUserSendInput;
extern HOOK_OBJECT g_HookObj_NtUserBuildHwndList;
extern HOOK_OBJECT g_HookObj_NtUserFindWindowEx;
extern HOOK_OBJECT g_HookObj_NtUserGetForegroundWindow;
extern HOOK_OBJECT g_HookObj_NtUserMoveWindow;
extern HOOK_OBJECT g_HookObj_NtUserQueryWindow;
extern HOOK_OBJECT g_HookObj_NtUserSetParent;
extern HOOK_OBJECT g_HookObj_NtUserSetWindowLong;
extern HOOK_OBJECT g_HookObj_NtUserSetWindowPlacement;
extern HOOK_OBJECT g_HookObj_NtUserSetWindowPos;
extern HOOK_OBJECT g_HookObj_NtUserShowWindow;
extern HOOK_OBJECT g_HookObj_NtUserShowWindowAsync;
extern HOOK_OBJECT g_HookObj_NtUserWindowFromPoint;
extern HOOK_OBJECT g_HookObj_NtUserMessageCall;
extern HOOK_OBJECT g_HookObj_NtUserPostMessage;
extern HOOK_OBJECT g_HookObj_NtUserCallHwndParamLock;
extern HOOK_OBJECT g_HookObj_NtUserDestroyWindow;
extern HOOK_OBJECT g_HookObj_NtUserSetWindowsHookEx;

/*

extern KSPIN_LOCK g_HookDpcSpinLock;
extern ULONG g_ulNumberOfRaisedCpu;
extern KDPC g_Dpcs[NUM_OF_DPCS];
*/

BOOLEAN InitFakeSysCallTable ();
BOOLEAN Hook (ULONG_PTR ulpHookPoint, PBYTE pHookCode, ULONG ulHookCodeSize);

PMDL MakeAddrWritable (ULONG_PTR ulpOldAddress, ULONG ulSize, PULONG_PTR pulpNewAddress);

VOID DpcRoutine(PKDPC pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

ULONG_PTR SuperFilter(ULONG_PTR ulpServiceId, ULONG_PTR ulpServiceAddr, ULONG_PTR ulpServiceOffset);

BOOLEAN IsAllHookObjectNotInUse();

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InitFakeSysCallTable)
#pragma alloc_text(PAGE, MakeAddrWritable)
#pragma alloc_text(PAGE, IsAllHookObjectNotInUse)
#endif


#endif
