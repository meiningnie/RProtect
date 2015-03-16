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
	ULONG	ulOrigSysCall;
	ULONG	ulFakeSysCall;
	ULONG	ulPreFilter;
	ULONG	ulPostFilter;
	ULONG		ulFltType;
	ULONG		ulCrimeType;
	ULONG		ulUserRef;
} HOOK_OBJECT, *PHOOK_OBJECT, **PPHOOK_OBJECT;


#pragma pack(1)
typedef struct _IDTINFO_ {
	USHORT IDTLimit;
	USHORT LowIDTbase;
	USHORT HiIDTbase;
} IDTINFO, *PIDTINFO, **PPIDTINFO;
#pragma pack()

#pragma pack(1)
typedef struct _IDTENTRY_{
	USHORT LowOffset;
	USHORT selector;
	UCHAR unused_lo;
	UCHAR segment_type:4;
	UCHAR system_segment_flag:1;
	UCHAR DPL:2;
	UCHAR P:1;
	USHORT HiOffset;
} IDTENTRY, *PIDTENTRY, **PPIDTENTRY;
#pragma pack()


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
extern HOOK_OBJECT g_HookObj_NtCreateSection;
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

ULONG FindHookPoint();

BOOLEAN InitFakeSysCallTable ();
BOOLEAN Hook (ULONG ulHookPoint, ULONG ulDetourAddr);
BOOLEAN UnHook ();
VOID HookInternal(ULONG ulHookPoint, ULONG ulE9909090, ULONG ulJmpOffSet);

PMDL MakeAddrWritable (ULONG ulOldAddress, ULONG ulSize, PULONG pulNewAddress);

VOID DpcRoutine(PKDPC pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

ULONG SuperFilter(ULONG ulServiceId, ULONG ulServiceAddr, ULONG ulServiceOffset);

BOOLEAN IsAllHookObjectNotInUse();

ULONG __stdcall KiFastCallEntry_Filter(ULONG ulSyscallId, ULONG ulSyscallAddr, ULONG ulSyscallTableAddr);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InitFakeSysCallTable)
#pragma alloc_text(PAGE, MakeAddrWritable)
#pragma alloc_text(PAGE, IsAllHookObjectNotInUse)
#endif


#endif
