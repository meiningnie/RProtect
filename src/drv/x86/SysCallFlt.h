#ifndef _SYSCALL_FLT_H_
#define _SYSCALL_FLT_H_

#include "Hook.h"

#define RP_STATUS_OK			0
#define RP_STATUS_ERR			1
#define RP_STATUS_NOT_CLEAR		2

typedef ULONG RPSTATUS;

typedef struct _FLT_CONTEXT_ {
	ULONG ulXxxCount;
	ULONG ulXxx1;
	ULONG ulXxx2;
	ULONG ulXxx3;
	ULONG ulXxx4;
	ULONG ulXxx5;
	ULONG ulXxx6;
	ULONG ulXxx7;
	ULONG ulXxx8;
	ULONG ulXxx9;
	ULONG ulXxx10;
	ULONG ulXxx11;
	ULONG ulXxx12;
	ULONG ulXxx13;
	ULONG ulXxx14;
	ULONG ulXxx15;
	ULONG ulXxx16;
} FLT_CONTEXT, *PFLT_CONTEXT, **PPFLT_CONTEXT;

typedef RPSTATUS (*F_FLT)(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);



RPSTATUS PreFlt_NtXXX(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PostFlt_NtXXX(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);

///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT PreFilter
//
RPSTATUS PreFlt_NtCreateFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtDeleteFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtSetInformationFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtLoadDriver(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtUnloadDriver(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtSetSystemInformation(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtCreateSection(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtCreateUserProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtCreateSymbolicLinkObject(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtCreateThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtSuspendThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtSuspendProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtGetContextThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtSetContextThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtTerminateProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtTerminateThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtAssignProcessToJobObject(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtWriteVirtualMemory(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtProtectVirtualMemory(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PreFlt_NtSystemDebugControl(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT PostFilter
//
RPSTATUS PostFlt_NtOpenFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PostFlt_NtOpenThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PostFlt_NtOpenProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PostFlt_NtOpenSection(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PostFlt_NtReadVirtualMemory(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);
RPSTATUS PostFlt_NtDuplicateObject(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);

///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT Shadow PreFilter
//
RPSTATUS PreFlt_NtUserSetWindowsHookEx(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT Shadow PostFilter
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, PreFlt_NtXXX)
#pragma alloc_text(PAGE, PostFlt_NtXXX)
#pragma alloc_text(PAGE, PreFlt_NtCreateFile)
#pragma alloc_text(PAGE, PreFlt_NtDeleteFile)
#pragma alloc_text(PAGE, PreFlt_NtSetInformationFile)
#pragma alloc_text(PAGE, PreFlt_NtLoadDriver)
#pragma alloc_text(PAGE, PreFlt_NtUnloadDriver)
#pragma alloc_text(PAGE, PreFlt_NtSetSystemInformation)
//#pragma alloc_text(PAGE, PreFlt_NtCreateSection)
#pragma alloc_text(PAGE, PreFlt_NtCreateUserProcess)
#pragma alloc_text(PAGE, PreFlt_NtCreateSymbolicLinkObject)
#pragma alloc_text(PAGE, PreFlt_NtCreateThread)
#pragma alloc_text(PAGE, PreFlt_NtSuspendThread)
#pragma alloc_text(PAGE, PreFlt_NtSuspendProcess)
#pragma alloc_text(PAGE, PreFlt_NtGetContextThread)
#pragma alloc_text(PAGE, PreFlt_NtSetContextThread)
#pragma alloc_text(PAGE, PreFlt_NtTerminateProcess)
#pragma alloc_text(PAGE, PreFlt_NtTerminateThread)
#pragma alloc_text(PAGE, PreFlt_NtAssignProcessToJobObject)
#pragma alloc_text(PAGE, PreFlt_NtWriteVirtualMemory)
#pragma alloc_text(PAGE, PreFlt_NtProtectVirtualMemory)
#pragma alloc_text(PAGE, PreFlt_NtSystemDebugControl)
#pragma alloc_text(PAGE, PostFlt_NtOpenFile)
#pragma alloc_text(PAGE, PostFlt_NtOpenThread)
#pragma alloc_text(PAGE, PostFlt_NtOpenProcess)
#pragma alloc_text(PAGE, PostFlt_NtOpenSection)
#pragma alloc_text(PAGE, PostFlt_NtReadVirtualMemory)
#pragma alloc_text(PAGE, PostFlt_NtDuplicateObject)
#pragma alloc_text(PAGE, PreFlt_NtUserSetWindowsHookEx)
#endif


#endif
