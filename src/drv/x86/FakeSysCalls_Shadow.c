/*++

Module Name:

	FakeSysCalls_Shadow.c - SSDT Shadow DetourÄ£¿é


Author:

	Fypher

	2012/02/27

--*/
#include <ntddk.h>
#include "Common.h"
#include "Hook.h"
#include "FakeSysCalls.h"
#include "SysCallFlt.h"


/*
HHOOK
NTAPI
Fake_NtUserSetWindowsHookEx(
 	HINSTANCE Mod,
	PUNICODE_STRING ModuleName,
	DWORD ThreadId,
	int HookId,
	HOOKPROC HookProc,
	DWORD dwFlags
	)*/

ULONG
NTAPI
Fake_NtUserSetWindowsHookEx(
	HANDLE hMod,
	PUNICODE_STRING ModuleName,
	HANDLE ThreadId,
	ULONG HookId,
	PVOID HookProc,
	ULONG dwFlags
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtUserSetWindowsHookEx;
	FLT_CONTEXT FltContext;
	ULONG ulRet;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 6;
	FltContext.ulXxx1 = (ULONG)hMod;
	FltContext.ulXxx2 = (ULONG)ModuleName;
	FltContext.ulXxx3 = (ULONG)ThreadId;
	FltContext.ulXxx4 = (ULONG)HookId;
	FltContext.ulXxx5 = (ULONG)HookProc;
	FltContext.ulXxx6 = (ULONG)dwFlags;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		ulRet = ((F_6)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
				FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6);


		if (ulRet && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		ulRet = 0;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return ulRet;
}





