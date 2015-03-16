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
	FltContext.ulpXxx1 = (ULONG_PTR)hMod;
	FltContext.ulpXxx2 = (ULONG_PTR)ModuleName;
	FltContext.ulpXxx3 = (ULONG_PTR)ThreadId;
	FltContext.ulpXxx4 = (ULONG_PTR)HookId;
	FltContext.ulpXxx5 = (ULONG_PTR)HookProc;
	FltContext.ulpXxx6 = (ULONG_PTR)dwFlags;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		ulRet = ((F_6)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
				FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6);


		if (ulRet && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		ulRet = 0;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return ulRet;
}
