/*++

Module Name:

	SysCallFlt_Post.c - Post Filter模块

Abstract:

	该模块负责对系统调用进行事后处理

Author:

	Fypher

	2012/02/27

--*/
#include <ntifs.h>
#include "Common.h"
#include "Hook.h"
#include "SysCallFlt.h"
#include "EventHandler.h"


RPSTATUS PostFlt_NtXXX(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	PAGED_CODE();

	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtXXX!!! Why am I here??\r\n"));
	return RP_STATUS_OK;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT
//

RPSTATUS PostFlt_NtOpenFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PHANDLE FileHandle = (PHANDLE)pFltContext->ulpXxx1;
		ACCESS_MASK DesiredAccess = (ACCESS_MASK)pFltContext->ulpXxx2;
		POBJECT_ATTRIBUTES ObjectAttributes = (POBJECT_ATTRIBUTES)pFltContext->ulpXxx3;
		ULONG OpenOptions = (ULONG)pFltContext->ulpXxx6;

		if (OpenOptions & FILE_DIRECTORY_FILE)
			return RpStatus;

		if (!(DesiredAccess & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
			return RpStatus;

		MyProbeForRead(FileHandle, sizeof(HANDLE), 1, pHookObj->ulFltType);
		MyProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1, pHookObj->ulFltType);
		MyProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1, pHookObj->ulFltType);
		MyProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1, pHookObj->ulFltType);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								ObjectAttributes->ObjectName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								0
							);
		if (RpStatus == RP_STATUS_ERR) {
			ZwClose(*FileHandle);
			*FileHandle = (HANDLE)INVALID_HANDLE_VALUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtOpenFile!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}





RPSTATUS PostFlt_NtOpenThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PHANDLE ThreadHandle = (PHANDLE)pFltContext->ulpXxx1;
		NTSTATUS NtStatus;
		PETHREAD pTarEthread;
		PEPROCESS pTarEproc;

		MyProbeForRead(ThreadHandle, sizeof(HANDLE), 1, pHookObj->ulFltType);

		NtStatus = ObReferenceObjectByHandle(*ThreadHandle, 0, NULL, KernelMode, &pTarEthread, NULL);
		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pTarEthread);

		pTarEproc = PsGetThreadProcess(pTarEthread);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);
		pusTarProcName = GetProcNameByEproc(pTarEproc);
		RpStatus = EventCheck(	pusCurProcName,
								pusTarProcName,
								pCurEproc,
								pTarEproc,
								pHookObj->ulCrimeType,
								0
							);

		if (RpStatus == RP_STATUS_ERR) {
			ZwClose(*ThreadHandle);
			*ThreadHandle = NULL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtOpenThread!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PostFlt_NtOpenProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PHANDLE  ProcessHandle = (PHANDLE)pFltContext->ulpXxx1;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;


		MyProbeForRead(ProcessHandle, sizeof(HANDLE), 1, pHookObj->ulFltType);

		NtStatus = ObReferenceObjectByHandle(*ProcessHandle, 0, NULL, KernelMode, &pTarEproc, NULL);
		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pTarEproc);
		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);
		pusTarProcName = GetProcNameByEproc(pTarEproc);

		RpStatus = EventCheck(	pusCurProcName,
								pusTarProcName,
								pCurEproc,
								pTarEproc,
								pHookObj->ulCrimeType,
								0
							);

		if (RpStatus == RP_STATUS_ERR) {
			ZwClose(*ProcessHandle);
			*ProcessHandle = NULL;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtOpenProcess!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PostFlt_NtOpenSection(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PHANDLE	SectionHandle = (PHANDLE)pFltContext->ulpXxx1;

		PVOID pSecObj;
		NTSTATUS NtStatus;

		MyProbeForRead(SectionHandle, sizeof(HANDLE), 1, pHookObj->ulFltType);


		NtStatus = ObReferenceObjectByHandle(*SectionHandle, 0, NULL, KernelMode, &pSecObj, NULL);

		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pSecObj);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								NULL,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								(ULONG_PTR)pSecObj
							);

		if (RpStatus == RP_STATUS_ERR) {
			ZwClose(*SectionHandle);
			*SectionHandle = NULL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtOpenSection!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}





RPSTATUS PostFlt_NtReadVirtualMemory(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ProcessHandle = (HANDLE)pFltContext->ulpXxx1;
		PVOID BaseAddress = (PVOID)pFltContext->ulpXxx2;
		PVOID Buffer = (PVOID)pFltContext->ulpXxx3;
		PULONG ReturnLength = (PULONG)pFltContext->ulpXxx5;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;
		HANDLE TarPid;
		ULONG ulReturnLength;

		MyProbeForRead(ReturnLength, sizeof(ULONG), 1, pHookObj->ulFltType);
		ulReturnLength = *ReturnLength;

		MyProbeForWrite(Buffer, ulReturnLength, 1, pHookObj->ulFltType);

		NtStatus = ObReferenceObjectByHandle(ProcessHandle, 0, NULL, KernelMode, &pTarEproc, NULL);
		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pTarEproc);

		TarPid = PsGetProcessId(pTarEproc);

		if (GetHandleCountOfProcess(TarPid)) {
			pCurEproc = PsGetCurrentProcess();
			pusCurProcName = GetProcNameByEproc(pCurEproc);
			pusTarProcName = GetProcNameByEproc(pTarEproc);

			RpStatus = EventCheck(	pusCurProcName,
									pusTarProcName,
									pCurEproc,
									pTarEproc,
									pHookObj->ulCrimeType,
									(ULONG_PTR)BaseAddress
								);


			if (RpStatus == RP_STATUS_ERR) {
				memset(Buffer, 0, ulReturnLength);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtReadVirtualMemory!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PostFlt_NtDuplicateObject(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE SourceProcessHandle = (HANDLE)pFltContext->ulpXxx1;
		HANDLE TargetProcessHandle = (HANDLE)pFltContext->ulpXxx3;
		PHANDLE TargetHandle = (PHANDLE)pFltContext->ulpXxx4;


		NTSTATUS NtStatus;
		PEPROCESS pSrcEproc;
		PEPROCESS pDstEproc;
		PEPROCESS pCurEproc;
		KAPC_STATE ApcState;
		PVOID pObj;

		MyProbeForRead(TargetHandle, sizeof(HANDLE), 1, pHookObj->ulFltType);

		NtStatus = ObReferenceObjectByHandle(TargetProcessHandle, 0, NULL, KernelMode, &pDstEproc, NULL);

		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pDstEproc);

		pCurEproc = PsGetCurrentProcess();

		if (pDstEproc != pCurEproc) {
			HANDLE hTarget = *TargetHandle;				// may be optimized to BSOD
			KeStackAttachProcess(pDstEproc, &ApcState);
			NtStatus = ObReferenceObjectByHandle(hTarget, 0, NULL, KernelMode, &pObj, NULL);
			KeUnstackDetachProcess(&ApcState);
		} else {
			NtStatus = ObReferenceObjectByHandle(*TargetHandle, 0, NULL, KernelMode, &pObj, NULL);
		}

		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pObj);


		NtStatus = ObReferenceObjectByHandle(SourceProcessHandle, 0, NULL, KernelMode, &pSrcEproc, NULL);

		if (!NT_SUCCESS(NtStatus))
			pSrcEproc = pCurEproc;
		else
			ObDereferenceObject(pSrcEproc);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);
		pusTarProcName = GetProcNameByEproc(pSrcEproc);

		RpStatus = EventCheck(	pusCurProcName,
								pusTarProcName,
								pCurEproc,
								pSrcEproc,
								pHookObj->ulCrimeType,
								(ULONG_PTR)pObj
							);

		if (RpStatus == RP_STATUS_ERR) {
			ZwClose(*TargetHandle);
			*TargetHandle = NULL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtDuplicateObject!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT Shadow
//
