/*++

Module Name:

	SysCallFlt_Pre.c - Pre Filter模块

Abstract:

	该模块负责对系统调用进行事前处理

Author:

	Fypher

	2012/02/27

--*/
#include <ntifs.h>
#include "Common.h"
#include "Hook.h"
#include "SysCallFlt.h"
#include "EventHandler.h"



RPSTATUS PreFlt_NtXXX(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	PAGED_CODE();

	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtXXX!!! Why am I here??\r\n"));
	return RP_STATUS_OK;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT
//

RPSTATUS PreFlt_NtCreateFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		ACCESS_MASK DesiredAccess = (ACCESS_MASK)pFltContext->ulXxx2;
		POBJECT_ATTRIBUTES ObjectAttributes = (POBJECT_ATTRIBUTES)pFltContext->ulXxx3;
		ULONG CreateDisposition = (ULONG)pFltContext->ulXxx8;
		ULONG CreateOptions = (ULONG)pFltContext->ulXxx9;

		if (CreateOptions & FILE_DIRECTORY_FILE)
			return RpStatus;

		if (!(CreateDisposition & (FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF)) &&
			!(DesiredAccess & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA))
			)
			return RpStatus;

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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PostFlt_NtCreateFile!!! %wZ\r\n", pusCurProcName));
	}
#endif

	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtDeleteFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		POBJECT_ATTRIBUTES ObjectAttributes = (POBJECT_ATTRIBUTES)pFltContext->ulXxx1;

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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtDeleteFile!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PreFlt_NtSetInformationFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE FileHandle = (HANDLE)pFltContext->ulXxx1;
		FILE_INFORMATION_CLASS FileInformationClass = (FILE_INFORMATION_CLASS)pFltContext->ulXxx5;

		NTSTATUS NtStatus;
		PFILE_OBJECT pFileObj;

		NtStatus = ObReferenceObjectByHandle(FileHandle, 0, NULL, KernelMode, &pFileObj, NULL);
		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pFileObj);

		if (FileInformationClass == FileLinkInformation		||
			FileInformationClass == FileRenameInformation	||
			FileInformationClass == FileShortNameInformation	)
		{
			pCurEproc = PsGetCurrentProcess();
			pusCurProcName = GetProcNameByEproc(pCurEproc);

			RpStatus = EventCheck(	pusCurProcName,
									&pFileObj->FileName,
									pCurEproc,
									NULL,
									pHookObj->ulCrimeType,
									FileInformationClass
								);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSetInformationFile!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}
/*
RPSTATUS PreFlt_NtSetInformationFile(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PVOID FileInformation = (PVOID)pFltContext->ulXxx3;
		ULONG ulLength = (ULONG)pFltContext->ulXxx4;
		FILE_INFORMATION_CLASS FileInformationClass = (FILE_INFORMATION_CLASS)pFltContext->ulXxx5;

		MyProbeForRead(FileInformation, ulLength, 1, pHookObj->ulFltType);

		switch (FileInformationClass) {
			case FileLinkInformation:
			{
				PFILE_LINK_INFORMATION pFileLinkInfo = (PFILE_LINK_INFORMATION)FileInformation;
				MyProbeForRead(pFileLinkInfo->FileName, pFileLinkInfo->FileNameLength, 1, pHookObj->ulFltType);

				if (pFileLinkInfo->FileNameLength) {
					UNICODE_STRING usFileLink;
					PUNICODE_STRING pusTmp;
					PWSTR pTmp = (PWSTR)ExAllocatePoolWithTag(PagedPool,
										pFileLinkInfo->FileNameLength, ALLOC_TAG);
					if (pTmp) {
						RtlCopyMemory(pTmp, pFileLinkInfo->FileName, pFileLinkInfo->FileNameLength);
						usFileLink.Length = usFileLink.MaximumLength = (USHORT)pFileLinkInfo->FileNameLength;
						usFileLink.Buffer = pTmp;
						pusTmp = &usFileLink;

						pCurEproc = PsGetCurrentProcess();
						pusCurProcName = GetProcNameByEproc(pCurEproc);

						RpStatus = EventCheck(	pusCurProcName,
												pusTmp,
												pCurEproc,
												NULL,
												pHookObj->ulCrimeType,
												FileLinkInformation
											);
						ExFreePool(pTmp);
					}
				}
				break;
			}
			case FileRenameInformation:
			{
				PFILE_RENAME_INFORMATION pFileRenameInfo = (PFILE_RENAME_INFORMATION)FileInformation;
				MyProbeForRead(pFileRenameInfo->FileName, pFileRenameInfo->FileNameLength, 1, pHookObj->ulFltType);
				if (pFileRenameInfo->FileNameLength) {
					UNICODE_STRING usFileRename;
					PUNICODE_STRING pusTmp;
					PWSTR pTmp = (PWSTR)ExAllocatePoolWithTag(PagedPool,
										pFileRenameInfo->FileNameLength, ALLOC_TAG);
					if (pTmp) {
						RtlCopyMemory(pTmp, pFileRenameInfo->FileName, pFileRenameInfo->FileNameLength);
						usFileRename.Length = usFileRename.MaximumLength = (USHORT)pFileRenameInfo->FileNameLength;
						usFileRename.Buffer = pTmp;
						pusTmp = &usFileRename;

						pCurEproc = PsGetCurrentProcess();
						pusCurProcName = GetProcNameByEproc(pCurEproc);

						RpStatus = EventCheck(	pusCurProcName,
												pusTmp,
												pCurEproc,
												NULL,
												pHookObj->ulCrimeType,
												FileRenameInformation
											);

						ExFreePool(pTmp);
					}
				}
				break;
			}
			case FileShortNameInformation:
			{
				PFILE_NAME_INFORMATION pFileNameInfo = (PFILE_NAME_INFORMATION)FileInformation;
				MyProbeForRead(pFileNameInfo->FileName, pFileNameInfo->FileNameLength, 1, pHookObj->ulFltType);
				if (pFileNameInfo->FileNameLength) {
					UNICODE_STRING usFileName;
					PUNICODE_STRING pusTmp;
					PWSTR pTmp = (PWSTR)ExAllocatePoolWithTag(PagedPool,
										pFileNameInfo->FileNameLength, ALLOC_TAG);
					if (pTmp) {
						RtlCopyMemory(pTmp, pFileNameInfo->FileName, pFileNameInfo->FileNameLength);
						usFileName.Length = usFileName.MaximumLength = (USHORT)pFileNameInfo->FileNameLength;
						usFileName.Buffer = pTmp;
						pusTmp = &usFileName;

						pCurEproc = PsGetCurrentProcess();
						pusCurProcName = GetProcNameByEproc(pCurEproc);

						RpStatus = EventCheck(	pusCurProcName,
												pusTmp,
												pCurEproc,
												NULL,
												pHookObj->ulCrimeType,
												FileShortNameInformation
											);

						ExFreePool(pTmp);
					}
				}
				break;
			}
			default:
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSetInformationFile!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}
*/


RPSTATUS PreFlt_NtLoadDriver(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PUNICODE_STRING DriverServiceName = (PUNICODE_STRING)pFltContext->ulXxx1;

		MyProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), 1, pHookObj->ulFltType);
		MyProbeForRead(DriverServiceName->Buffer, DriverServiceName->Length, 1, pHookObj->ulFltType);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								DriverServiceName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								0
							);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtLoadDriver!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PreFlt_NtUnloadDriver(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PUNICODE_STRING DriverServiceName = (PUNICODE_STRING)pFltContext->ulXxx1;

		MyProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), 1, pHookObj->ulFltType);
		MyProbeForRead(DriverServiceName->Buffer, DriverServiceName->Length, 1, pHookObj->ulFltType);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								DriverServiceName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								0
							);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtUnloadDriver!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtSetSystemInformation(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		SYSTEM_INFORMATION_CLASS SystemInformationClass = (SYSTEM_INFORMATION_CLASS)pFltContext->ulXxx1;
		PVOID SystemInformation = (PVOID)pFltContext->ulXxx2;
		ULONG SystemInformationLength = (ULONG)pFltContext->ulXxx3;

		MyProbeForRead(SystemInformation, SystemInformationLength, 1, pHookObj->ulFltType);

		switch (SystemInformationClass) {
			case SystemLoadAndCallImage:
			{
				PUNICODE_STRING pusImageName = (PUNICODE_STRING)SystemInformation;
				MyProbeForRead(pusImageName->Buffer, pusImageName->Length, 1, pHookObj->ulFltType);

				pCurEproc = PsGetCurrentProcess();
				pusCurProcName = GetProcNameByEproc(pCurEproc);

				RpStatus = EventCheck(	pusCurProcName,
										pusImageName,
										pCurEproc,
										NULL,
										pHookObj->ulCrimeType,
										0
									);


				break;
			}
			default:
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSetSystemInformation!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PreFlt_NtCreateSection(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		ACCESS_MASK DesiredAccess = (ACCESS_MASK)pFltContext->ulXxx2;
		ULONG SectionPageProtection = (ULONG)pFltContext->ulXxx5;
		ULONG AllocationAttributes = (ULONG)pFltContext->ulXxx6;
		HANDLE FileHandle = (HANDLE)pFltContext->ulXxx7;

		NTSTATUS NtStatus;
		PFILE_OBJECT pFileObj;

		if (!FileHandle									||
			!(DesiredAccess & STANDARD_RIGHTS_REQUIRED)	||	// 0x000f001f
			!(SectionPageProtection & PAGE_EXECUTE)		||	// 0x10
			!(AllocationAttributes & SEC_IMAGE)			)	// 0x01000000
		{
			return RpStatus;
		}

		NtStatus = ObReferenceObjectByHandle(FileHandle, 0, NULL, KernelMode, &pFileObj, NULL);
		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pFileObj);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								&pFileObj->FileName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								0
							);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtCreateSection!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}


RPSTATUS PreFlt_NtCreateUserProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters = (PRTL_USER_PROCESS_PARAMETERS)pFltContext->ulXxx9;

		MyProbeForRead(ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS), 1, pHookObj->ulFltType);
		MyProbeForRead(ProcessParameters->ImagePathName.Buffer, ProcessParameters->ImagePathName.Length, 1, pHookObj->ulFltType);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								&ProcessParameters->ImagePathName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								0
							);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtCreateSection!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}


RPSTATUS PreFlt_NtCreateSymbolicLinkObject(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		PUNICODE_STRING TargetName = (PUNICODE_STRING)pFltContext->ulXxx4;

		MyProbeForRead(TargetName, sizeof(UNICODE_STRING), 1, pHookObj->ulFltType);
		MyProbeForRead(TargetName->Buffer, TargetName->Length, 1, pHookObj->ulFltType);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								TargetName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								0
							);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtCreateSymbolicLinkObject!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PreFlt_NtCreateThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ProcessHandle = (HANDLE)pFltContext->ulXxx4;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;
		HANDLE TarPid;

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
									0
								);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtCreateThread!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtSuspendProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE Process = (HANDLE)pFltContext->ulXxx1;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;



		NtStatus = ObReferenceObjectByHandle(Process, 0, NULL, KernelMode, &pTarEproc, NULL);
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSuspendProcess!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PreFlt_NtSuspendThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ThreadHandle = (HANDLE)pFltContext->ulXxx1;

		NTSTATUS NtStatus;
		PETHREAD pEthread;
		PEPROCESS pTarEproc;


		NtStatus = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &pEthread, NULL);
		if (!NT_SUCCESS(NtStatus))
			return RpStatus;

		ObDereferenceObject(pEthread);
		pTarEproc = PsGetThreadProcess(pEthread);

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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSuspendThread!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtGetContextThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ThreadHandle = (HANDLE)pFltContext->ulXxx1;

		NTSTATUS NtStatus;
		PETHREAD pTarEthread;
		PEPROCESS pTarEproc;


		NtStatus = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &pTarEthread, NULL);
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtGetContextThread!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}



RPSTATUS PreFlt_NtSetContextThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ThreadHandle = (HANDLE)pFltContext->ulXxx1;

		NTSTATUS NtStatus;
		PETHREAD pTarEthread;
		PEPROCESS pTarEproc;

		NtStatus = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &pTarEthread, NULL);
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSetContextThread!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtTerminateProcess(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE  ProcessHandle = (HANDLE)pFltContext->ulXxx1;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;

		NtStatus = ObReferenceObjectByHandle(ProcessHandle, 0, NULL, KernelMode, &pTarEproc, NULL);
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtTerminateProcess!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtTerminateThread(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ThreadHandle = (HANDLE)pFltContext->ulXxx1;

		NTSTATUS NtStatus;
		PETHREAD pTarEthread;
		PEPROCESS pTarEproc;

		NtStatus = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &pTarEthread, NULL);
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtTerminateThread!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtAssignProcessToJobObject(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ProcessHandle = (HANDLE)pFltContext->ulXxx2;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;

		NtStatus = ObReferenceObjectByHandle(ProcessHandle, 0, NULL, KernelMode, &pTarEproc, NULL);
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
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtAssignProcessToJobObject!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




RPSTATUS PreFlt_NtWriteVirtualMemory(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ProcessHandle = (HANDLE)pFltContext->ulXxx1;
		PVOID BaseAddress = (PVOID)pFltContext->ulXxx2;
		ULONG BufferLength = (ULONG)pFltContext->ulXxx4;

		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;
		HANDLE TarPid;

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
									(ULONG)BaseAddress
								);

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtWriteVirtualMemory!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}





RPSTATUS PreFlt_NtProtectVirtualMemory(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		HANDLE ProcessHandle = (HANDLE)pFltContext->ulXxx1;
		PVOID * BaseAddress = (PVOID *)pFltContext->ulXxx2;
		ULONG NewProtect = (ULONG)pFltContext->ulXxx4;

		PVOID pBaseAddr;
		NTSTATUS NtStatus;
		PEPROCESS pTarEproc;
		HANDLE TarPid;

		MyProbeForRead(BaseAddress, sizeof(PVOID), 1, pHookObj->ulFltType);
		pBaseAddr = *BaseAddress;

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
									(ULONG)pBaseAddr
								);

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtProtectVirtualMemory!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}





RPSTATUS PreFlt_NtSystemDebugControl(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		ULONG ControlCode = (ULONG)pFltContext->ulXxx1;
		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								NULL,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								(ULONG)ControlCode
							);


	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtSystemDebugControl!!! %wZ\r\n", pusCurProcName));
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

RPSTATUS PreFlt_NtUserSetWindowsHookEx(PFLT_CONTEXT pFltContext, PHOOK_OBJECT pHookObj)
{
	RPSTATUS RpStatus = RP_STATUS_OK;
	PEPROCESS pCurEproc;
	PUNICODE_STRING pusCurProcName = NULL;
	PUNICODE_STRING pusTarProcName = NULL;

	PAGED_CODE();

	__try
	{
		ULONG ulMod = (ULONG)pFltContext->ulXxx1;
		PUNICODE_STRING ModuleName = (PUNICODE_STRING)pFltContext->ulXxx2;
		ULONG ThreadId = (ULONG)pFltContext->ulXxx3;
		ULONG HookId = (ULONG)pFltContext->ulXxx4;
		ULONG HookProc = (ULONG)pFltContext->ulXxx5;

		// hook self
		if (!ulMod)
			return RpStatus;

		if (ThreadId)	// not global hook
		{

			NTSTATUS NtStatus;
			PETHREAD pEthread;

			NtStatus = PsLookupThreadByThreadId((HANDLE)ThreadId, &pEthread);
			if (!NT_SUCCESS(NtStatus))
				return RpStatus;

			ObDereferenceObject(pEthread);

			if (PsGetThreadProcess(pEthread) == PsGetCurrentProcess())		// also hook self
				return RpStatus;
		}

		MyProbeForRead(ModuleName, sizeof(UNICODE_STRING), 1, pHookObj->ulFltType);
		MyProbeForRead(ModuleName->Buffer, ModuleName->Length, 1, pHookObj->ulFltType);

		pCurEproc = PsGetCurrentProcess();
		pusCurProcName = GetProcNameByEproc(pCurEproc);

		RpStatus = EventCheck(	pusCurProcName,
								ModuleName,
								pCurEproc,
								NULL,
								pHookObj->ulCrimeType,
								HookProc
							);

		RpStatus = RP_STATUS_ERR;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#ifdef DBG
	if (RpStatus != RP_STATUS_OK) {
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PreFlt_NtUserSetWindowsHookEx!!! %wZ\r\n", pusCurProcName));
	}
#endif
	if (pusCurProcName)
		ExFreePool(pusCurProcName);
	if (pusTarProcName)
		ExFreePool(pusTarProcName);

	return RpStatus;
}




