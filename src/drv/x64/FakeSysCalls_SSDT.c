/*++

Module Name:

	FakeSysCalls_SSDT.c - SSDT DetourÄ£¿é


Author:

	Fypher

	2012/02/27

--*/
#include <ntddk.h>
#include "Common.h"
#include "Hook.h"
#include "FakeSysCalls.h"
#include "SysCallFlt.h"



NTSTATUS
NTAPI
Fake_NtCreateFile (
	OUT PHANDLE  FileHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER  AllocationSize  OPTIONAL,
	IN ULONG  FileAttributes,
	IN ULONG  ShareAccess,
	IN ULONG  CreateDisposition,
	IN ULONG  CreateOptions,
	IN PVOID  EaBuffer  OPTIONAL,
	IN ULONG  EaLength
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtCreateFile;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 11;
	FltContext.ulpXxx1 = (ULONG_PTR)FileHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)IoStatusBlock;
	FltContext.ulpXxx5 = (ULONG_PTR)AllocationSize;
	FltContext.ulpXxx6 = (ULONG_PTR)FileAttributes;
	FltContext.ulpXxx7 = (ULONG_PTR)ShareAccess;
	FltContext.ulpXxx8 = (ULONG_PTR)CreateDisposition;
	FltContext.ulpXxx9 = (ULONG_PTR)CreateOptions;
	FltContext.ulpXxx10 = (ULONG_PTR)EaBuffer;
	FltContext.ulpXxx11 = (ULONG_PTR)EaLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_11)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6,
					FltContext.ulpXxx7, FltContext.ulpXxx8, FltContext.ulpXxx9, FltContext.ulpXxx10, FltContext.ulpXxx11);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}


NTSTATUS
NTAPI
Fake_NtOpenFile (
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtOpenFile;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 6;
	FltContext.ulpXxx1 = (ULONG_PTR)FileHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)IoStatusBlock;
	FltContext.ulpXxx5 = (ULONG_PTR)ShareAccess;
	FltContext.ulpXxx6 = (ULONG_PTR)OpenOptions;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_6)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtDeleteFile;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 1;
	FltContext.ulpXxx1 = (ULONG_PTR)ObjectAttributes;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG ulLength,
	IN FILE_INFORMATION_CLASS FileInformationClass
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtSetInformationFile;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 5;
	FltContext.ulpXxx1 = (ULONG_PTR)FileHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)IoStatusBlock;
	FltContext.ulpXxx3 = (ULONG_PTR)FileInformation;
	FltContext.ulpXxx4 = (ULONG_PTR)ulLength;
	FltContext.ulpXxx5 = (ULONG_PTR)FileInformationClass;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}


NTSTATUS
NTAPI
Fake_NtLoadDriver(
	IN PUNICODE_STRING  DriverServiceName
    )
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtLoadDriver;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 1;
	FltContext.ulpXxx1 = (ULONG_PTR)DriverServiceName;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtUnloadDriver(
	IN PUNICODE_STRING  DriverServiceName
    )
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtUnloadDriver;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 1;
	FltContext.ulpXxx1 = (ULONG_PTR)DriverServiceName;


	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtSetSystemInformation;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 3;
	FltContext.ulpXxx1 = (ULONG_PTR)SystemInformationClass;
	FltContext.ulpXxx2 = (ULONG_PTR)SystemInformation;
	FltContext.ulpXxx3 = (ULONG_PTR)SystemInformationLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_3)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2, FltContext.ulpXxx3);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}


/*
NTSTATUS
NTAPI
Fake_NtCreateSection(
	OUT PHANDLE  SectionHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER  MaximumSize OPTIONAL,
	IN ULONG  SectionPageProtection,
	IN ULONG  AllocationAttributes,
	IN HANDLE  FileHandle OPTIONAL
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtCreateSection;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 7;
	FltContext.ulpXxx1 = (ULONG_PTR)SectionHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)MaximumSize;
	FltContext.ulpXxx5 = (ULONG_PTR)SectionPageProtection;
	FltContext.ulpXxx6 = (ULONG_PTR)AllocationAttributes;
	FltContext.ulpXxx7 = (ULONG_PTR)FileHandle;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_7)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2, FltContext.ulpXxx3,
					FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6, FltContext.ulpXxx7);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}
*/

NTSTATUS
NTAPI
Fake_NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PVOID pUnknown,
	IN PVOID AttributeList
)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtCreateUserProcess;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 11;
	FltContext.ulpXxx1 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx3 = (ULONG_PTR)ProcessDesiredAccess;
	FltContext.ulpXxx4 = (ULONG_PTR)ThreadDesiredAccess;
	FltContext.ulpXxx5 = (ULONG_PTR)ProcessObjectAttributes;
	FltContext.ulpXxx6 = (ULONG_PTR)ThreadObjectAttributes;
	FltContext.ulpXxx7 = (ULONG_PTR)CreateProcessFlags;
	FltContext.ulpXxx8 = (ULONG_PTR)CreateThreadFlags;
	FltContext.ulpXxx9 = (ULONG_PTR)ProcessParameters;
	FltContext.ulpXxx10 = (ULONG_PTR)pUnknown;
	FltContext.ulpXxx11 = (ULONG_PTR)AttributeList;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_11)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2, FltContext.ulpXxx3,
					FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6, FltContext.ulpXxx7,
					FltContext.ulpXxx8, FltContext.ulpXxx9, FltContext.ulpXxx10, FltContext.ulpXxx11);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtOpenSection(
	OUT PHANDLE  SectionHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtOpenSection;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 3;
	FltContext.ulpXxx1 = (ULONG_PTR)SectionHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_3)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2, FltContext.ulpXxx3);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtCreateSymbolicLinkObject(
	OUT PHANDLE SymbolicLinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING TargetName
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtCreateSymbolicLinkObject;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	InterlockedIncrement(&pHookObject->ulUserRef);

	PAGED_CODE();

	FltContext.ulXxxCount = 4;
	FltContext.ulpXxx1 = (ULONG_PTR)SymbolicLinkHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)TargetName;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_4)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}





NTSTATUS
NTAPI
Fake_NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PULONG UserStack,
	IN BOOLEAN CreateSuspended
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtCreateThread;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 8;
	FltContext.ulpXxx1 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx5 = (ULONG_PTR)ClientId;
	FltContext.ulpXxx6 = (ULONG_PTR)ThreadContext;
	FltContext.ulpXxx7 = (ULONG_PTR)UserStack;
	FltContext.ulpXxx8 = (ULONG_PTR)CreateSuspended;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_8)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2, FltContext.ulpXxx3,
					FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6, FltContext.ulpXxx7, FltContext.ulpXxx8);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtOpenThread;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 4;
	FltContext.ulpXxx1 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)ClientId;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_4)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtOpenProcess;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 4;
	FltContext.ulpXxx1 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx3 = (ULONG_PTR)ObjectAttributes;
	FltContext.ulpXxx4 = (ULONG_PTR)ClientId;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_4)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}


NTSTATUS
NTAPI
Fake_NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtSuspendThread;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 2;
	FltContext.ulpXxx1 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)PreviousSuspendCount;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtSuspendProcess(
	IN HANDLE Process
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtSuspendProcess;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 1;
	FltContext.ulpXxx1 = (ULONG_PTR)Process;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtGetContextThread(
	IN HANDLE ThreadHandle,
	OUT PCONTEXT Context
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtGetContextThread;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 2;
	FltContext.ulpXxx1 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)Context;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtSetContextThread;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 2;
	FltContext.ulpXxx1 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)Context;


	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtTerminateProcess(
	IN HANDLE  ProcessHandle,
	IN NTSTATUS  ExitStatus
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtTerminateProcess;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	//InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 2;
	FltContext.ulpXxx1 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)ExitStatus;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	//InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtTerminateThread(
	IN HANDLE ThreadHandle OPTIONAL,
	IN NTSTATUS ExitStatus
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtTerminateThread;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	//InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 2;
	FltContext.ulpXxx1 = (ULONG_PTR)ThreadHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)ExitStatus;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	//InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtAssignProcessToJobObject;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 2;
	FltContext.ulpXxx1 = (ULONG_PTR)JobHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)ProcessHandle;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}





NTSTATUS
NTAPI
Fake_NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtReadVirtualMemory;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 5;
	FltContext.ulpXxx1 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)BaseAddress;
	FltContext.ulpXxx3 = (ULONG_PTR)Buffer;
	FltContext.ulpXxx4 = (ULONG_PTR)BufferLength;
	FltContext.ulpXxx5 = (ULONG_PTR)ReturnLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtWriteVirtualMemory;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 5;
	FltContext.ulpXxx1 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)BaseAddress;
	FltContext.ulpXxx3 = (ULONG_PTR)Buffer;
	FltContext.ulpXxx4 = (ULONG_PTR)BufferLength;
	FltContext.ulpXxx5 = (ULONG_PTR)ReturnLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG ProtectSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtProtectVirtualMemory;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 5;
	FltContext.ulpXxx1 = (ULONG_PTR)ProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)BaseAddress;
	FltContext.ulpXxx3 = (ULONG_PTR)ProtectSize;
	FltContext.ulpXxx4 = (ULONG_PTR)NewProtect;
	FltContext.ulpXxx5 = (ULONG_PTR)OldProtect;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}



NTSTATUS
NTAPI
Fake_NtSystemDebugControl(
	IN ULONG ControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtSystemDebugControl;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 6;
	FltContext.ulpXxx1 = (ULONG_PTR)ControlCode;
	FltContext.ulpXxx2 = (ULONG_PTR)InputBuffer;
	FltContext.ulpXxx3 = (ULONG_PTR)InputBufferLength;
	FltContext.ulpXxx4 = (ULONG_PTR)OutputBuffer;
	FltContext.ulpXxx5 = (ULONG_PTR)OutputBufferLength;
	FltContext.ulpXxx6 = (ULONG_PTR)ReturnLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_6)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2,
					FltContext.ulpXxx3, FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}




NTSTATUS
NTAPI
Fake_NtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG Attributes,
	IN ULONG Options
	)
{
	PHOOK_OBJECT pHookObject = &g_HookObj_NtDuplicateObject;
	FLT_CONTEXT FltContext;
	NTSTATUS NtStatus;
	RPSTATUS RpStatus = RP_STATUS_OK;

	PAGED_CODE();

	InterlockedIncrement(&pHookObject->ulUserRef);

	FltContext.ulXxxCount = 7;
	FltContext.ulpXxx1 = (ULONG_PTR)SourceProcessHandle;
	FltContext.ulpXxx2 = (ULONG_PTR)SourceHandle;
	FltContext.ulpXxx3 = (ULONG_PTR)TargetProcessHandle;
	FltContext.ulpXxx4 = (ULONG_PTR)TargetHandle;
	FltContext.ulpXxx5 = (ULONG_PTR)DesiredAccess;
	FltContext.ulpXxx6 = (ULONG_PTR)Attributes;
	FltContext.ulpXxx7 = (ULONG_PTR)Options;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulpPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_7)pHookObject->ulpOrigSysCall)(FltContext.ulpXxx1, FltContext.ulpXxx2, FltContext.ulpXxx3,
					FltContext.ulpXxx4, FltContext.ulpXxx5, FltContext.ulpXxx6, FltContext.ulpXxx7);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulpPostFilter)(&FltContext, pHookObject);
			// ---
		}
	}

	if (RpStatus != RP_STATUS_OK)
		NtStatus = STATUS_ACCESS_DENIED;

	InterlockedDecrement(&pHookObject->ulUserRef);

	return NtStatus;
}








/*
HOOK_OBJECT g_HookObj_NtCreateKey = {0};
HOOK_OBJECT g_HookObj_NtDeleteKey = {0};
HOOK_OBJECT g_HookObj_NtQueryValueKey = {0};
HOOK_OBJECT g_HookObj_NtSetValueKey = {0};
HOOK_OBJECT g_HookObj_NtDeleteValueKey = {0};
HOOK_OBJECT g_HookObj_NtEnumerateValueKey = {0};
*/
