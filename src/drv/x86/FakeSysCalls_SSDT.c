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
	FltContext.ulXxx1 = (ULONG)FileHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)IoStatusBlock;
	FltContext.ulXxx5 = (ULONG)AllocationSize;
	FltContext.ulXxx6 = (ULONG)FileAttributes;
	FltContext.ulXxx7 = (ULONG)ShareAccess;
	FltContext.ulXxx8 = (ULONG)CreateDisposition;
	FltContext.ulXxx9 = (ULONG)CreateOptions;
	FltContext.ulXxx10 = (ULONG)EaBuffer;
	FltContext.ulXxx11 = (ULONG)EaLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_11)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6,
					FltContext.ulXxx7, FltContext.ulXxx8, FltContext.ulXxx9, FltContext.ulXxx10, FltContext.ulXxx11);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)FileHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)IoStatusBlock;
	FltContext.ulXxx5 = (ULONG)ShareAccess;
	FltContext.ulXxx6 = (ULONG)OpenOptions;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_6)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ObjectAttributes;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulOrigSysCall)(FltContext.ulXxx1);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)FileHandle;
	FltContext.ulXxx2 = (ULONG)IoStatusBlock;
	FltContext.ulXxx3 = (ULONG)FileInformation;
	FltContext.ulXxx4 = (ULONG)ulLength;
	FltContext.ulXxx5 = (ULONG)FileInformationClass;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)DriverServiceName;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulOrigSysCall)(FltContext.ulXxx1);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)DriverServiceName;


	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulOrigSysCall)(FltContext.ulXxx1);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)SystemInformationClass;
	FltContext.ulXxx2 = (ULONG)SystemInformation;
	FltContext.ulXxx3 = (ULONG)SystemInformationLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_3)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2, FltContext.ulXxx3);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)SectionHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)MaximumSize;
	FltContext.ulXxx5 = (ULONG)SectionPageProtection;
	FltContext.ulXxx6 = (ULONG)AllocationAttributes;
	FltContext.ulXxx7 = (ULONG)FileHandle;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_7)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2, FltContext.ulXxx3,
					FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6, FltContext.ulXxx7);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ProcessHandle;
	FltContext.ulXxx2 = (ULONG)ThreadHandle;
	FltContext.ulXxx3 = (ULONG)ProcessDesiredAccess;
	FltContext.ulXxx4 = (ULONG)ThreadDesiredAccess;
	FltContext.ulXxx5 = (ULONG)ProcessObjectAttributes;
	FltContext.ulXxx6 = (ULONG)ThreadObjectAttributes;
	FltContext.ulXxx7 = (ULONG)CreateProcessFlags;
	FltContext.ulXxx8 = (ULONG)CreateThreadFlags;
	FltContext.ulXxx9 = (ULONG)ProcessParameters;
	FltContext.ulXxx10 = (ULONG)pUnknown;
	FltContext.ulXxx11 = (ULONG)AttributeList;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_11)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2, FltContext.ulXxx3,
					FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6, FltContext.ulXxx7,
					FltContext.ulXxx8, FltContext.ulXxx9, FltContext.ulXxx10, FltContext.ulXxx11);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)SectionHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_3)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2, FltContext.ulXxx3);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)SymbolicLinkHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)TargetName;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_4)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ThreadHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)ProcessHandle;
	FltContext.ulXxx5 = (ULONG)ClientId;
	FltContext.ulXxx6 = (ULONG)ThreadContext;
	FltContext.ulXxx7 = (ULONG)UserStack;
	FltContext.ulXxx8 = (ULONG)CreateSuspended;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_8)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2, FltContext.ulXxx3,
					FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6, FltContext.ulXxx7, FltContext.ulXxx8);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ThreadHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)ClientId;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_4)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4);

		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ProcessHandle;
	FltContext.ulXxx2 = (ULONG)DesiredAccess;
	FltContext.ulXxx3 = (ULONG)ObjectAttributes;
	FltContext.ulXxx4 = (ULONG)ClientId;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_4)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ThreadHandle;
	FltContext.ulXxx2 = (ULONG)PreviousSuspendCount;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)Process;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_1)pHookObject->ulOrigSysCall)(FltContext.ulXxx1);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ThreadHandle;
	FltContext.ulXxx2 = (ULONG)Context;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ThreadHandle;
	FltContext.ulXxx2 = (ULONG)Context;


	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ProcessHandle;
	FltContext.ulXxx2 = (ULONG)ExitStatus;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ThreadHandle;
	FltContext.ulXxx2 = (ULONG)ExitStatus;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)JobHandle;
	FltContext.ulXxx2 = (ULONG)ProcessHandle;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_2)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ProcessHandle;
	FltContext.ulXxx2 = (ULONG)BaseAddress;
	FltContext.ulXxx3 = (ULONG)Buffer;
	FltContext.ulXxx4 = (ULONG)BufferLength;
	FltContext.ulXxx5 = (ULONG)ReturnLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ProcessHandle;
	FltContext.ulXxx2 = (ULONG)BaseAddress;
	FltContext.ulXxx3 = (ULONG)Buffer;
	FltContext.ulXxx4 = (ULONG)BufferLength;
	FltContext.ulXxx5 = (ULONG)ReturnLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ProcessHandle;
	FltContext.ulXxx2 = (ULONG)BaseAddress;
	FltContext.ulXxx3 = (ULONG)ProtectSize;
	FltContext.ulXxx4 = (ULONG)NewProtect;
	FltContext.ulXxx5 = (ULONG)OldProtect;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_5)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)ControlCode;
	FltContext.ulXxx2 = (ULONG)InputBuffer;
	FltContext.ulXxx3 = (ULONG)InputBufferLength;
	FltContext.ulXxx4 = (ULONG)OutputBuffer;
	FltContext.ulXxx5 = (ULONG)OutputBufferLength;
	FltContext.ulXxx6 = (ULONG)ReturnLength;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_6)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2,
					FltContext.ulXxx3, FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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
	FltContext.ulXxx1 = (ULONG)SourceProcessHandle;
	FltContext.ulXxx2 = (ULONG)SourceHandle;
	FltContext.ulXxx3 = (ULONG)TargetProcessHandle;
	FltContext.ulXxx4 = (ULONG)TargetHandle;
	FltContext.ulXxx5 = (ULONG)DesiredAccess;
	FltContext.ulXxx6 = (ULONG)Attributes;
	FltContext.ulXxx7 = (ULONG)Options;

	if (pHookObject->ulFltType & FLT_TYPE_PRE)	// prehook
	{
		// +++
		RpStatus = ((F_FLT)pHookObject->ulPreFilter)(&FltContext, pHookObject);
		// ---
	}

	if (RpStatus == RP_STATUS_OK)
	{
		NtStatus = ((F_7)pHookObject->ulOrigSysCall)(FltContext.ulXxx1, FltContext.ulXxx2, FltContext.ulXxx3,
					FltContext.ulXxx4, FltContext.ulXxx5, FltContext.ulXxx6, FltContext.ulXxx7);


		// post hook
		if (NT_SUCCESS(NtStatus) && (pHookObject->ulFltType & FLT_TYPE_POST))
		{
			// +++
			RpStatus = ((F_FLT)pHookObject->ulPostFilter)(&FltContext, pHookObject);
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



