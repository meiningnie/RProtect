#ifndef _FAKE_SYSCALLS_H_
#define _FAKE_SYSCALLS_H_

/////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT
//

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
	);


NTSTATUS
NTAPI
Fake_NtOpenFile (
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);


NTSTATUS
NTAPI
Fake_NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);


NTSTATUS
NTAPI
Fake_NtSetInformationFile(
	IN HANDLE  FileHandle,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PVOID  FileInformation,
	IN ULONG  ulLength,
	IN FILE_INFORMATION_CLASS  FileInformationClass
	);


NTSTATUS
NTAPI
Fake_NtLoadDriver(
	IN PUNICODE_STRING  DriverServiceName
	);


NTSTATUS
NTAPI
Fake_NtUnloadDriver(
	IN PUNICODE_STRING  DriverServiceName
	);


NTSTATUS
NTAPI
Fake_NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength
	);



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
	);


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
	IN PVOID Parameter9,
	IN PVOID AttributeList
	);

NTSTATUS
NTAPI
Fake_NtOpenSection(
	OUT PHANDLE  SectionHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes
	);



NTSTATUS
NTAPI
Fake_NtCreateSymbolicLinkObject(
	OUT PHANDLE SymbolicLinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING TargetName
	);



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
	);


NTSTATUS
NTAPI
Fake_NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId
	);


NTSTATUS
NTAPI
Fake_NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);

NTSTATUS
NTAPI
Fake_NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);



NTSTATUS
NTAPI
Fake_NtSuspendProcess(
	IN HANDLE Process
	);


NTSTATUS
NTAPI
Fake_NtGetContextThread(
	IN HANDLE ThreadHandle,
	OUT PCONTEXT Context
	);


NTSTATUS
NTAPI
Fake_NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context
	);


NTSTATUS
NTAPI
Fake_NtTerminateProcess(
	IN HANDLE  ProcessHandle,
	IN NTSTATUS  ExitStatus
	);


NTSTATUS
NTAPI
Fake_NtTerminateThread(
	IN HANDLE ThreadHandle OPTIONAL,
	IN NTSTATUS ExitStatus
	);


NTSTATUS
NTAPI
Fake_NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle
	);


NTSTATUS
NTAPI
Fake_NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);


NTSTATUS
NTAPI
Fake_NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);


NTSTATUS
NTAPI
Fake_NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG ProtectSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
	);


NTSTATUS
NTAPI
Fake_NtSystemDebugControl(
	IN ULONG ControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);



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
	);

/////////////////////////////////////////////////////////////////////////////////////////////////
//
//	SSDT Shadow
//

ULONG
NTAPI
Fake_NtUserSetWindowsHookEx(
 	HANDLE hMod,
	PUNICODE_STRING ModuleName,
	HANDLE ThreadId,
	ULONG HookId,
	PVOID HookProc,
	ULONG dwFlags
	);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Fake_NtCreateFile)
#pragma alloc_text(PAGE, Fake_NtOpenFile)
#pragma alloc_text(PAGE, Fake_NtDeleteFile)
#pragma alloc_text(PAGE, Fake_NtSetInformationFile)
#pragma alloc_text(PAGE, Fake_NtLoadDriver)
#pragma alloc_text(PAGE, Fake_NtUnloadDriver)
#pragma alloc_text(PAGE, Fake_NtSetSystemInformation)
//#pragma alloc_text(PAGE, Fake_NtCreateSection)
#pragma alloc_text(PAGE, Fake_NtCreateUserProcess)
#pragma alloc_text(PAGE, Fake_NtOpenSection)
#pragma alloc_text(PAGE, Fake_NtCreateSymbolicLinkObject)
#pragma alloc_text(PAGE, Fake_NtCreateThread)
#pragma alloc_text(PAGE, Fake_NtOpenThread)
#pragma alloc_text(PAGE, Fake_NtOpenProcess)
#pragma alloc_text(PAGE, Fake_NtSuspendThread)
#pragma alloc_text(PAGE, Fake_NtSuspendProcess)
#pragma alloc_text(PAGE, Fake_NtGetContextThread)
#pragma alloc_text(PAGE, Fake_NtSetContextThread)
#pragma alloc_text(PAGE, Fake_NtTerminateProcess)
#pragma alloc_text(PAGE, Fake_NtTerminateThread)
#pragma alloc_text(PAGE, Fake_NtAssignProcessToJobObject)
#pragma alloc_text(PAGE, Fake_NtReadVirtualMemory)
#pragma alloc_text(PAGE, Fake_NtWriteVirtualMemory)
#pragma alloc_text(PAGE, Fake_NtProtectVirtualMemory)
#pragma alloc_text(PAGE, Fake_NtSystemDebugControl)
#pragma alloc_text(PAGE, Fake_NtDuplicateObject)
#pragma alloc_text(PAGE, Fake_NtUserSetWindowsHookEx)
#endif


#endif
