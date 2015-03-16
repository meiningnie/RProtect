#ifndef _COMMON_H_
#define _COMMON_H_

#define RP_DBG

#define OS_VERSION_ERROR		0
#define OS_VERSION_2000			1
#define OS_VERSION_XP			2
#define OS_VERSION_SERVER_2003	3
#define OS_VERSION_VISTA		4
#define OS_VERSION_VISTA_SP1	5
#define OS_VERSION_VISTA_SP2	6
#define OS_VERSION_WIN7			7
#define OS_VERSION_WIN7_SP1		8

#define ALLOC_TAG				'rDyF'

#define DRV_NAME				L"RProtect"

typedef UCHAR BYTE;
typedef BYTE * PBYTE;

#define MAX_PATH 260


#define INVALID_HANDLE_VALUE	0xFFFFFFFF
#define SEC_IMAGE				0x1000000


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts,
	SystemConfigurationInformation,
	SystemProcessorTimes,
	SystemGlobalFlag,
	SystemNotImplemented2,
	SystemModuleInformation,
	SystemLockInformation,
	SystemNotImplemented3,
	SystemNotImplemented4,
	SystemNotImplemented5,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPagefileInformation,
	SystemInstructionEmulationCounts,
	SystemInvalidInfoClass1,
	SystemCacheInformation,
	SystemPoolTagInformation,
	SystemProcessorStatistics,
	SystemDpcInformation,
	SystemNotImplemented6,
	SystemLoadImage,
	SystemUnloadImage,
	SystemTimeAdjustment,
	SystemNotImplemented7,
	SystemNotImplemented8,
	SystemNotImplemented9,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,
	SystemPrioritySeparation,
	SystemNotImplemented10,
	SystemNotImplemented11,
	SystemInvalidInfoClass2,
	SystemInvalidInfoClass3,
	SystemTimeZoneInformation,
	SystemLookasideInformation,
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession,
	SystemInvalidInfoClass4,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
}SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS,  *PRTL_USER_PROCESS_PARAMETERS;


NTSTATUS
NTAPI
ZwQuerySystemInformation (
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);


NTSTATUS
NTAPI
ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);



NTKERNELAPI
HANDLE
PsGetThreadProcessId(
	IN PETHREAD Thread
	);


PEPROCESS
NTAPI
PsGetThreadProcess(
	IN PETHREAD Thread
	);



extern PULONG InitSafeBootMode;

extern ULONG g_ulMmUserProbeAddress;
extern ULONG g_ulOsVersion;

extern ULONG g_ulKiSystemService;

//extern ULONG g_ulKiSystemCall64;

extern ULONG g_ulKeServiceDescriptorTable;
extern ULONG g_ulKiServiceTable;
extern ULONG g_ulServiceNumber;


extern ULONG g_ulKeServiceDescriptorTableShadow;
extern ULONG g_ulW32pServiceTable;
extern ULONG g_ulShadowServiceNumber;

extern ULONG g_ulNtdllBase;
extern ULONG g_ulNtDllSize;

extern ULONG g_ulHookPoint;
extern ULONG g_ulJmpBackPoint;


extern UCHAR g_Signature[10];
//extern UCHAR g_HookCodes[17];
extern BYTE g_OriginalBytes[];


extern PVOID g_pPhysicalMemoryObj;

// hard coded
extern ULONG g_ulShadowId_NtUserSetWindowsHookEx;


// for self protect
extern PEPROCESS g_pProtected;


ULONG GetOsVersion();
BOOLEAN InitCommonVars();
BOOLEAN InitShadowServiceId();
ULONG GetKiSystemServiceAddr();
PVOID GetSectionObjectByName(IN WCHAR * wcsObjName);
PRTL_PROCESS_MODULES GetSystemModules();
PSYSTEM_PROCESS_INFORMATION GetSystemProcesses();
//HANDLE GetProcIdByName(WCHAR * wcsProcName);
//ULONG GetThreadNumOfProcess(HANDLE Pid);
ULONG GetHandleCountOfProcess(IN HANDLE Pid);
BOOLEAN GetSSDTShadow(PULONG pulSSDTShadow, PULONG pulShadowServiceNum);

BOOLEAN GetSysModInfoByName(IN char * strModName, OUT PRTL_PROCESS_MODULE_INFORMATION pSysModInfo);
ULONG MyGetProcAddress(IN ULONG ulModBase, IN CHAR * strRoutineName);
BOOLEAN IsCurrentProcRProcess();
PUNICODE_STRING GetProcNameByEproc(IN PEPROCESS pEproc);
BOOLEAN IsUniStrEndWithWcs(IN PUNICODE_STRING puniXXX, IN WCHAR* wcsSubXXX);
//BOOLEAN IsWcsEndWithWcs(PWSTR pwcsXXX, PWSTR wcsSubXXX, ULONG ulXXXLen);

VOID MyProbeForRead(IN PVOID pAddr, IN ULONG ulLen, IN ULONG ulAlignment, IN ULONG ulMemType);
VOID MyProbeForWrite(IN PVOID pAddr, IN ULONG ulLen, IN ULONG ulAlignment, IN ULONG ulMemType);
void __stdcall MyMemCpy_NoPaged(PVOID pDst, PVOID pSrc, ULONG count);

//BOOLEAN GetHash(PBYTE pBuffer, ULONG ulSize, PULONG pulHash);

typedef NTSTATUS (*F_0)();
typedef NTSTATUS (*F_1)(ULONG);
typedef NTSTATUS (*F_2)(ULONG, ULONG);
typedef NTSTATUS (*F_3)(ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_4)(ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_5)(ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_6)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_7)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_8)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_9)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_10)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_11)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_12)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_13)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_14)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_15)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (*F_16)(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, GetOsVersion)
#pragma alloc_text(PAGE, InitCommonVars)
#pragma alloc_text(PAGE, InitShadowServiceId)
#pragma alloc_text(PAGE, GetSectionObjectByName)
#pragma alloc_text(PAGE, GetSystemModules)
#pragma alloc_text(PAGE, GetSystemProcesses)
//#pragma alloc_text(PAGE, GetProcIdByName)
//#pragma alloc_text(PAGE, GetThreadNumOfProcess)
#pragma alloc_text(PAGE, GetHandleCountOfProcess)
#pragma alloc_text(PAGE, GetSysModInfoByName)
#pragma alloc_text(PAGE, MyGetProcAddress)
#pragma alloc_text(PAGE, IsCurrentProcRProcess)
#pragma alloc_text(PAGE, GetProcNameByEproc)
#pragma alloc_text(PAGE, MyProbeForRead)
#pragma alloc_text(PAGE, MyProbeForWrite)
//#pragma alloc_text(PAGE, GetHash)
#endif


#endif

