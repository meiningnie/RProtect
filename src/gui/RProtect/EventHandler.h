#ifndef _EVENT_HANDLER_H_
#define _EVENT_HANDLER_H_


#define IOCTL_GET_EVENT						\
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa01,	\
	METHOD_BUFFERED, FILE_READ_DATA )

#define IOCTL_GIVE_JUDGMENT					\
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa02, 	\
	METHOD_BUFFERED, FILE_WRITE_DATA)



////////////////////////////////////////////////////////////
//
//		CRIME_FILE
//
#define CRIME_MAJOR_FILE						0x10000000

#define CRIME_MINOR_NtCreateFile				0x10000001
#define CRIME_MINOR_NtOpenFile					0x10000002
#define CRIME_MINOR_NtDeleteFile				0x10000003
#define CRIME_MINOR_NtSetInformationFile		0x10000004

////////////////////////////////////////////////////////////
//
//		CRIME_REG
//
#define CRIME_MAJOR_REG							0x20000000



////////////////////////////////////////////////////////////
//
//		CRIME_PROC
//
#define CRIME_MAJOR_PROC						0x40000000

#define CRIME_MINOR_NtCreateUserProcess			0x40000001
//#define CRIME_MINOR_NtCreateSection				0x40000001
#define CRIME_MINOR_NtCreateThread				0x40000002
#define CRIME_MINOR_NtSuspendThread				0x40000003
#define CRIME_MINOR_NtSuspendProcess			0x40000004
#define CRIME_MINOR_NtGetContextThread			0x40000005
#define CRIME_MINOR_NtSetContextThread			0x40000006
#define CRIME_MINOR_NtTerminateProcess			0x40000007
#define CRIME_MINOR_NtTerminateThread			0x40000008
#define CRIME_MINOR_NtReadVirtualMemory			0x40000009
#define CRIME_MINOR_NtWriteVirtualMemory		0x4000000A
#define CRIME_MINOR_NtProtectVirtualMemory		0x4000000B
#define CRIME_MINOR_NtOpenThread				0x4000000C
#define CRIME_MINOR_NtOpenProcess				0x4000000D
#define CRIME_MINOR_NtAssignProcessToJobObject	0x4000000E



////////////////////////////////////////////////////////////
//
//		CRIME_SYS
//
#define CRIME_MAJOR_SYS							0x80000000

#define CRIME_MINOR_NtLoadDriver				0x80000001
#define CRIME_MINOR_NtUnloadDriver				0x80000002
#define CRIME_MINOR_NtSetSystemInformation		0x80000003
#define CRIME_MINOR_NtOpenSection				0x80000004
#define CRIME_MINOR_NtCreateSymbolicLinkObject	0x80000005
#define CRIME_MINOR_NtSystemDebugControl		0x80000006
#define CRIME_MINOR_NtUserSetWindowsHookEx		0x80000007
#define CRIME_MINOR_NtDuplicateObject			0x80000008

////////////////////////////////////////////////////////////
//
//		CRIME_ALL
//
#define CRIME_MAJOR_ALL		(CRIME_MAJOR_PROC | CRIME_MAJOR_FILE | CRIME_MAJOR_REG | CRIME_MAJOR_SYS)


#define CRIME_MAJOR_MASK	0xF0000000



#define JUDGMENT_REFUSE			1
#define JUDGMENT_ACCEPT			2
#define JUDGMENT_ALWAYS			4



#define USER_MAX_PATH (MAX_PATH + 2)
typedef struct _USEREVENTDATA_{
	ULONG	ulEvtData;
	ULONG		ulCrimeType;
	ULONG	ulExtraInfo;
	WCHAR		wzCriminal[USER_MAX_PATH];
	WCHAR		wzVictim[USER_MAX_PATH];
} USEREVENTDATA, *PUSEREVENTDATA, **PPUSEREVENTDATA;


typedef struct _JUDGMENTDATA_{
	ULONG				ulEvtData;
	ULONG					ulJudgment;
} JUDGMENTDATA, *PJUDGMENTDATA, **PPJUDGMENTDATA;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation         = 1,
    FileFullDirectoryInformation,   // 2
    FileBothDirectoryInformation,   // 3
    FileBasicInformation,           // 4
    FileStandardInformation,        // 5
    FileInternalInformation,        // 6
    FileEaInformation,              // 7
    FileAccessInformation,          // 8
    FileNameInformation,            // 9
    FileRenameInformation,          // 10
    FileLinkInformation,            // 11
    FileNamesInformation,           // 12
    FileDispositionInformation,     // 13
    FilePositionInformation,        // 14
    FileFullEaInformation,          // 15
    FileModeInformation,            // 16
    FileAlignmentInformation,       // 17
    FileAllInformation,             // 18
    FileAllocationInformation,      // 19
    FileEndOfFileInformation,       // 20
    FileAlternateNameInformation,   // 21
    FileStreamInformation,          // 22
    FilePipeInformation,            // 23
    FilePipeLocalInformation,       // 24
    FilePipeRemoteInformation,      // 25
    FileMailslotQueryInformation,   // 26
    FileMailslotSetInformation,     // 27
    FileCompressionInformation,     // 28
    FileObjectIdInformation,        // 29
    FileCompletionInformation,      // 30
    FileMoveClusterInformation,     // 31
    FileQuotaInformation,           // 32
    FileReparsePointInformation,    // 33
    FileNetworkOpenInformation,     // 34
    FileAttributeTagInformation,    // 35
    FileTrackingInformation,        // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation,       // 40
    FileIoCompletionNotificationInformation, // 41
    FileIoStatusBlockRangeInformation,       // 42
    FileIoPriorityHintInformation,           // 43
    FileSfioReserveInformation,              // 44
    FileSfioVolumeInformation,               // 45
    FileHardLinkInformation,                 // 46
    FileProcessIdsUsingFileInformation,      // 47
    FileNormalizedNameInformation,           // 48
    FileNetworkPhysicalNameInformation,      // 49
    FileIdGlobalTxDirectoryInformation,      // 50
    FileIsRemoteDeviceInformation,           // 51
    FileAttributeCacheInformation,           // 52
    FileNumaNodeInformation,                 // 53
    FileStandardLinkInformation,             // 54
    FileRemoteProtocolInformation,           // 55
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

extern USEREVENTDATA g_UsrEvtData;

DWORD WINAPI EventHandler(LPVOID lpParameter);
VOID GetDetail(ULONG ulCrimeType, PTSTR tcsMsg, ULONG usMsgLen);
VOID DeviceNameToDosName(PTSTR tcsDevName);
#endif
