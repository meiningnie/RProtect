#ifndef _EVENT_HANDLER_H_
#define _EVENT_HANDLER_H_

#include "SysCallFlt.h"

#define MAX_EVENT_IN_LIST		50

#define JUDGMENT_REFUSE			1
#define JUDGMENT_ACCEPT			2
#define JUDGMENT_ALWAYS			4




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

//#define CRIME_MINOR_NtCreateSection				0x40000001
#define CRIME_MINOR_NtCreateUserProcess			0x40000001
#define CRIME_MINOR_NtCreateSection				CRIME_MINOR_NtCreateUserProcess
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


typedef struct _EVENTDATA_{
	LIST_ENTRY ListEntry;
	KEVENT evt;
	ULONG ulCrimeType;
	ULONG ulJudgment;
	ULONG ulExtraInfo;
	PEPROCESS pCriminalEproc;
	PEPROCESS pVictimEproc;
	UNICODE_STRING usCriminal;
	UNICODE_STRING usVictim;
	WCHAR wzCriminal[MAX_PATH];
	WCHAR wzVictim[MAX_PATH];
} EVENTDATA, *PEVENTDATA, **PPEVENTDATA;

#define USER_MAX_PATH (MAX_PATH + 2)
typedef struct _USEREVENTDATA_{
	ULONG	ulEvtData;
	ULONG		ulCrimeType;
	ULONG	ulExtraInfo;
	WCHAR		wzCriminal[USER_MAX_PATH];
	WCHAR		wzVictim[USER_MAX_PATH];
} USEREVENTDATA, *PUSEREVENTDATA, **PPUSEREVENTDATA;


typedef struct _JUDGMENTDATA_{
	ULONG ulEvtData;
	ULONG ulJudgment;
} JUDGMENTDATA, *PJUDGMENTDATA, **PPJUDGMENTDATA;


extern LIST_ENTRY g_EventDataLinkListHead;
extern NPAGED_LOOKASIDE_LIST g_EventDataPageList;
extern KSPIN_LOCK g_EventDataLock;
extern ULONG g_ulEventDataCount;;
extern KSEMAPHORE g_EventDataSemaphore;



RPSTATUS
EventCheck(
	IN PUNICODE_STRING pusCriminal,
	IN PUNICODE_STRING pusVictim,
	IN PEPROCESS		pCriminalEproc,
	IN PEPROCESS		pVictimEproc,
	IN ULONG			ulCrimeType,
	IN ULONG		ulExtraInfo
	);


PEVENTDATA
BuildEventData(
	IN PUNICODE_STRING pusCriminal,
	IN PUNICODE_STRING pusVictim,
	IN PEPROCESS		pCriminalEproc,
	IN PEPROCESS		pVictimEproc,
	IN ULONG			ulCrimeType,
	IN ULONG		ulExtraInfo
	);

BOOLEAN InitEventHandler();

VOID BuildUserEventData(IN PEVENTDATA pEvtData, OUT PUSEREVENTDATA pUsrEvtData);


VOID DestroyEventData(IN PEVENTDATA pEvtData);

VOID PushEvent(IN PEVENTDATA pEvtData);
PEVENTDATA PopEvent(IN PLARGE_INTEGER Timeout);
VOID CancelAllEvents();

VOID SetMajorProtectedType(IN ULONG ulCrimeType, IN BOOLEAN bOn);
BOOLEAN IsMajorProtected(IN ULONG ulCrimeType);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EventCheck)
#pragma alloc_text(PAGE, BuildEventData)
#pragma alloc_text(PAGE, IsMajorProtected)
#pragma alloc_text(PAGE, SetMajorProtectedType)
#pragma alloc_text(PAGE, InitEventHandler)
#pragma alloc_text(PAGE, BuildUserEventData)
#pragma alloc_text(PAGE, DestroyEventData)
#pragma alloc_text(PAGE, PushEvent)
#pragma alloc_text(PAGE, PopEvent)
#pragma alloc_text(PAGE, CancelAllEvents)
#endif




#endif

