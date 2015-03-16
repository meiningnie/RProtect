/*++

Module Name:

	EventHandler.c - 处理违规操作的模块

Abstract:

	该模块处理检测到的违规操作。

	当检测到一个违规操作后，该违规操作将被组织成一个“违规事件”，根据监控状态、黑白名单状态决定是否放行，无法决定的违规事件将被压入队尾。

	Ring3索取违规事件时，从队头取出并决策。

	考虑到“违规事件”的产生频繁，这里使用 NPAGED_LOOKASIDE_LIST 数据结构来避免内存空洞。

Author:

	Fypher

	2012/02/27

--*/
#include <ntifs.h>
#include "Common.h"
#include "SysCallFlt.h"
#include "WhiteBlackList.h"
#include "EventHandler.h"


//#pragma data_seg("PAGE")
ULONG g_ulEventDataCount = 0;
KSEMAPHORE g_EventDataSemaphore;
//#pragma data_seg()

LIST_ENTRY g_EventDataLinkListHead;
NPAGED_LOOKASIDE_LIST g_EventDataPageList;
KSPIN_LOCK g_EventDataLock;


ULONG g_ulMajorProtectedMask = 0;


BOOLEAN InitEventHandler()
/*++

Routine Description:

	初始化工作


Arguments:

	None.


Return Value:

	TRUE if successful, and FALSE if not.


Author:

	Fypher

--*/
{
	PAGED_CODE();

	KeInitializeSemaphore(&g_EventDataSemaphore, 0 , MAXLONG);
	KeInitializeSpinLock(&g_EventDataLock);
	InitializeListHead(&g_EventDataLinkListHead);
	ExInitializeNPagedLookasideList(&g_EventDataPageList, NULL, NULL, 0, sizeof(EVENTDATA), ALLOC_TAG, 0);
	g_ulEventDataCount = 0;
	g_ulMajorProtectedMask = 0;

	SetMajorProtectedType(CRIME_MAJOR_ALL, TRUE);

	return TRUE;
}


RPSTATUS
EventCheck(
	IN PUNICODE_STRING pusCriminal,
	IN PUNICODE_STRING pusVictim,
	IN PEPROCESS		pCriminalEproc,
	IN PEPROCESS		pVictimEproc,
	IN ULONG			ulCrimeType,
	IN ULONG_PTR		ulpExtraInfo
	)
/*++

Routine Description:

	处理检测到的违规操作


Arguments:

	pusCriminal - 违规者名字

	pusVictim - 受害者名字

	pCriminalEproc - 违规者进程

	pVictimEproc - 受害者进程

	ulCrimeType - 违规类型

	ulpExtraInfo - 额外信息，根据违规类型的不同而不同


Return Value:

	允许放行返回 RP_STATUS_OK，拒绝该操作返回 RP_STATUS_ERR


Author:

	Fypher

--*/
{
	PEVENTDATA pEvtData;
	ULONG ulJudgment;
	RPSTATUS RpStatus = RP_STATUS_NOT_CLEAR;

	PAGED_CODE();

	if (!g_pProtected)					// no ring3
		return RP_STATUS_OK;

	if (!IsMajorProtected(ulCrimeType))		// protect off
		return RP_STATUS_OK;

	if (IsInWhiteBlackHashTable(pusCriminal, CRIME_MAJOR_ALL, NODE_TYPE_WHITE))	// Super White List
		return RP_STATUS_OK;

	if (IsInWhiteBlackHashTable(pusCriminal, ulCrimeType, NODE_TYPE_WHITE))			// white list
		RpStatus = RP_STATUS_OK;
	else if (IsInWhiteBlackHashTable(pusCriminal, ulCrimeType, NODE_TYPE_BLACK))	// black list
		RpStatus = RP_STATUS_ERR;

	if (pCriminalEproc && pCriminalEproc == pVictimEproc)	// Self xx
		return RP_STATUS_OK;

	if (g_ulEventDataCount > MAX_EVENT_IN_LIST)	{ // too many
		KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "EventCheck! g_ulEventDataCount: %d\r\n", g_ulEventDataCount));
		return RP_STATUS_ERR;
	}

	switch (ulCrimeType & CRIME_MAJOR_MASK) {
		//
		// CRIME_MAJOR_FILE
		//
		case CRIME_MAJOR_FILE:
			if (!IsInWhiteBlackHashTable(pusVictim, CRIME_MAJOR_FILE, NODE_TYPE_BLACK))
				return RP_STATUS_OK;

			break;
		//
		// CRIME_MAJOR_PROC
		//
		case CRIME_MAJOR_PROC:
			if (pVictimEproc == g_pProtected)	// self protect
				return RP_STATUS_ERR;

			// only for self protect
			if (ulCrimeType == CRIME_MINOR_NtOpenProcess	||
				ulCrimeType == CRIME_MINOR_NtOpenThread		||
				ulCrimeType == CRIME_MINOR_NtAssignProcessToJobObject)
			{
				return RP_STATUS_OK;
			}
			break;
		//
		// CRIME_MAJOR_REG
		//
		case CRIME_MAJOR_REG:
			break;
		//
		// CRIME_MAJOR_SYS
		//
		case CRIME_MAJOR_SYS:
			if (ulCrimeType == CRIME_MINOR_NtDuplicateObject)
			{
				if (g_pProtected == (PEPROCESS)ulpExtraInfo) {	// selfprotect
					return RP_STATUS_ERR;
				}
			}
			else if (ulCrimeType == CRIME_MINOR_NtOpenSection)
			{
				if (/*g_pPhysicalMemoryObj && */g_pPhysicalMemoryObj != (PVOID)ulpExtraInfo)
					return RP_STATUS_OK;
			}
			break;
		default:
			KdPrintEx((	DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"EventCheck! How did I get here! %x\r\n", ulCrimeType
					));
			break;
	}

	if (RpStatus != RP_STATUS_NOT_CLEAR)
		return RpStatus;

	pEvtData = BuildEventData(pusCriminal, pusVictim, pCriminalEproc, pVictimEproc, ulCrimeType, ulpExtraInfo);
	if (!pEvtData)
		return RP_STATUS_ERR;

	PushEvent(pEvtData);

	KeWaitForSingleObject(&pEvtData->evt, Executive, KernelMode, FALSE, NULL);

	ulJudgment = pEvtData->ulJudgment;

	DestroyEventData(pEvtData);

	if (ulJudgment & JUDGMENT_ACCEPT) {
		if (ulJudgment & JUDGMENT_ALWAYS) {
			AddToWhiteBlackHashTable(pusCriminal, ulCrimeType, NODE_TYPE_WHITE);
		}
		return RP_STATUS_OK;
	} else if (ulJudgment & JUDGMENT_REFUSE) {
		if (ulJudgment & JUDGMENT_ALWAYS) {
			AddToWhiteBlackHashTable(pusCriminal, ulCrimeType, NODE_TYPE_BLACK);
		}
		return RP_STATUS_ERR;
	}

	// never reaches here
	return RP_STATUS_ERR;

}


VOID SetMajorProtectedType(IN ULONG ulCrimeType, IN BOOLEAN bOn) {

	PAGED_CODE();

	if (bOn)
		g_ulMajorProtectedMask |= (ulCrimeType & CRIME_MAJOR_MASK);
	else
		g_ulMajorProtectedMask &= ~(ulCrimeType & CRIME_MAJOR_MASK);
}

BOOLEAN IsMajorProtected(IN ULONG ulCrimeType) {

	PAGED_CODE();

	return ((ulCrimeType & CRIME_MAJOR_MASK & g_ulMajorProtectedMask) != 0);
}


PEVENTDATA
BuildEventData(
	IN PUNICODE_STRING pusCriminal,
	IN PUNICODE_STRING pusVictim,
	IN PEPROCESS		pCriminalEproc,
	IN PEPROCESS		pVictimEproc,
	IN ULONG			ulCrimeType,
	IN ULONG_PTR		ulpExtraInfo
	)
/*++

Routine Description:

	根据违规操作的具体信息，创建一个“违规事件”


Arguments:

	pusCriminal - 违规者名字

	pusVictim - 受害者名字

	pCriminalEproc - 违规者进程

	pVictimEproc - 受害者进程

	ulCrimeType - 违规类型

	ulpExtraInfo - 额外信息，根据违规类型的不同而不同


Return Value:

	成功则返回“违规事件”，失败返回 NULL。


Comments:

    该函数返回的“违规事件”，使用完毕后需要调用DestroyEventData进行销毁


Author:

	Fypher

--*/
{
	PEVENTDATA pEvtData;

	PAGED_CODE();

	pEvtData = (PEVENTDATA)ExAllocateFromNPagedLookasideList(&g_EventDataPageList);
	if (!pEvtData)
		return NULL;

	// memset(pEvtData, 0, sizeof(EVENTDATA));

	KeInitializeEvent(&pEvtData->evt, NotificationEvent, FALSE);
	pEvtData->ulCrimeType = ulCrimeType;

	pEvtData->ulpExtraInfo = ulpExtraInfo;

	pEvtData->pCriminalEproc = pCriminalEproc;
	pEvtData->pVictimEproc = pVictimEproc;

	pEvtData->usCriminal.Length = pEvtData->usVictim.Length = 0;
	pEvtData->usCriminal.MaximumLength = pEvtData->usVictim.MaximumLength = MAX_PATH;
	pEvtData->usCriminal.Buffer = pEvtData->wzCriminal;
	pEvtData->usVictim.Buffer = pEvtData->wzVictim;

	if (pusCriminal) {
		RtlCopyUnicodeString(&pEvtData->usCriminal, pusCriminal);
	} else {
		wcscpy_s(pEvtData->usCriminal.Buffer, MAX_PATH, L"Unknown");
		pEvtData->usCriminal.Length = 14;	// !!!!!
	}

	if (pusVictim) {
		RtlCopyUnicodeString(&pEvtData->usVictim, pusVictim);
	} else if (ulCrimeType & CRIME_MAJOR_SYS) {
		wcscpy_s(pEvtData->usVictim.Buffer, MAX_PATH, L"System-wide");
		pEvtData->usVictim.Length = 22;	// !!!!!
	} else {
		wcscpy_s(pEvtData->usVictim.Buffer, MAX_PATH, L"Unknown");
		pEvtData->usVictim.Length = 14;	// !!!!!
	}

	return pEvtData;
}


VOID BuildUserEventData(IN PEVENTDATA pEvtData, OUT PUSEREVENTDATA pUsrEvtData)
/*++

Routine Description:

	根据指定的“违规事件”，创建一个“精简版违规事件”，以便传递给Ring3


Arguments:

	pEvtData - 指定“违规事件”

	pUsrEvtData - 存放“精简版违规事件”


Return Value:

	NULL.


Author:

	Fypher

--*/
{
	PAGED_CODE();

	memset(pUsrEvtData, 0, sizeof(USEREVENTDATA));

	pUsrEvtData->ulpEvtData = (ULONG_PTR)pEvtData;
	pUsrEvtData->ulCrimeType = pEvtData->ulCrimeType;
	pUsrEvtData->ulpExtraInfo = pEvtData->ulpExtraInfo;

	RtlCopyMemory(pUsrEvtData->wzCriminal, pEvtData->wzCriminal, pEvtData->usCriminal.Length);
	RtlCopyMemory(pUsrEvtData->wzVictim, pEvtData->wzVictim, pEvtData->usVictim.Length);
}


VOID DestroyEventData(IN PEVENTDATA pEvtData)
/*++

Routine Description:

	销毁一个“违规事件”


Arguments:

	pEvtData - 指定“违规事件”


Return Value:

	None.

Comment:

    BuildEventData 函数创建产生的“违规事件”，必须通过该函数释放


Author:

	Fypher

--*/
{

	PAGED_CODE();

	ExFreeToNPagedLookasideList(&g_EventDataPageList, pEvtData);
}


VOID PushEvent(IN PEVENTDATA pEvtData)
/*++

Routine Description:

	“违规事件”压栈


Arguments:

	pEvtData - 指定“违规事件”


Return Value:

	None.

Author:

	Fypher

--*/
{

	PAGED_CODE();

	ExInterlockedInsertTailList(&g_EventDataLinkListHead, &pEvtData->ListEntry, &g_EventDataLock);
	InterlockedIncrement(&g_ulEventDataCount);

	KeReleaseSemaphore(&g_EventDataSemaphore, 0, 1, FALSE);
}

PEVENTDATA PopEvent(IN PLARGE_INTEGER Timeout)
/*++

Routine Description:

	“违规事件”出栈


Arguments:

	Timeout - 超时值，若栈中没有违规事件，则等待(*Timeout) * 100ns。该参数为 NULL 表示无限等待


Return Value:

	成功返回违规事件，失败（超时）返回NULL。


Author:

	Fypher

--*/
{
	PLIST_ENTRY pEntry ;
	PEVENTDATA pEvtData;
	NTSTATUS NtStatus;

	PAGED_CODE();

	NtStatus = KeWaitForSingleObject(&g_EventDataSemaphore, Executive, KernelMode, FALSE, Timeout);

	if (NtStatus == STATUS_TIMEOUT || !NT_SUCCESS(NtStatus))
		return NULL;

	pEntry = ExInterlockedRemoveHeadList(&g_EventDataLinkListHead, &g_EventDataLock);
	pEvtData = CONTAINING_RECORD(pEntry, EVENTDATA, ListEntry);
	InterlockedDecrement(&g_ulEventDataCount);
	return pEvtData;
}

VOID CancelAllEvents()
/*++

Routine Description:

	取消所有还未来得及处理的违规操作


Arguments:

	None.


Return Value:

	None.


Comments:

	该函数可以在Ring3进程退出时和驱动卸载时调用


Author:

	Fypher

*/
{
	PLIST_ENTRY pEntry;
	PEVENTDATA pEvtData;

	PAGED_CODE();

	InterlockedExchange(&g_ulEventDataCount, MAX_EVENT_IN_LIST + 1);

	while(KeReadStateSemaphore(&g_EventDataSemaphore)){
		KeWaitForSingleObject(&g_EventDataSemaphore, Executive, KernelMode, FALSE, NULL);
		pEntry = ExInterlockedRemoveHeadList(&g_EventDataLinkListHead, &g_EventDataLock);
		pEvtData = CONTAINING_RECORD(pEntry, EVENTDATA, ListEntry);
		pEvtData->ulJudgment = JUDGMENT_REFUSE;
		KeSetEvent(&pEvtData->evt, IO_NO_INCREMENT, FALSE);
	}

	InterlockedExchange(&g_ulEventDataCount, 0);
}
