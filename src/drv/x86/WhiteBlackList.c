/*++

Module Name:

	WhiteBlackList.c - 黑白名单模块

Abstract:

	该模块负责黑、白名单的相关算法

Author:

	Fypher

	2012/02/27

--*/
#include <ntifs.h>
#include "Common.h"
#include "EventHandler.h"
#include "WhiteBlackList.h"

PWHITEBLACKHASHNODE g_WhiteBlackHashTable[0x100] = {0};
KSPIN_LOCK g_WhiteBlackHashSpinLock;


BOOLEAN InitWhiteBlackHashTable() {
	UNICODE_STRING usNodeName;
	BOOLEAN bResult = TRUE;

	PAGED_CODE();

	KeInitializeSpinLock(&g_WhiteBlackHashSpinLock);

	// add rprotect.exe/csrss.exe as trusted process
	RtlInitUnicodeString(&usNodeName, L"csrss.exe");
	bResult = (bResult && AddToWhiteBlackHashTable(&usNodeName, CRIME_MAJOR_ALL, NODE_TYPE_WHITE));

	// add .cpp/.c as protected file
	RtlInitUnicodeString(&usNodeName, L".cpp");
	bResult = (bResult && AddToWhiteBlackHashTable(&usNodeName, CRIME_MAJOR_FILE, NODE_TYPE_BLACK));

	RtlInitUnicodeString(&usNodeName, L".c");
	bResult = (bResult && AddToWhiteBlackHashTable(&usNodeName, CRIME_MAJOR_FILE, NODE_TYPE_BLACK));

	return bResult;
}


BOOLEAN IsInWhiteBlackHashTable(PUNICODE_STRING pusNodeName, ULONG ulCrimeType, UCHAR NodeType)
/*++

Routine Description:



Arguments:



Return Value:



Comments:

--*/
{
	BYTE index = GET_INDEX(ulCrimeType);
	BOOLEAN bFound = FALSE;
	KIRQL OldIrql;
	PWHITEBLACKHASHNODE pWhiteBlackHashNode;


	KeAcquireSpinLock(&g_WhiteBlackHashSpinLock, &OldIrql);

	pWhiteBlackHashNode = g_WhiteBlackHashTable[index];
	while (pWhiteBlackHashNode) {
		if (IsUniStrEndWithWcs(pusNodeName, pWhiteBlackHashNode->wzProcName) && NodeType == pWhiteBlackHashNode->NodeType) {
			// find it
#ifdef DBG
			if (ulCrimeType != CRIME_MAJOR_ALL) {
				if (NodeType == NODE_TYPE_WHITE)
					KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%wZ in White List!\r\n", pusNodeName));
				else
					KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%wZ in Black List!\r\n", pusNodeName));
			}
#endif
			bFound = TRUE;
			break;
		}
		pWhiteBlackHashNode = pWhiteBlackHashNode->pNextNode;
	}

	KeReleaseSpinLock(&g_WhiteBlackHashSpinLock, OldIrql);

	return bFound;
}


BOOLEAN AddToWhiteBlackHashTable(PUNICODE_STRING pusNodeName, ULONG ulCrimeType, UCHAR NodeType)
{
	BYTE index = GET_INDEX(ulCrimeType);
	KIRQL OldIrql;

	PWHITEBLACKHASHNODE pNewNode;

	if (!pusNodeName)
		return FALSE;

	pNewNode = (PWHITEBLACKHASHNODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(WHITEBLACKHASHNODE), ALLOC_TAG);
	if (!pNewNode)
		return FALSE;

	memset(pNewNode, 0, sizeof(WHITEBLACKHASHNODE));

	pNewNode->ulCrimeType = ulCrimeType;
	pNewNode->NodeType = NodeType;

	if (pusNodeName->Length <= (MAX_NODE_NAME_LEN - 1) * sizeof(WCHAR)) {
		RtlCopyMemory(pNewNode->wzProcName, pusNodeName->Buffer, pusNodeName->Length);
	} else {
		RtlCopyMemory(	pNewNode->wzProcName,
						((PBYTE)pusNodeName->Buffer) + (pusNodeName->Length - (MAX_NODE_NAME_LEN - 1) * sizeof(WCHAR)),
						(MAX_NODE_NAME_LEN - 1) * sizeof(WCHAR)
					);
	}


	KeAcquireSpinLock(&g_WhiteBlackHashSpinLock, &OldIrql);
	pNewNode->pNextNode = g_WhiteBlackHashTable[index];
	g_WhiteBlackHashTable[index] = pNewNode;
	KeReleaseSpinLock(&g_WhiteBlackHashSpinLock, OldIrql);

	return TRUE;
}



BOOLEAN DelFromWhiteBlackHashTable(PUNICODE_STRING pusNodeName, ULONG ulCrimeType)
{
	BYTE index = GET_INDEX(ulCrimeType);
	BOOLEAN bFound = FALSE;
	KIRQL OldIrql;
	PWHITEBLACKHASHNODE pWhiteBlackHashNode;

	KeAcquireSpinLock(&g_WhiteBlackHashSpinLock, &OldIrql);

	pWhiteBlackHashNode = g_WhiteBlackHashTable[index];
	if (!pWhiteBlackHashNode)
		return FALSE;

	if (IsUniStrEndWithWcs(pusNodeName, pWhiteBlackHashNode->wzProcName)) {
		// find it
		g_WhiteBlackHashTable[index] = pWhiteBlackHashNode->pNextNode;
		ExFreePool(pWhiteBlackHashNode);
		KeReleaseSpinLock(&g_WhiteBlackHashSpinLock, OldIrql);
		return TRUE;
	}

	while (pWhiteBlackHashNode->pNextNode) {
		if (IsUniStrEndWithWcs(pusNodeName, pWhiteBlackHashNode->pNextNode->wzProcName)) {
			// find it
			PWHITEBLACKHASHNODE pTmpNode = pWhiteBlackHashNode->pNextNode;
			pWhiteBlackHashNode->pNextNode = pTmpNode->pNextNode;
			ExFreePool(pTmpNode);
			bFound = TRUE;
			break;
		}
		pWhiteBlackHashNode = pWhiteBlackHashNode->pNextNode;
	}

	KeReleaseSpinLock(&g_WhiteBlackHashSpinLock, OldIrql);

	return bFound;
}


void EraseWhiteBlackHashTable()
{
	int i;
	KIRQL OldIrql;

	KeAcquireSpinLock(&g_WhiteBlackHashSpinLock, &OldIrql);
	for (i = 0; i <= 0xFF; ++i) {
		PWHITEBLACKHASHNODE pWhiteBlackHashNode = g_WhiteBlackHashTable[i];
		g_WhiteBlackHashTable[i] = NULL;
		while (pWhiteBlackHashNode) {
			PWHITEBLACKHASHNODE pTmpNode = pWhiteBlackHashNode;
			pWhiteBlackHashNode = pWhiteBlackHashNode->pNextNode;
			ExFreePool(pTmpNode);
		}
	}
	KeReleaseSpinLock(&g_WhiteBlackHashSpinLock, OldIrql);
}




