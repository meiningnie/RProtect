#ifndef _WHITE_BLACK_LIST_H_
#define _WHITE_BLACK_LIST_H_


#define MAX_NODE_NAME_LEN 32

#define NODE_TYPE_WHITE		0
#define NODE_TYPE_BLACK		1

typedef struct _WHITEBLACKHASHNODE_ {
	struct _WHITEBLACKHASHNODE_ * pNextNode;
	ULONG ulCrimeType;
	UCHAR NodeType;
	WCHAR wzProcName[MAX_NODE_NAME_LEN];
} WHITEBLACKHASHNODE, *PWHITEBLACKHASHNODE, **PPWHITEBLACKHASHNODE;


extern PWHITEBLACKHASHNODE g_WhiteBlackHashTable[0x100];
extern KSPIN_LOCK g_WhiteBlackHashSpinLock;

#define GET_INDEX(ulCrimeType)		(BYTE)((((ULONG)(ulCrimeType)) >> 24) | (((ULONG)(ulCrimeType)) & 0xF))

BOOLEAN InitWhiteBlackHashTable();
BOOLEAN IsInWhiteBlackHashTable(PUNICODE_STRING pusNodeName, ULONG ulCrimeType, UCHAR NodeType);
BOOLEAN AddToWhiteBlackHashTable(PUNICODE_STRING pusNodeName, ULONG ulCrimeType, UCHAR NodeType);
BOOLEAN DelFromWhiteBlackHashTable(PUNICODE_STRING pusNodeName, ULONG ulCrimeType);

void EraseWhiteBlackHashTable();

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InitWhiteBlackHashTable)
#endif


#endif

