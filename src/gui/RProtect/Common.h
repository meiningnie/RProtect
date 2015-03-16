#ifndef _COMMON_H_
#define _COMMON_H_

#ifndef UNICODE
	#define UNICODE
#endif

#ifndef _UNICODE
	#define _UNICODE
#endif

#include <windows.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <process.h>
#include <tchar.h>

#include <shlobj.h>

#include "Resource.h"

#pragma comment(lib,"comctl32.lib")

typedef unsigned (__stdcall *PTHREAD_START) (void *);

#define BEGINTHREADEX(psa, cbStack, pfnStartAddr,	\
   pvParam, fdwCreate, pdwThreadId)                 \
      ((HANDLE)_beginthreadex(                      \
         (void *)        (psa),                     \
         (unsigned)      (cbStack),                 \
         (PTHREAD_START) (pfnStartAddr),            \
         (void *)        (pvParam),                 \
         (unsigned)      (fdwCreate),               \
         (unsigned *)    (pdwThreadId)))


extern HANDLE g_hDev;


#endif
