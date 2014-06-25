// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef _STDAFX_H_
#define _STDAFX_H_

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

// TODO: reference additional headers your program requires here

#ifdef WIN32
#include <crtdbg.h>
#endif

#ifdef WIN32
#define _WIN32_WINNT    0x0500
#include <winsock2.h>
#include <Windows.h>
#endif

// #include "Ksdef.h"
#include <string.h>

// #ifdef WIN32
// #include "Engine/KWin32.h"
// #endif

#endif
