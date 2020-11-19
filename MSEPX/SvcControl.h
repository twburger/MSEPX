//SvcControl.h

#pragma once

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

extern SC_HANDLE schSCManager;
extern SC_HANDLE schService;

VOID __stdcall DisplayUsage(void);

DWORD __stdcall DoStartSvc(LPCWSTR szSvcName, DWORD argc, LPCWSTR args[]);
VOID __stdcall DoUpdateSvcDacl(LPCWSTR szSvcName);
VOID __stdcall DoStopSvc(LPCWSTR szSvcName);
