//SvcConfig.h

#pragma once

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

//extern TCHAR szSvcName[80];

VOID __stdcall DisplayUsage(void);

DWORD __stdcall DoQuerySvc(LPCWSTR szSvcName);
VOID __stdcall DoUpdateSvcDesc(LPCWSTR szSvcName);
VOID __stdcall DoDisableSvc(LPCWSTR szSvcName);
VOID __stdcall DoEnableSvc(LPCWSTR szSvcName);
VOID __stdcall DoDeleteSvc(LPCWSTR szSvcName);

