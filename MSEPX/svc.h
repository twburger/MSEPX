// svc.h

#pragma once

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <assert.h>

#include "ServiceName.h"
#include "common.h"

#pragma comment(lib, "advapi32.lib")

#define MAX_PATH_LEN 255

struct _ThreadArgs {
	HANDLE QuitEvent;
	//HANDLE hReadWritePipe;
	LPCWSTR PipeName;
};

VOID SvcInstall(void);
VOID WINAPI SvcCtrlHandler( DWORD ); 
VOID WINAPI SvcMain( DWORD, LPTSTR * ); 

VOID ReportSvcStatus( DWORD, DWORD, DWORD );
VOID ServiceRun( DWORD, LPTSTR * ); 
VOID SvcReportEvent( LPTSTR );

HKEY GetRegistrationKey(LPTSTR keyname);
HKEY GetRegSubKey( LPTSTR keyname, LPTSTR subkeyname );
DWORD GetRegValType(LPTSTR RegValueType);
byte* GetRegData(DWORD RegValueType, LPTSTR value, DWORD & size);
