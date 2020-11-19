#include "StdAfx.h"
#include "Utility.h"

CUtility::CUtility(void)
{
}

CUtility::~CUtility(void)
{
}

// Lookup a registry error to display
LPCWSTR CUtility::LookupRegistryError(const DWORD errorcode)
{
	LPCWSTR mssg = NULL;

	ERROR_TABLE t[] = {
		{1, _T("ERROR_INVALID_FUNCTION")},
		{2, _T("ERROR_FILE_NOT_FOUND - The registry entry was not found")},
		{4, _T("ERROR_TOO_MANY_OPEN_FILES")},
		{5, _T("ERROR_ACCESS_DENIED - The current user has insufficient access rights")},
		{6, _T("ERROR_INVALID_HANDLE")},
		{8, _T("ERROR_NOT_ENOUGH_MEMORY")},
		{12, _T("ERROR_INVALID_ACCESS")},
		{13, _T("ERROR_INVALID_DATA")},
		{234, _T("ERROR_MORE_DATA")},
		{122, _T("ERROR_INSUFFICIENT_BUFFER")},
		{87, _T("ERROR_INVALID_PARAMETER")},

		// program specific errors
		{ERR_CURRENT_USER_NOT_FOUND, _T("Did not find current user")},
		{UNKNOWN_ERROR, _T("An unknown error occurred")},
		{ERR_SERVICE, _T("An error occurred in the RegValSvc service.")},
		{ERR_SERVICE_RETVAL, _T("The RegValSvc service returned a value but it could not be processed.")},

		( 0, NULL )
	};

	pERROR_TABLE p = t;
	int i=0, sz = (sizeof(t)/sizeof(ERROR_TABLE));
	while( p->code && p->sError && i < sz )
	{
		if( errorcode == p->code )
		{
			mssg = p->sError;
			break;
		}
		p++;
		i++;
	}

	return mssg;
}

// Display an error to the user in a message box
void CUtility::ShowRegistryError( HWND hWnd, DWORD ErrVal, LPCWSTR pStrDetails )
{
	DWORD fmflags = FORMAT_MESSAGE_FROM_SYSTEM | 
		// FORMAT_MESSAGE_ALLOCATE_BUFFER |  // just does not seem to work
		FORMAT_MESSAGE_IGNORE_INSERTS; // do not expect an array of inserts (last param) - must be used
	DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
	LPWSTR lpSystemMssgBuffer = NULL;

	ASSERT(ErrVal != 0);

	// make sure an error was reported
	if( !ErrVal )
		ErrVal = GetLastError();
	if( !ErrVal )
		ErrVal = UNKNOWN_ERROR; // // return;

	// Get an explanation of the most common errors from our lookup
	LPCWSTR pStrErr = LookupRegistryError(ErrVal);
	if( !pStrErr )
	{
		// allocate memory to get a system error
		lpSystemMssgBuffer = new WCHAR[SZ_SYS_ERR_MSSG+1];
		DWORD c = FormatMessage( fmflags, NULL, ErrVal, lang, lpSystemMssgBuffer, SZ_SYS_ERR_MSSG, NULL);
		if( c && lpSystemMssgBuffer )
		{
			pStrErr = lpSystemMssgBuffer;
		}
	}
	// Format and show the error message
	if( pStrErr )
	{
		// build a buffer big enough for the string
		// If using wsprintf you can just set the buffer to the maximum 1024+1
		// If using _snprintf_s you can set the size of the string needed and 
		// either truncate the overflow or set the count to the buffer length -1 for the termination WCHAR of 0
		unsigned int len = (lstrlen(pStrErr) + lstrlen(pStrDetails) + lstrlen(ERR_FORMAT_STR) + SZ_SAFETY);
		LPWSTR lpMssgBuffer = new WCHAR[len];
		ASSERT(lpMssgBuffer);
		unsigned int count = _TRUNCATE; // len-1;
		if( lpMssgBuffer )
		{
			 _snwprintf_s(lpMssgBuffer, len, count, ERR_FORMAT_STR, pStrErr, pStrDetails);
			MessageBox( hWnd, lpMssgBuffer, REG_ERR_CAPTION, MB_OK | MB_ICONERROR);
			delete lpMssgBuffer;
		}

		// make sure the system error buffer is released
		if( lpSystemMssgBuffer ) 
			delete lpSystemMssgBuffer; // free the system message buffer if it exists
	}
	// just show the general error if no luck above
	else
	{
		// build a buffer big enough for the string
		unsigned int len = ( SZ_ERR_CODE + lstrlen(pStrDetails) + lstrlen(GEN_ERR_FORMAT_STR) + SZ_SAFETY); // 1024;
		LPWSTR lpMssgBuffer = new WCHAR[len];
		ASSERT(lpMssgBuffer);
		unsigned int count = _TRUNCATE; // len-1;
		if( lpMssgBuffer )
		{
			//wsprintf(lpMssgBuffer, _T("0x%08x"), ErrVal);
			//DWORD l = lstrlen(lpMssgBuffer); // tests to 10

			 _snwprintf_s(lpMssgBuffer, len, count, GEN_ERR_FORMAT_STR, ErrVal, pStrDetails);
			//wsprintf(lpMssgBuffer, GEN_ERR_FORMAT_STR, rv, pStrDetails);
			MessageBox( hWnd, lpMssgBuffer, REG_ERR_CAPTION, MB_OK | MB_ICONERROR);
			delete lpMssgBuffer;
		}
	}

	return;
}

