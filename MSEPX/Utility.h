#pragma once

#define SZ_SYS_ERR_MSSG 1024
#define SZ_SAFETY 128
#define SZ_ERR_CODE 10

#define ERR_CURRENT_USER_NOT_FOUND -99
#define UNKNOWN_ERROR -1
#define ERR_SERVICE -2
#define ERR_SERVICE_RETVAL -3

#define REG_ERR_CAPTION _T("Registry Error")
#define GEN_ERR_FORMAT_STR _T("Registry operation failure.\nError code: 0x%08x")
//#define GEN_ERR_FORMAT_STR _T("Registry operation failure.\nError code: %Id\n%s")
#define ERR_FORMAT_STR _T("Error: %s\n%s")

typedef struct {
	DWORD code;
	LPCWSTR sError;
}ERROR_TABLE, *pERROR_TABLE;


class CUtility
{
public:
	CUtility(void);
	~CUtility(void);

	static LPWSTR GetErrorMessageBuffer() { LPWSTR m = new WCHAR[SZ_SYS_ERR_MSSG]; return m; };
	static const DWORD MaxMssgBuffSz = SZ_SYS_ERR_MSSG; // buffer size reference
	static void ShowRegistryError( HWND hWnd, DWORD rv, LPCWSTR details );
private:
	static LPCWSTR LookupRegistryError(const DWORD errorcode);
};
