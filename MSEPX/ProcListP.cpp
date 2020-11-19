#include "stdafx.h"
#include "ProcListP.h"

#pragma warning(disable : 4995)
#pragma warning(disable : 4996)

// Programs that must run on earlier versions of Windows as well as Windows 7 and later versions 
// should always call this function as EnumProcesses. To ensure correct resolution of symbols, 
// add Psapi.lib to the TARGETLIBS macro and compile the program 
//with –DPSAPI_VERSION=1. To use run-time dynamic linking, load Psapi.dll.

CEnumProcessList::CEnumProcessList():m_hProcess(0),m_dwError(0)
{
	CModuleDetails	*pThisModule = NULL;
	DWORD		dwNeeded = 0;
	DWORD dwSize = 0;
    DWORD dwProcId[MAXCOUNT] = { 0 };
	TCHAR szName[MAX_PATH] = { 0 };
	//m_ModulesListIter = NULL;


    EnumProcesses( dwProcId, MAXCOUNT, &dwSize );
    if( !dwSize )
    {
        return;
    }

	for( DWORD dwIndex = 0; dwIndex < dwSize; ++dwIndex )
	{
        HANDLE hProcModule = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                          FALSE, 
                                          dwProcId[dwIndex] );
        if( !hProcModule )
        {
            continue;
        }

        DWORD dwModuleSize = 0;
        HMODULE hModules[MAXCOUNT] = { 0 };

        bool bDeviceDriver = false;

        LPVOID lpvLoadAddrs[MAXCOUNT ] = { 0 };

        EnumProcessModules( hProcModule, hModules, MAXCOUNT, &dwModuleSize );
        dwModuleSize /= sizeof( HMODULE );
        if( !dwModuleSize )
        {
            EnumDeviceDrivers( lpvLoadAddrs, MAXCOUNT, &dwModuleSize );
            dwModuleSize /= sizeof( LPVOID );

            if( !dwSize )
            {
                continue;
            }

            bDeviceDriver = true;
        }
      
		if( !bDeviceDriver )
		{
			pThisModule = new CModuleDetails( hProcModule, hModules[0]);
			pThisModule->pProcessID =  dwProcId[dwIndex];
			pThisModule->m_bIsProcess = TRUE;
			m_ModulesList.push_back(pThisModule);
		}

       CloseHandle( hProcModule );
    }
}

CEnumProcessList::CEnumProcessList(DWORD dwProcessID):  m_hProcess(0),m_dwError(0)
{
	HMODULE		hModules[1024];
	int			iHandleCount = 0;
	int			iResult = 0;
	CModuleDetails	* pThisModule = NULL;
	DWORD		dwNeeded = 0;
	//m_ModulesListIter = NULL;


	m_hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,dwProcessID);

	if (m_hProcess == FALSE)
	{
		m_dwError = ::GetLastError();
	}
	else {
		// Get the modules for this process
		iResult = ::EnumProcessModules(m_hProcess,hModules,sizeof(hModules),&dwNeeded);
		if(iResult == 0) {
			m_dwError = ::GetLastError();
		}
		else {
			bool bDeviceDriver = false;
			iHandleCount = (dwNeeded/sizeof(HMODULE));

			for(int i=1;i<iHandleCount;i++) 
			{
				pThisModule = new CModuleDetails(m_hProcess,hModules[i]);
				pThisModule->pProcessID = NULL;
				pThisModule->m_bIsProcess = FALSE;
				m_ModulesList.push_back(pThisModule);
			}
		}
	}

	if(::CloseHandle(m_hProcess) == 0) {
		m_dwError = ::GetLastError();
	}
}


CEnumProcessList::~CEnumProcessList()
{
	CModuleDetails* pModule = NULL;

	if (m_ModulesList.empty() == FALSE) 
	{	
		 
		for(m_ModulesListIterUtil = m_ModulesList.begin(); 
			m_ModulesListIterUtil != m_ModulesList.begin();
			m_ModulesListIterUtil++)
		{
			pModule = (CModuleDetails*)*(m_ModulesListIterUtil);
			ASSERT(pModule != NULL);
			delete pModule;
		}
		m_ModulesList.clear();
	}
}


BOOL CEnumProcessList::GetModuleVersion(CString ModuleName,CString &VersionString)
{
	CModuleDetails* pModuleData = NULL;
	BOOL		 bResult = FALSE;
	ModuleName.MakeUpper();
	
	if (m_ModulesList.empty() == FALSE) 
	{	
		for(m_ModulesListIterUtil = m_ModulesList.begin();
			m_ModulesListIterUtil != m_ModulesList.end();
			m_ModulesListIterUtil++)
		{
			pModuleData = (CModuleDetails *)*(m_ModulesListIterUtil);
			ASSERT(pModuleData != NULL);
			if(ModuleName.CompareNoCase(pModuleData->GetModuleName())!=0)
			{
				bResult = TRUE;
				break;
			}
		}
	}

	if(bResult == TRUE) {
		ASSERT(pModuleData != NULL);
		VersionString = pModuleData->GetFileVersion();
		return(TRUE);
	}
	else {
		VersionString = "";
		return(FALSE);
	}
}

BOOL CEnumProcessList::SearchProcessOrModule(CString ModuleName,CModuleDetails* pModuleData)
{
	BOOL bResult = FALSE;
	ModuleName.MakeUpper();
	
	if (m_ModulesList.empty() == FALSE) 
	{	
		for(m_ModulesListIterUtil = m_ModulesList.begin();
			m_ModulesListIterUtil != m_ModulesList.end(); 
			m_ModulesListIterUtil++)
		{
			pModuleData = (CModuleDetails *)*(m_ModulesListIterUtil);
			ASSERT(pModuleData != NULL);
			if(ModuleName.CompareNoCase(pModuleData->GetModuleName())!=0)
			{
				bResult = TRUE;
				break;
			}
		}
	}

	if(bResult == TRUE) {
		ASSERT(pModuleData != NULL);
		return(TRUE);
	}
	else {
		pModuleData = NULL;
		return(FALSE);
	}
}


CModuleDetails*  CEnumProcessList::GetFirst()
{
	CModuleDetails* pTemp = NULL;
	m_ModulesListIterNext = m_ModulesList.begin();

	ASSERT(m_ModulesList.empty() == FALSE);
	if( m_ModulesList.empty() != FALSE)
	{
		pTemp = (CModuleDetails *) m_ModulesList.front();
	}

	return (pTemp);
}


CModuleDetails* CEnumProcessList::GetNext()
{
	CModuleDetails* pTemp = NULL;

	ASSERT(m_ModulesListIterNext != m_ModulesList.end() );
	if( m_ModulesListIterNext != m_ModulesList.end() )
	{
		m_ModulesListIterNext++;
		pTemp = (CModuleDetails *)*(m_ModulesListIterNext);
		ASSERT(pTemp != NULL);
	}

	return (pTemp);
}

BOOL CEnumProcessList::HasFailed()
{
	if(m_dwError != 0) {
		return(TRUE);
	}
	else {
		return(FALSE);
	}
}


DWORD CEnumProcessList::LastError()
{
	return(m_dwError);
}

CString CEnumProcessList::FormatError(DWORD dwError)
{
	LPTSTR	lpBuffer;
	CString Temp;
	int		iReturn = 0;

	iReturn = ::FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
						NULL, dwError,MAKELANGID(LANG_NEUTRAL,SUBLANG_SYS_DEFAULT),
						(LPTSTR) &lpBuffer,0,NULL);

	if(iReturn != 0) {
		Temp = lpBuffer;
		::LocalFree(lpBuffer);
	}
	else {
		Temp = "Unknown error";
	}

	return(Temp);
}




/*******************************************************************************/

#pragma comment (lib, "version.lib")

CModuleDetails::CModuleDetails(const HANDLE hProcessID,const HMODULE hModuleID)
        :
		m_hProcessHandle(hProcessID),
		m_hModuleHandle(hModuleID),
		m_ModuleName(""),
		m_FullFileName(""),
		m_BaseName(""),
		m_lFileSize(0),
		m_wLangID(0),
		m_wCharSet(0),
		m_Comments(""),
		m_CompanyName(""),
		m_FileDescription(""),
		m_FileVersion(""),
		m_InternalName(""),
		m_LegalCopyright(""),
		m_LegalTrademarks(""),
		m_OriginalFilename(""),
		m_PrivateBuild(""),
		m_ProductName(""),
		m_ProductVersion(""),
		m_SpecialBuild(""),
		m_dwError(0)
{
	char			cBuffer[MAX_PATH];
	char*			pVersionInfo = NULL;
	DWORD			dwVersionSize = 0;
	DWORD			dwResult;
	DWORD			dwVersionHandle;
	void*			pFixedPointer = NULL;
	UINT			uFixedLength = 0;
	TRANSLATIONS*	pTranslations = NULL;
	//CFileStatus		FileStatus;

	//Get the module details based on the handle passed
	memset(cBuffer,0x00,MAX_PATH);
	dwResult = ::GetModuleBaseName(m_hProcessHandle,m_hModuleHandle,(LPWSTR)cBuffer,MAX_PATH-1);
	if(dwResult == 0) {
		m_dwError = ::GetLastError();
	}
	else {
		m_BaseName = cBuffer;
	}

	// Module Filename Full path
	memset(cBuffer,0x00,MAX_PATH);
	dwResult = ::GetModuleFileNameEx(m_hProcessHandle,m_hModuleHandle,(LPWSTR)cBuffer,MAX_PATH-1);
	if(dwResult == 0) {
		m_dwError = ::GetLastError();
	}
	else {
		m_FullFileName = cBuffer;
		m_FullFileName.MakeUpper();
	}
	m_ModuleName = m_BaseName;
	m_ModuleName.MakeUpper();

	// Get the file details
	//CFile::GetStatus(m_FullFileName,FileStatus);
	//m_lFileSize = FileStatus.m_size;
	//m_FileDate = FileStatus.m_mtime;
	
	// Get the version information
	dwVersionSize = GetFileVersionInfoSize((LPWSTR)cBuffer,&dwVersionHandle);
	if (GetFileVersionInfoSize == 0) {
		m_dwError = ::GetLastError();
	}
	else {
		pVersionInfo = (char *)malloc(dwVersionSize);
		if (pVersionInfo == NULL) {
			m_dwError = ::GetLastError();
		}
		else {
			if (::GetFileVersionInfo((LPWSTR)cBuffer,dwVersionHandle,dwVersionSize,pVersionInfo) == FALSE) {
				m_dwError = ::GetLastError();
			}
			else {
				if(::VerQueryValue(pVersionInfo,_T("\\VarFileInfo\\Translation"),&pFixedPointer,&uFixedLength)==FALSE) {
					m_dwError = ::GetLastError();
				}
				else {
					pTranslations = (TRANSLATIONS *)pFixedPointer;

					m_wLangID = pTranslations[0].m_wLangID;
					m_wCharSet = pTranslations[0].m_wCharSet;

					m_Comments = GetVersionString(pVersionInfo,"Comments");
					m_CompanyName = GetVersionString(pVersionInfo,"CompanyName");
					m_FileDescription = GetVersionString(pVersionInfo,"FileDescription");
					m_FileVersion = GetVersionString(pVersionInfo,"FileVersion");
					m_InternalName = GetVersionString(pVersionInfo,"InternalName");
					m_LegalCopyright = GetVersionString(pVersionInfo,"LegalCopyright");
					m_LegalTrademarks = GetVersionString(pVersionInfo,"LegalTrademarks");
					m_OriginalFilename = GetVersionString(pVersionInfo,"OriginalFilename");
					m_PrivateBuild = GetVersionString(pVersionInfo,"PrivateBuild");
					m_ProductName = GetVersionString(pVersionInfo,"ProductName");
					m_ProductVersion = GetVersionString(pVersionInfo,"ProductVersion");
					m_SpecialBuild = GetVersionString(pVersionInfo,"SpecialBuild");
				}
			}
		}
		ASSERT(pVersionInfo!=NULL);
		free(pVersionInfo);
	}
}


CModuleDetails::CModuleDetails(CModuleDetails&)
{
}

CModuleDetails::CModuleDetails()
{
}

CModuleDetails::~CModuleDetails()
{
}


CString	CModuleDetails::GetVersionString(char *pVersionInfo, char *pKey)
{
	void *pFixedPointer = NULL;
	UINT uFixedLength = 0;
	char cQuery[64];
	const char * VersionFormat = "\\StringFileInfo\\%04x%04x\\%s";

	sprintf(cQuery, VersionFormat, m_wLangID, m_wCharSet, pKey);
	if( ::VerQueryValue(pVersionInfo, (LPCWSTR) cQuery, &pFixedPointer, &uFixedLength)==TRUE) {
		if(uFixedLength > 0) {
			// uFixedLength includes the trailling "\0"
			return(CString((char *)pFixedPointer,((int)uFixedLength)-1));
		}
		else {
			return(CString(""));
		}
	}
	else {
		m_dwError = ::GetLastError();
		return(CString(""));
	}
	return(CString(""));
}


BOOL CModuleDetails::HasFailed() const
{
	if(m_dwError != 0) {
		return(TRUE);
	}
	else {
		return(FALSE);
	}
}



CString	CModuleDetails::GetComments() const
{
	return(m_Comments);
}

CString	CModuleDetails::GetCompanyName() const
{
	return(m_CompanyName);
}

CString	CModuleDetails::GetFileDescription() const
{
	return(m_FileDescription);
}

CString	CModuleDetails::GetFileVersion() const
{
	return(m_FileVersion);
}

CString	CModuleDetails::GetInternalName() const
{
	return(m_InternalName);
}

CString	CModuleDetails::GetLegalCopyright() const
{
	return(m_LegalCopyright);
}

CString	CModuleDetails::GetLegalTrademarks() const
{
	return(m_LegalTrademarks);
}

CString	CModuleDetails::GetOriginalFilename() const
{
	return(m_OriginalFilename);
}

CString	CModuleDetails::GetPrivateBuild() const
{
	return(m_PrivateBuild);
}

CString	CModuleDetails::GetProductName() const
{
	return(m_ProductName);
}

CString	CModuleDetails::GetProductVersion() const
{
	return(m_ProductVersion);
}

CString	CModuleDetails::GetSpecialBuild() const
{
	return(m_SpecialBuild);
}

CString	CModuleDetails::GetFullFileName() const
{
	return(m_FullFileName);
}

CString	CModuleDetails::GetModuleName() const
{
	return(m_ModuleName);
}

ULONGLONG CModuleDetails::GetFileSize() const
{
	return(m_lFileSize);
}

//CTime CModuleDetails::GetFileDate() const{	return(m_FileDate);}

DWORD CModuleDetails::GetLastError() const
{
	return(m_dwError);
}

/*
HICON CModuleDetails::GetAssociatedIcon()
{
	SHFILEINFO shFileInfo = { 0 };
    VERIFY( SHGetFileInfo( m_FullFileName, 
                           FILE_ATTRIBUTE_NORMAL, 
                           &shFileInfo, 
                           sizeof( shFileInfo ), 
                           SHGFI_SMALLICON | SHGFI_ICON | SHGFI_USEFILEATTRIBUTES ));

	return shFileInfo.hIcon;
}
*/

BOOL CModuleDetails::IsProcessTrue()
{
	return m_bIsProcess;
}

BOOL CModuleDetails::TerminateProcess()
{
	if(IsProcessTrue())
	{
		HANDLE hProcess=OpenProcess(PROCESS_TERMINATE, FALSE, pProcessID);
		return ::TerminateProcess(hProcess,1);
	}
	else
		return FALSE;
}
