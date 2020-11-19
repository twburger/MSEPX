// proclistP.h
#ifndef PROCLISTP_H
#define PROCLISTP_H 1

#include <Psapi.h>
#include <atlstr.h>
#include <vector>

#define MAXCOUNT 4000


class CModuleDetails; // Forward declaration

class CEnumProcessList
{
 public:
    CEnumProcessList();
	CEnumProcessList(DWORD dwProcessID);
    ~CEnumProcessList();

	BOOL GetModuleVersion(CString ModuleName,CString &VersionString);
	BOOL SearchProcessOrModule(CString ModuleName,CModuleDetails* pModuleData);
	BOOL HasFailed();
	CModuleDetails* GetFirst();
	CModuleDetails* GetNext();
	DWORD LastError();
	static CString FormatError(DWORD dwError);

private:
	std::vector<CModuleDetails*> m_ModulesList;
	std::vector<CModuleDetails*>::iterator m_ModulesListIterNext, m_ModulesListIterUtil;
	BOOL			m_bRead;
	HANDLE			m_hProcess;
	DWORD			m_dwError;
};



struct TRANSLATIONS {
	WORD m_wLangID;
	WORD m_wCharSet;
};

class CModuleDetails
{
    public :
	    BOOL TerminateProcess();
	    BOOL IsProcessTrue();
	BOOL m_bIsProcess;
	HICON GetAssociatedIcon();

	 CModuleDetails(const HANDLE hProcessID,const HMODULE hModuleID);
	 CModuleDetails();
     ~CModuleDetails();

	 BOOL HasFailed() const;

	///////////////////////////////////////////////////////////////////////////////
	//
	//	CModule Data "properties"
	//
	   // version details
   	 VS_FIXEDFILEINFO GetVersion();
     CString	GetComments() const;
     CString	GetCompanyName() const;
     CString	GetFileDescription() const;
     CString	GetFileVersion() const;
     CString	GetInternalName() const;
	 CString	GetProductName() const;
     CString	GetProductVersion() const;
	 CString	GetLegalCopyright() const;
     CString	GetLegalTrademarks() const;
     CString	GetOriginalFilename() const;
     CString	GetPrivateBuild() const;
     CString	GetSpecialBuild() const;
     CString	GetFullFileName() const;
     CString	GetModuleName() const;
     ULONGLONG		GetFileSize() const;
     //CTime		GetFileDate() const;
     DWORD		GetLastError() const;
	 DWORD		pProcessID;

 protected:

 private:

	CModuleDetails(CModuleDetails &rCopy);
	CString	GetVersionString(char *pVersionInfo, char *pKey);

	HANDLE				m_hProcessHandle;
	HMODULE				m_hModuleHandle;
	CString				m_ModuleType;
	CString				m_ModuleName;
	CString				m_FullFileName;
	CString				m_BaseName;
	

	// File Data
	//long		m_lFileSize;
	ULONGLONG		m_lFileSize;
	//CTime		m_FileDate;

	// Language Block Information
	WORD		m_wLangID;
	WORD		m_wCharSet;

	// Version Data
	CString		m_Comments;
	CString		m_CompanyName;
	CString		m_FileDescription;
	CString		m_FileVersion;
	CString		m_InternalName;
	CString		m_LegalCopyright;
	CString		m_LegalTrademarks;
	CString		m_OriginalFilename;
	CString		m_PrivateBuild;
	CString		m_ProductName;
	CString		m_ProductVersion;
	CString		m_SpecialBuild;
	DWORD		m_dwError;
};


#endif // PROCLIST_H

