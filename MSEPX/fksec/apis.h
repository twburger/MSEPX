// apis.h: DO NOT include this file. #include fksec.h instead!



#if ! defined( AFX_APIS_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_APIS_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


/*! \file apis.h
\brief declares wrappers for the functions that get and set
security descriptors from and on securable objects.
\author Simon Fell \<simon@zaks.demon.co.uk\>
\author Felix Kasza \<felixk@mvps.org\>
\author see http://mvps.org/win32/security/fksec.html
*/


namespace fksec {

	// functions that extract and set SDs from/to securable objects

	//! retrieves a file's security descriptor
	void GetFileSecurity( const TCHAR *filename, SECURITY_INFORMATION whichParts, sd &sd );

	//! sets a file's security descriptor
	void SetFileSecurity( const TCHAR *filename, SECURITY_INFORMATION whichParts, const sd &sd );

	//! retrieves a kernel object's security descriptor
	void GetKernelObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, sd &sd );

	//! sets a kernel object's security descriptor
	void SetKernelObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, const sd &sd );

	//! retrieves a user object's security descriptor
	void GetUserObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, sd &sd );

	//! sets a user object's security descriptor
	void SetUserObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, const sd &sd );

	//! retrieves a service's security descriptor
	void QueryServiceObjectSecurity( SC_HANDLE hSvc, SECURITY_INFORMATION whichParts, sd &sd );

	//! sets a service's security descriptor
	void SetServiceObjectSecurity( SC_HANDLE hSvc, SECURITY_INFORMATION whichParts, const sd &sd );

	//! retrieves a registry key's security descriptor
	void RegGetKeySecurity( HKEY hk, SECURITY_INFORMATION whichParts, sd &sd );

	//! sets a registry key's security descriptor
	void RegSetKeySecurity( HKEY hk, SECURITY_INFORMATION whichParts, const sd &sd );

	//! retrieves an Active Directory Object's security descriptor
	void AdsGetObjectSecurity ( const TCHAR *AdsPath, SECURITY_INFORMATION whichParts, sd &sd ) ;

	//! sets an Active Directory object's security descriptor
	void AdsSetObjectSecurity ( const TCHAR *AdsPath, SECURITY_INFORMATION whichParts, const sd &sd ) ;

} // namespace fksec



#endif // ! defined( AFX_APIS_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
