// recommended includes in stdafx.h (or in the precompiled header, to be precise):
// windows.h, tchar.h, string, vector, algorithm, exception, sstream, iomanip

#include "stdafx.h"
#define FKSEC_NO_AUTO_INCLUDES 1
#include "fksec.h"
#include "ex.h"
#include "priv.h"
#include "sid.h"
#include "ace.h"
#include "acl.h"
#include "sd.h"
#include "apis.h"


/*! \file apis.cpp
\brief implements wrappers for the functions that get and set
security descriptors from and on securable objects.
\author Simon Fell \<simon@zaks.demon.co.uk\>
\author Felix Kasza \<felixk@mvps.org\>
\author see http://mvps.org/win32/security/fksec.html */


namespace fksec {
	static const int initialBufferSize = 2048;
} // namespace fksec

using fksec::errUnreadableSD;
using fksec::errUnwritableSD;
using fksec::ex;
using fksec::priv;
using fksec::sd;



/*! GetFileSecurity() mimics the behaviour of the NT API function 
of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a pre-allocated buffer (and its size) for a 
  SECURITY_DESCRIPTOR, the function accepts a reference to an 
  fksec::sd and fills it in
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param filename the name of the file for which you wish to 
retrieve the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be retrieved; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object which is to receive the 
security descriptor.
\exception errUnreadableSd
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::GetFileSecurity( const TCHAR *filename, SECURITY_INFORMATION whichParts, sd &sd )
{
	SECURITY_DESCRIPTOR *psd;
	DWORD needed, rc;
	bool haveRetriedPrivilege = false, haveRetriedSize = false;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::GetFileSecurity(): cannot identify SeSecurityPrivilege" )

	needed = initialBufferSize;
	psd = (SECURITY_DESCRIPTOR *) new byte[initialBufferSize];

	for ( ; ; )
	{
		if ( ::GetFileSecurity( filename, whichParts, psd, needed, &needed ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_INSUFFICIENT_BUFFER && ! haveRetriedSize )
		{
			delete [] (byte *) psd;
			psd = (SECURITY_DESCRIPTOR *) new byte[needed];
			haveRetriedSize = true;
		}
		else if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable or all OK
	}

	if ( rc == 0 )
		sd = psd;

	delete [] (byte *) psd;

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnreadableSD, "fksec::GetFileSecurity(): cannot read SD, see ex::GetErrWin32()", rc );
}



/*! SetFileSecurity() mimics the behaviour of the NT API function 
of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a SECURITY_DESCRIPTOR, the function accepts 
  a reference to an fksec::sd
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param filename the name of the file for which you wish to 
set the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be set; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object representing the 
security descriptor to be applied.
\exception errUnwritableSd
\exception errInvalidAcl if the acl contains object ACE's
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::SetFileSecurity( const TCHAR *filename, SECURITY_INFORMATION whichParts, const sd &sd )
{
	DWORD rc;
	bool haveRetriedPrivilege = false;
	bool oldSecPrivState = false;
	priv secPriv;

	if ( sd.GetDacl().IsObjectACL() )
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetFileSecurity(): cannot write SD, DACL contains object ACE's" ) ;
	if ( sd.GetSacl().IsObjectACL() ) 
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetFileSecurity(): cannot write SD, SACL contains object ACE's" ) ;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::SetFileSecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		if ( ::SetFileSecurity( filename, whichParts, (SECURITY_DESCRIPTOR *) sd ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable or all OK
	}

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnwritableSD, "fksec::SetFileSecurity(): cannot write SD, see ex::GetErrWin32()", rc );
}



/*! GetKernelObjectSecurity() mimics the behaviour of the NT API 
function of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a pre-allocated buffer (and its size) for a 
  SECURITY_DESCRIPTOR, the function accepts a reference to an 
  fksec::sd and fills it in
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param h a handle to the kernel object for which you wish to 
retrieve the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be retrieved; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object which is to receive the 
security descriptor.
\exception errUnreadableSd
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::GetKernelObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, sd &sd )
{
	SECURITY_DESCRIPTOR *psd;
	DWORD needed, rc;
	bool haveRetriedPrivilege = false, haveRetriedSize = false;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::GetKernelObjectSecurity(): cannot identify SeSecurityPrivilege" )

	needed = initialBufferSize;
	psd = (SECURITY_DESCRIPTOR *) new byte[initialBufferSize];

	for ( ; ; )
	{
		if ( ::GetKernelObjectSecurity( h, whichParts, psd, needed, &needed ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_INSUFFICIENT_BUFFER && ! haveRetriedSize )
		{
			delete [] (byte *) psd;
			psd = (SECURITY_DESCRIPTOR *) new byte[needed];
			haveRetriedSize = true;
		}
		else if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable or just fine
	}

	if ( rc == 0 )
		sd = psd;

	delete [] (byte *) psd;

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnreadableSD, "fksec::GetKernelObjectSecurity(): cannot read SD, see ex::GetErrWin32()", rc );
}



/*! SetKernelObjectSecurity() mimics the behaviour of the NT API function 
of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a SECURITY_DESCRIPTOR, the function accepts 
  a reference to an fksec::sd
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param h a handle to the kernel object for which you wish to 
set the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be set; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object representing the 
security descriptor to be applied.
\exception errUnwritableSd
\exception errInvalidAcl if the acl contains object ACE's
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::SetKernelObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, const sd &sd )
{
	DWORD rc;
	bool haveRetriedPrivilege = false;
	bool oldSecPrivState = false;
	priv secPriv;

	if ( sd.GetDacl().IsObjectACL() )
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetKernelObjectSecurity(): cannot write SD, DACL contains object ACE's" ) ;
	if ( sd.GetSacl().IsObjectACL() ) 
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetKernelObjectSecurity(): cannot write SD, SACL contains object ACE's" ) ;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::SetKernelObjectSecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		if ( ::SetKernelObjectSecurity( h, whichParts, (SECURITY_DESCRIPTOR *) sd ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnwritableSD, "fksec::SetKernelObjectSecurity(): cannot write SD, see ex::GetErrWin32()", rc );
}



/*! GetUserObjectSecurity() mimics the behaviour of the NT API 
function of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a pre-allocated buffer (and its size) for a 
  SECURITY_DESCRIPTOR, the function accepts a reference to an 
  fksec::sd and fills it in
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param h a handle to the user object for which you wish to 
retrieve the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be retrieved; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object which is to receive the 
security descriptor.
\exception errUnreadableSd
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::GetUserObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, sd &sd )
{
	SECURITY_DESCRIPTOR *psd;
	DWORD needed, rc;
	bool haveRetriedPrivilege = false, haveRetriedSize = false;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::GetUserObjectSecurity(): cannot identify SeSecurityPrivilege" )

	needed = initialBufferSize;
	psd = (SECURITY_DESCRIPTOR *) new byte[initialBufferSize];

	for ( ; ; )
	{
		if ( ::GetUserObjectSecurity( h, &whichParts, psd, needed, &needed ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_INSUFFICIENT_BUFFER && ! haveRetriedSize )
		{
			delete [] (byte *) psd;
			psd = (SECURITY_DESCRIPTOR *) new byte[needed];
			haveRetriedSize = true;
		}
		else if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( rc == 0 )
		sd = psd;

	delete [] (byte *) psd;

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnreadableSD, "fksec::GetUserObjectSecurity(): cannot read SD, see ex::GetErrWin32()", rc );
}



/*! SetUserObjectSecurity() mimics the behaviour of the NT API function 
of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a SECURITY_DESCRIPTOR, the function accepts 
  a reference to an fksec::sd
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param h a handle to the user object for which you wish to 
set the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be set; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object representing the 
security descriptor to be applied.
\exception errUnwritableSd
\exception errInvalidAcl if the acl contains object ACE's
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::SetUserObjectSecurity( HANDLE h, SECURITY_INFORMATION whichParts, const sd &sd )
{
	DWORD rc;
	bool haveRetriedPrivilege = false;
	bool oldSecPrivState = false;
	priv secPriv;

	if ( sd.GetDacl().IsObjectACL() )
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetUserObjectSecurity(): cannot write SD, DACL contains object ACE's" ) ;
	if ( sd.GetSacl().IsObjectACL() ) 
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetUserObjectSecurity(): cannot write SD, SACL contains object ACE's" ) ;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::SetUserObjectSecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		if ( ::SetUserObjectSecurity( h, &whichParts, (SECURITY_DESCRIPTOR *) sd ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnwritableSD, "fksec::SetUserObjectSecurity(): cannot write SD, see ex::GetErrWin32()", rc );
}



/*! GetServiceObjectSecurity() mimics the behaviour of the NT API 
function of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a pre-allocated buffer (and its size) for a 
  SECURITY_DESCRIPTOR, the function accepts a reference to an 
  fksec::sd and fills it in
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param hSvc an SCM handle to the servoce entry for which you 
wish to retrieve the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be retrieved; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object which is to receive the 
security descriptor.
\exception errUnreadableSd
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::QueryServiceObjectSecurity( SC_HANDLE hSvc, SECURITY_INFORMATION whichParts, sd &sd )
{
	SECURITY_DESCRIPTOR *psd;
	DWORD needed, rc;
	bool haveRetriedPrivilege = false, haveRetriedSize = false;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::QueryServiceObjectSecurity(): cannot identify SeSecurityPrivilege" )

	needed = initialBufferSize;
	psd = (SECURITY_DESCRIPTOR *) new byte[initialBufferSize];

	for ( ; ; )
	{
		if ( ::QueryServiceObjectSecurity( hSvc, whichParts, psd, needed, &needed ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_INSUFFICIENT_BUFFER && ! haveRetriedSize )
		{
			delete [] (byte *) psd;
			psd = (SECURITY_DESCRIPTOR *) new byte[needed];
			haveRetriedSize = true;
		}
		else if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( rc == 0 )
		sd = psd;

	delete [] (byte *) psd;

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnreadableSD, "fksec::QueryServiceObjectSecurity(): cannot read SD, see ex::GetErrWin32()", rc );
}



/*! SetServiceObjectSecurity() mimics the behaviour of the NT API function 
of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a SECURITY_DESCRIPTOR, the function accepts 
  a reference to an fksec::sd
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param hSvc an SCM handle to the service for which you wish to 
set the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be set; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object representing the 
security descriptor to be applied.
\exception errUnwritableSd
\exception errInvalidAcl if the acl contains object ACE's
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::SetServiceObjectSecurity( SC_HANDLE hSvc, SECURITY_INFORMATION whichParts, const sd &sd )
{
	DWORD rc;
	bool haveRetriedPrivilege = false;
	bool oldSecPrivState = false;
	priv secPriv;

	if ( sd.GetDacl().IsObjectACL() )
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetServiceObjectSecurity(): cannot write SD, DACL contains object ACE's" ) ;
	if ( sd.GetSacl().IsObjectACL() ) 
		throw NEWEX(fksec::errInvalidAcl, "fksec::SetServiceObjectSecurity(): cannot write SD, SACL contains object ACE's" ) ;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::SetServiceObjectSecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		if ( ::SetServiceObjectSecurity( hSvc, whichParts, (SECURITY_DESCRIPTOR *) sd ) )
			rc = 0;
		else
			rc = GetLastError();

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnwritableSD, "fksec::SetServiceObjectSecurity(): cannot write SD, see ex::GetErrWin32()", rc );
}



/*! RegGetKeySecurity() mimics the behaviour of the NT API 
function of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and 
  SetLastError() but are thrown as exceptions
- Instead of a pre-allocated buffer (and its size) for a 
  SECURITY_DESCRIPTOR, the function accepts a reference to an 
  fksec::sd and fills it in
- It automatically enables SeSecurityPrivilege, if a first 
  attempt at calling the NT function results in an 
  ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param hk a handle to the registry key for which you wish to 
retrieve the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be retrieved; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object which is to receive the 
security descriptor.
\exception errUnreadableSd
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::RegGetKeySecurity( HKEY hk, SECURITY_INFORMATION whichParts, sd &sd )
{
	SECURITY_DESCRIPTOR *psd;
	DWORD needed, rc;
	bool haveRetriedPrivilege = false, haveRetriedSize = false;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::RegGetKeySecurity(): cannot identify SeSecurityPrivilege" )

	needed = initialBufferSize;
	psd = (SECURITY_DESCRIPTOR *) new byte[initialBufferSize];

	for ( ; ; )
	{
		rc = ::RegGetKeySecurity( hk, whichParts, psd, &needed );

		if ( rc == ERROR_INSUFFICIENT_BUFFER && ! haveRetriedSize )
		{
			delete [] (byte *) psd;
			psd = (SECURITY_DESCRIPTOR *) new byte[needed];
			haveRetriedSize = true;
		}
		else if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( rc == 0 )
		sd = psd;

	delete [] (byte *) psd;

	if ( haveRetriedPrivilege ) // did we mess with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnreadableSD, "fksec::RegGetKeySecurity(): cannot read SD, see ex::GetErrWin32()", rc );
}



/*! RegSetKeySecurity() mimics the behaviour of the NT API function 
of the same name, with only a few changes. These are:
- Errors are not indicated by a FALSE return value and
  SetLastError() but are thrown as exceptions
- Instead of a SECURITY_DESCRIPTOR, the function accepts
  a reference to an fksec::sd
- It automatically enables SeSecurityPrivilege, if
  a first attempt at calling the NT function results in
  an ERROR_PRIVILEGE_NOT_HELD

Note that the function takes a reference to an fksec::sd as its
last argument.
\param hk a handle to the registry key for which you wish to 
set the security descriptor
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be set; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object representing the 
security descriptor to be applied.
\exception errUnwritableSd
\exception errInvalidAcl if the acl contains object ACE's
\exception additionally any that other fksec classes 
may throw (unlikely, and usually the result of a bug of mine) */
void fksec::RegSetKeySecurity( HKEY hk, SECURITY_INFORMATION whichParts, const sd &sd )
{
	DWORD rc;
	bool haveRetriedPrivilege = false;
	bool oldSecPrivState = false;
	priv secPriv;

	if ( sd.GetDacl().IsObjectACL() )
		throw NEWEX(fksec::errInvalidAcl, "fksec::RegSetKeySecurity(): cannot write SD, DACL contains object ACE's" ) ;
	if ( sd.GetSacl().IsObjectACL() ) 
		throw NEWEX(fksec::errInvalidAcl, "fksec::RegSetKeySecurity(): cannot write SD, SACL contains object ACE's" ) ;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::RegSetKeySecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		rc = ::RegSetKeySecurity( hk, whichParts, (SECURITY_DESCRIPTOR *) sd );

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable or all OK
	}

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnwritableSD, "fksec::RegSetKeySecurity(): cannot write SD, see ex::GetErrWin32()", rc );
}



/*! AdsGetObjectSecurity() reads the security descriptor for an object stored in the
Windows 2000 Active Directory. As with the other functions contained here, if 
the first attempt returns ERROR_PRIVILEGE_NOT_HELD, then it is retried with 
SeSecurityPrivilege enabled.

\param AdsPath is the X.500 Format name of the object you which to fetch the SD for
e.g. "OU=test2,OU=test1,DC=simonfell,DC=com". Whilst the documentation for 
GetNamedSecurityInfo (the underlying API call used) indicates that you can specify 
the name in the ADSI Path format ( e.g. "\\simonfell.com\test1\test2" ), I've yet to
see it work. 
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be retrieved; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object which is to receive the 
security descriptor.
\exception errUnreadableSd
\exception additionally any that other fksec classes may throw (unlikely)
\author Simon Fell \<simon@zaks.demon.co.uk\> */
void fksec::AdsGetObjectSecurity ( const TCHAR *AdsPath, SECURITY_INFORMATION whichParts, sd &sd )
{
	PSECURITY_DESCRIPTOR psd = 0 ;
	DWORD rc;
	bool haveRetriedPrivilege = false ;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::AdsGetObjectSecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		rc = GetNamedSecurityInfo ( const_cast<TCHAR *>(AdsPath), SE_DS_OBJECT_ALL, whichParts, NULL, NULL, NULL, NULL, (void **)&psd ) ;

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable
	}

	if ( 0 == rc )
	{
		sd = (SECURITY_DESCRIPTOR *)psd;
		LocalFree ( psd ) ;
	}
	
	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnreadableSD, "fksec::AdsGetObjectSecurity(): cannot read SD, see ex::GetErrWin32()", rc );
}



/*! AdsSetObjectSecurity() sets the security descriptor on an object stored in the
Windows 2000 Active Direcotry. As with the other functions contained here, if 
the first attempt returns ERROR_PRIVILEGE_NOT_HELD, then it is retried with 
SeSecurityPrivilege enabled.

\param AdsPath is the X.500 Format name of the object you which to fetch the SD for
e.g. "OU=test2,OU=test1,DC=simonfell,DC=com". Whilst the documentation for 
GetNamedSecurityInfo (the underlying API call used) indicates that you can specify 
the name in the ADSI Path format ( e.g. "\\simonfell.com\test1\test2" ), I've yet to
see it work. 
\param whichParts a set of bits, ORed together, indicating which 
elements of the security descriptor should be set; valid 
bits are, as of 24 Dec 1999: \c DACL_SECURITY_INFORMATION, 
\c GROUP_SECURITY_INFORMATION, \c OWNER_SECURITY_INFORMATION, 
\c SACL_SECURITY_INFORMATION. NT5 also defines the following: 
\c PROTECTED_DACL_SECURITY_INFORMATION, \c PROTECTED_SACL_SECURITY_INFORMATION, 
\c UNPROTECTED_DACL_SECURITY_INFORMATION, \c UNPROTECTED_SACL_SECURITY_INFORMATION.
\param sd a reference to the sd object representing the 
security descriptor to be applied.
\exception errUnwritableSd
\exception additionally any that other fksec classes may throw (unlikely)
\author Simon Fell \<simon@zaks.demon.co.uk\> */
void fksec::AdsSetObjectSecurity ( const TCHAR *AdsPath, SECURITY_INFORMATION whichParts, const sd &sd )
{
	DWORD rc;
	bool haveRetriedPrivilege = false;
	bool oldSecPrivState = false;
	priv secPriv;

	try { secPriv = _T( "SeSecurityPrivilege" ); }
	RETHROWEX( "fksec::AdsSetObjectSecurity(): cannot identify SeSecurityPrivilege" )

	for ( ; ; )
	{
		rc = SetNamedSecurityInfo ( const_cast<TCHAR *>(AdsPath), SE_DS_OBJECT_ALL, whichParts, sd.GetOwnerSid(), sd.GetGroupSid(), sd.GetDacl(), sd.GetSacl() ) ;

		if ( rc == ERROR_PRIVILEGE_NOT_HELD && ! haveRetriedPrivilege )
		{
			try { oldSecPrivState = secPriv.Enable(); }
			catch ( ex *e ) { delete e; }
			haveRetriedPrivilege = true;
		}
		else
			break; // unrecoverable or all OK
	}

	if ( haveRetriedPrivilege ) // did we fuck with the privilege?
	{
		try { secPriv.SetState( oldSecPrivState ); }
		catch ( ex *e ) { delete e; } // just ignore errors here
	}

	if ( rc )
		throw NEWEX32( errUnwritableSD, "fksec::AdsSetObjectSecurity(): cannot write SD, see ex::GetErrWin32()", rc );
}
