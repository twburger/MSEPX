// fksec.h: This file pulls in all the other bits and pieces that make up the fksec namespace.

/*! \file fksec.h
\brief \#include this file from your sources */



#if ! defined( AFX_FKSEC_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_FKSEC_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


#pragma comment( lib, "kernel32.lib" )
#pragma comment( lib, "advapi32.lib" )
#pragma comment( lib, "user32.lib" )
#pragma comment( lib, "ole32.lib" )


#if ( defined( UNICODE ) != defined( _UNICODE ) )
#error UNICODE and _UNICODE must either both be #defined, or neither of them may be #defined.
#endif

#if ( defined( UNICODE ) == defined( _MBCS ) )
#error Only one of _UNICODE and _MBCS may be #defined.
#endif


#ifndef _WINDOWS_
#include <windows.h>
#endif // ! _WINDOWS_

#ifndef _INC_TCHAR
#include <tchar.h>
#endif

#ifndef _EXCEPTION_
#include <exception>
#endif // ! _EXCEPTION_

#ifndef _STRING_
#include <string>
#endif // ! _STRING_

#ifndef _VECTOR_
#include <vector>
#endif // ! _VECTOR_

#ifndef _ALGORITHM_
#include <algorithm>
#endif // ! _ALGORITHM_

#ifndef _OSTREAM_
#include <ostream>
#endif // ! _SSTREAM_

#ifndef _IOMANIP_
#include <iomanip>
#endif // ! _IOMANIP_

#ifndef __ACCESS_CONTROL_API__
#include <aclapi.h>
#endif // ! __ACCESS_CONTROL_API__



#ifndef lenof
/*! \brief computes the size of an array in elements.  Do not use on pointers!
\return the number of elements in array \a x. */
#define lenof(x) (sizeof (x)/sizeof ((x)[0]))
#endif



/*! \brief The fksec namespace contains all identifiers, except macros, declared by this class library. */
namespace fksec {

#ifdef _UNICODE
	//! fkstr is a synonym for the ANSI string in the ambient character size
	typedef std::wstring fkstr;
	//! fkostream is a synonym for the ANSI ostream in the ambient character size
	typedef std::wostream fkostream;
#else
	//! fkstr is a synonym for the ANSI string in the ambient character size
	typedef std::string fkstr;
	//! fkostream is a synonym for the ANSI ostream in the ambient character size
	typedef std::ostream fkostream;
#endif

} // namespace fksec



// fake some constants for NT 4 headers
#ifndef PROTECTED_DACL_SECURITY_INFORMATION
#define PROTECTED_DACL_SECURITY_INFORMATION 0x80000000L
#endif

#ifndef PROTECTED_SACL_SECURITY_INFORMATION
#define PROTECTED_SACL_SECURITY_INFORMATION 0x40000000L
#endif

#ifndef UNPROTECTED_DACL_SECURITY_INFORMATION
#define UNPROTECTED_DACL_SECURITY_INFORMATION 0x20000000L
#endif

#ifndef UNPROTECTED_SACL_SECURITY_INFORMATION
#define UNPROTECTED_SACL_SECURITY_INFORMATION 0x10000000L
#endif

#ifndef SE_GROUP_RESOURCE
#define SE_GROUP_RESOURCE 0x20000000L
#endif


#ifndef ADS_RIGHT_DS_CREATE_CHILD
#define ADS_RIGHT_DS_CREATE_CHILD 1
#endif


#ifndef FKSEC_NO_AUTO_INCLUDES
#include "ex.h"
#include "priv.h"
#include "sid.h"
#include "ace.h"
#include "acl.h"
#include "sd.h"
#include "token.h"
#include "apis.h"
#include "strconv.h"
#endif



#endif // ! defined( AFX_FKSEC_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
