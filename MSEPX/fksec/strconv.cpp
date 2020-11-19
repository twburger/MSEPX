#include "stdafx.h"
#define FKSEC_NO_AUTO_INCLUDES 1
#include "fksec.h"
#include "strconv.h"

/*! \file strconv.cpp
\brief implemenation of some general string manipulation functions.
\author Simon Fell \<simon@zaks.demon.co.uk\> */


/*! Takes an ANSI string, and returns a Unicode string. 
this is mainly needed for calls to NetApi32, which are Unicode only
\param psz a standard NULL terminated ANSI string
\return a Unicode char string, wrapped in a std::auto_ptr, which will free
the string memory when it goes out of scope */
std::auto_ptr<WCHAR> fksec::Ansi2Unicode(const char * psz)
{
	int cb = MultiByteToWideChar ( CP_ACP, 0, psz, -1, NULL, 0 ) ;
	std::auto_ptr<WCHAR> szdest ( new WCHAR [cb] ) ;
	MultiByteToWideChar ( CP_ACP, 0, psz, -1, szdest.get(), cb ) ;
	return szdest ;
}


/*! takes a Unicode string, and returns an ANSI string. 
this is mainly needed for calls to NetApi32, which are Unicode only.
\param psz a standard NULL terminated Unicode string
\return an ANSI char string, wrapped in a std::auto_ptr, which will free
the string memory when it goes out of scope */
std::auto_ptr<char> fksec::Unicode2Ansi(const WCHAR * psz)
{
	int cb = WideCharToMultiByte ( CP_ACP, 0, psz, -1, NULL, 0, NULL, NULL ) ;
	std::auto_ptr<char> szdest ( new char[cb] ) ;
	WideCharToMultiByte ( CP_ACP, 0 , psz, -1, szdest.get(), cb, NULL, NULL ) ;
	return szdest ;
}


/*! this inserts the standard text representation of a GUID into the stream.
e.g. {BF967ABA-0DE6-11D0-A285-00AA003049E2} */
fksec::fkostream &fksec::operator<<( fksec::fkostream &o, const GUID &g)
{
	WCHAR szguid[50] ;
	StringFromGUID2(g, szguid, sizeof(szguid)) ;
#ifdef _UNICODE
	o << szguid ;
#else
	std::auto_ptr<char> pszguid = Unicode2Ansi(szguid) ;
	o << pszguid.get() ;
#endif

	return o ;
}
