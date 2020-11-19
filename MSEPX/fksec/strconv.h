#if ! defined( AFX_STRCONV_H__3834ED95_1DD9_4438_A62D_8230C9BB545F__INCLUDED_ )
#define AFX_STRCONV_H__3834ED95_1DD9_4438_A62D_8230C9BB545F__INCLUDED_
#pragma once

/*! \file strconv.h
\brief declares some general string manipulation functions.
\author Simon Fell \<simon@zaks.demon.co.uk\> */

namespace fksec {

  	//! converts an ANSI string into a Unicode string
	std::auto_ptr<WCHAR> Ansi2Unicode(const char * psz );

	//! converts a Unicode string into an ANSI string
	std::auto_ptr<char> Unicode2Ansi(const WCHAR * psz) ;

	//! GUID inserter
	fkostream & operator << ( fkostream &o, const GUID &g );
}

#endif // ! defined( AFX_STRCONV_H__3834ED95_1DD9_4438_A62D_8230C9BB545F__INCLUDED_ )