// recommended includes in stdafx.h (or in the precompiled header, to be precise):
// windows.h, tchar.h, string, vector, algorithm, exception, sstream, iomanip

#include "stdafx.h"
#define FKSEC_NO_AUTO_INCLUDES 1
#include "fksec.h"
#include "ex.h"
#include "sid.h"
#include <lm.h>
#include "strconv.h"

using namespace fksec;

#pragma warning(disable : 4995)
#pragma warning(disable : 4996) // turn off warning C4995/C4996: '_sntprintf': name was marked as #pragma deprecated

/*! \file sid.h
\brief implements the fksec::sid class */


// --- ctors/dtor ---

/*! The initial state of *this is invalid.
\exception none */
sid::sid()
{
	Init();
	ClearPSID();
}


/*! *this becomes a copy of the argument, including its valid state.
\param s the sid to copy
\exception none */
sid::sid( const sid &s )
{
	Init();
	ClearPSID();
	isValid = s.isValid;
	if ( isValid )
	{
		sia = s.sia;
		subAuthCount = s.subAuthCount;
		memcpy( subAuth, s.subAuth, sizeof subAuth );
	}
}


/*! Parses the SID and stashes its contents in *this.  Note that the 
sid class does not wrap the PSID; you can free the PSID after 
this function returns.
\param s pointer to the NT-formatted SID to copy into *this
\exception none */
sid::sid( const PSID s )
{
	DWORD i;

	Init();
	ClearPSID();
	if ( IsValidSid( s ) )
	{
		isValid = true;
		sia = *::GetSidIdentifierAuthority( s );
		subAuthCount = (DWORD) *GetSidSubAuthorityCount( s );
		if ( subAuthCount < lenof( subAuth ) )
		{
			for ( i = 0; i < subAuthCount; ++ i )
				subAuth[i] = *GetSidSubAuthority( s, i );
		}
		else
			throw NEWEX( errTooManySubAuths, "sid::sid( PSID ): more than SID_MAX_SUB_AUTHORITIES subauthorities in the SID" );
	}
	else
		throw NEWEX( errInvalidSid, "sid::sid( PSID ): invalid SID passed in" );
}


/*! The ctor first tries to parse the string as a text-SID ("S-1-5-...");
if that fails, it calls LookupAccountName() with server == NULL 
(i.e., it asks the local machine to find the name).  If this works,
the SID is stored in *this.
\param name a pointer to a null-terminted string naming either a valid
account like \c felixk, \c MVPS\\felixk, or \c felixk@nt.mvps.org, or
a SID in string form, such as \c S-1-5-18
\exception errNoMemory
\exception errInvalidSid (both from LookupName()) */
sid::sid( const TCHAR *name )
{
	Init();
	ClearPSID();

	try { ConvertFromStringSid( name ); }
	catch ( ex *e )
	{
		if ( e->GetErr() != errInvalidSid )
		{
			e->FKSECADDHOP( "sid::sid( name )" );
			throw;
		}

		// not a string SID, so let's try something else
		delete e;
		try { LookupName( /* server */ 0, name ); }
		RETHROWEX( "sid::sid( name )" )
	}
}


/*! This ctor works in a manner similar to ::AllocateAndInitializeSid(), 
except that it allocates no memory.
\param newsia a SID_IDENTIFIER_AUTHORITY value (struct { byte[6] })
\param nSubAuths number of the following subauthorities that are valid and should be used
\param subAuthN the Nth subauthority value
\exception none */
sid::sid( SID_IDENTIFIER_AUTHORITY newsia, DWORD nSubAuths,
	DWORD subAuth0 /* = 0 */, DWORD subAuth1 /* = 0 */, DWORD subAuth2 /* = 0 */,
	DWORD subAuth3 /* = 0 */, DWORD subAuth4 /* = 0 */, DWORD subAuth5 /* = 0 */,
	DWORD subAuth6 /* = 0 */, DWORD subAuth7 /* = 0 */ )
{
	Init();
	ClearPSID();
	sia = newsia;
	subAuthCount = nSubAuths;
	subAuth[0] = subAuth0;
	subAuth[1] = subAuth1;
	subAuth[2] = subAuth2;
	subAuth[3] = subAuth3;
	subAuth[4] = subAuth4;
	subAuth[5] = subAuth5;
	subAuth[6] = subAuth6;
	subAuth[7] = subAuth7;
	isValid = true;
}


/*! This ctor works in a manner similar to ::AllocateAndInitializeSid(), 
except that it allocates no memory, and that it uses a different format
for the \a newsia argument.
\param newsia a SID_IDENTIFIER_AUTHORITY value (expressed as an unsigned __int64)
\param nSubAuths number of the following subauthorities that are valid and should be used
\param subAuthN the Nth subauthority value
\exception none */
sid::sid( unsigned __int64 newsia, DWORD nSubAuths,
	DWORD subAuth0 /* = 0 */, DWORD subAuth1 /* = 0 */, DWORD subAuth2 /* = 0 */,
	DWORD subAuth3 /* = 0 */, DWORD subAuth4 /* = 0 */, DWORD subAuth5 /* = 0 */,
	DWORD subAuth6 /* = 0 */, DWORD subAuth7 /* = 0 */ )
{
	int i;
	Init();
	ClearPSID();
	// why so complicated? because sia's byte ordering is machine-independent,
	// while __int64 is not.  This code is endian-safe.
	for ( i = lenof( sia.Value ) - 1; i >= 0; -- i )
	{
		sia.Value[i] = newsia % 256UI64;
		newsia /= 256UI64;
	}
	subAuthCount = nSubAuths;
	subAuth[0] = subAuth0;
	subAuth[1] = subAuth1;
	subAuth[2] = subAuth2;
	subAuth[3] = subAuth3;
	subAuth[4] = subAuth4;
	subAuth[5] = subAuth5;
	subAuth[6] = subAuth6;
	subAuth[7] = subAuth7;
	isValid = true;
}


/*! The dtor releases any internal buffers (like the one that the
object may have used for providing PSID conversion).
\exception none */
sid::~sid()
{
	ReleasePSID();
}



// --- assignment ---

/*! \param s the sid to crib from
\return a const reference to *this
\exception none */
const sid &sid::operator=( const sid &s )
{
	if ( this != &s )
	{
		ReleasePSID();
		isValid = s.isValid;
		if ( isValid )
		{
			sia = s.sia;
			subAuthCount = s.subAuthCount;
			memcpy( subAuth, s.subAuth, sizeof subAuth );
		}
	}

	return *this;
}


/*! Parses the SID and stashes its contents in *this.  Note that the 
sid class does not wrap the PSID; you can free the PSID after 
this function returns.
\param s a pointer to an NT-formatted SID
\return a const reference to *this.
\exception none */
const sid &sid::operator=( const PSID s )
{
	DWORD i;

	if ( havePSID && psid == s )
		return *this;

	ReleasePSID();
	Init();
	if ( ::IsValidSid( s ) )
	{
		isValid = true;
		sia = *::GetSidIdentifierAuthority( s );
		subAuthCount = (DWORD) *::GetSidSubAuthorityCount( s );
		if ( subAuthCount < lenof( subAuth ) )
		{
			for ( i = 0; i < subAuthCount; ++ i )
				subAuth[i] = *::GetSidSubAuthority( s, i );
		}
		else
			throw NEWEX( errTooManySubAuths,
				"sid::operator=( PSID ): more than SID_MAX_SUB_AUTHORITIES subauthorities in the SID" );
	}
	else
		throw NEWEX( errInvalidSid, "sid::operator=( PSID ): invalid SID passed in" );

	return *this;
}


/*! The operator first tries to parse the string as a text-SID ("S-1-5-...");
if that fails, it calls LookupAccountName() with server == NULL 
(i.e., it asks the local machine to find the name).  If this works,
the SID is stored in *this.
\param name a pointer to a null-terminted string naming either a valid
account like \c felixk, \c MVPS\\felixk, or \c felixk@nt.mvps.org, or
a SID in string form, such as \c S-1-5-18
\return a const reference to *this.
\exception errNoMemory
\exception errInvalidSid (both from LookupName()) */
const sid &sid::operator=( const TCHAR *name )
{
	ReleasePSID();
	Init();

	try { ConvertFromStringSid( name ); }
	catch ( ex *e )
	{
		if ( e->GetErr() != errInvalidSid )
		{
			e->FKSECADDHOP( "sid::operator=(TCHAR*)" );
			throw;
		}

		// invalid SID, let's try something different
		delete e;

		try { LookupName( /* server */ 0, name ); }
		RETHROWEX( "sid::operator=(TCHAR*)" )
	}


	return *this;
}



// --- conversions ---

/*! Creates an NT-formatted SID in storage internal to the object, and 
returns a pointer to that memory. The returned pointer is only 
guaranteed to be valid until the next method is invoked on the 
object.

Note: a PSID is essentially a typedef for a void*. This may lead to
conversions where you do not want them.
\return a const pointer to SID (PSID) which is typedef-ed as 
a const pointer to void.
\exception errInvalidSid
\exception errNoMemory */
sid::operator const PSID() const
{
	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::operator const PSID(): invalid SID" );

	try { MakePSID(); }
	RETHROWEX( "sid::operator const PSID(): MakePSID() failed" )

	return psid;
}



// --- comparisons ---

/*! Compares *this with r and returns the result.

The < operator compares by the following arbitrary ordering: If
*this has less subauthorities than r, *this is smaller. If *this
has more subauthorities than r, r is smaller. Else, if the
numerical value of this->sia is less than r.sia, *this is smaller;
if this->sia is higher than r.sia, r is smaller. If, after this,
the subauthority count and the SIA have proved equal, the lists
of subauthorities are compared left to right. The relation between
the first two unequal subauthorities determines the final result.
If no unequal subauthorities exist, the SIDs are equal, and the
result is false (since "==" implies "not <").
\param r the right-hand side sid for the comparison
\retval true if *this is "less" than r.
\retval false if *this is not "less" than r.
\exception errInvalidSid */
bool sid::operator<( const sid &r ) const
{
	DWORD i;
	__int64 tsia, rsia;

	if ( ! isValid || ! r.isValid )
		throw NEWEX( errInvalidSid, "sid::operator<( sid ): invalid SID" );

	tsia = GetSidIdentifierAuthority();
	rsia = r.GetSidIdentifierAuthority();
	if ( tsia < rsia )
		return true;
	if ( tsia > rsia )
		return false;

	if ( subAuthCount < r.subAuthCount )
		return true;
	if ( subAuthCount > r.subAuthCount )
		return false;

	for ( i = 0; i < subAuthCount; ++ i )
	{
		if ( subAuth[i] < r.subAuth[i] )
			return true;
		if ( subAuth[i] > r.subAuth[i] )
			return false;
	}

	return false;
}


/*! Compares *this with r and returns the result.

The == operator considers two SIDs (and sids) to be equal if and 
only if they have the same authority value, subauthority count, 
and subauthority lists.
\param r the right-hand side sid for the comparison
\retval true if *this is equal to r.
\retval false if *this is not equal to r.
\exception errInvalidSid */
bool sid::operator==( const sid &r ) const
{
	DWORD i;

	if ( ! isValid || ! r.isValid )
		throw NEWEX( errInvalidSid, "sid::operator==( sid ): invalid SID" );

	if ( subAuthCount != r.subAuthCount || 0 != memcmp( &sia, &r.sia, sizeof( sia ) ) )
		return false;

	for ( i = 0; i < subAuthCount; ++ i )
		if ( subAuth[i] != r.subAuth[i] )
			return false;

	return true;
}


/*! Compares *this with r and returns the result.

The != operator considers two SIDs (and sids) to be equal if and 
only if they have the same authority value, subauthority count, 
and subauthority lists.
\param r the right-hand side sid for the comparison
\retval true if *this is not equal to r.
\retval false if *this is equal to r.
\exception errInvalidSid */
bool sid::operator!=( const sid &r ) const
{
	DWORD i;

	if ( ! isValid || ! r.isValid )
		throw NEWEX( errInvalidSid, "sid::operator!=( sid ): invalid SID" );

	if ( subAuthCount != r.subAuthCount || 0 != memcmp( &sia, &r.sia, sizeof( sia ) ) )
		return true;

	for ( i = 0; i < subAuthCount; ++ i )
		if ( subAuth[i] != r.subAuth[i] )
			return true;

	return false;
}


/*! Compares the prefix of *this with the prefix of r and returns the result.

The method considers two SIDs (and sids) to be equal if and 
only if they have the same authority value, subauthority count, 
and subauthority lists, except for the last subauthority value,
which is ignored in both sid objects.
\param r the right-hand side sid for the comparison
\retval true if the sids have the same prefix.
\retval false if the sids do not have the same prefix
\exception errInvalidSid */
bool sid::EqualPrefix( const sid &r ) const
{
	DWORD i;

	if ( ! isValid || ! r.isValid )
		throw NEWEX( errInvalidSid, "sid::EqualPrefix(): invalid SID" );

	if ( subAuthCount != r.subAuthCount || 0 != memcmp( &sia, &r.sia, sizeof( sia ) ) )
		return false;

	for ( i = 0; i < subAuthCount - 1; ++ i )
		if ( subAuth[i] != r.subAuth[i] )
			return false;

	return true;
}



// --- utilities ---

/*! \return the number of bytes required for *this as an NT SID
\exception none */
DWORD sid::GetLength() const
{
	return ::GetSidLengthRequired( (byte) subAuthCount );
}


/*! \return the integer equivalent of the SIA, with proper byte ordering
\exception none */
__int64 sid::GetSidIdentifierAuthority() const
{
	unsigned __int64 r;

	// SIA is stored high byte first; we avoid platform
	// dependency by processing it byte for byte
	r = ( ( (unsigned __int64) sia.Value[0] ) << 40 ) |
		( ( (unsigned __int64) sia.Value[1] ) << 32 ) |
		( ( (unsigned __int64) sia.Value[2] ) << 24 ) |
		( ( (unsigned __int64) sia.Value[3] ) << 16 ) |
		( ( (unsigned __int64) sia.Value[4] ) <<  8 ) |
		( ( (unsigned __int64) sia.Value[5] )       );

	return (__int64) r;
}


/*! One of the uses for this method is getting a domain SID from 
a user or group SID.
\exception errInvalidSid */
void sid::RemoveLastRid()
{
	if ( ! isValid || subAuthCount == 0 )
		throw NEWEX( errInvalidSid, "sid::RemoveLastRid(): invalid SID" );

	ReleasePSID();
	-- subAuthCount;
	subAuth[subAuthCount] = 0;
}


/*! Given a domain SID and a user RID (some NetGroup*() functions 
return just those), this method can be used to build a full
SID for the user (or group).
\param rid the RID (subauthority value) to append to sid
\exception errInvalidSid
\exception errTooManySubAuths */
void sid::AppendSubAuthority( DWORD rid )
{
	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::AppendSubAuthority(): invalid SID" );

	if ( subAuthCount >= SID_MAX_SUB_AUTHORITIES )
		throw NEWEX( errTooManySubAuths, "sid::AppendSubAuthority(): already SID_MAX_SUB_AUTHORITIES in the SID" );

	ReleasePSID();
	subAuth[subAuthCount] = rid;
	++ subAuthCount;
}


/*! Note that subauthority index values range from 0 through 
GetSubAuthorityCount() - 1. This method can not be used to 
lengthen or truncate a sid.
\param index the zero-based index of the RID to be changed
\param rid the new value to be set for that RID
\exception errInvalidSid
\exception errInvalidSubAuthIndex */
void sid::SetSubAuthority( DWORD index, DWORD rid )
{
	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::SetSubAuthority(): invalid SID" );

	if ( index >= subAuthCount )
		throw NEWEX( errInvalidSubAuthIndex,
			"sid::SetSubAuthority(): invalid subauthority index" );

	ReleasePSID();
	subAuth[index] = rid;
}


/*! Note that subauthority index values range from 0 through 
GetSubAuthorityCount() - 1.
\param index the zero-based index of the RID to be retrieved
\return a DWORD with the index<sup>th</sup> subauthority value
\exception errInvalidSid
\exception errInvalidSubAuthIndex */
DWORD sid::GetSubAuthority( DWORD index ) const
{
	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::GetSubAuthority(): invalid SID" );

	if ( index >= subAuthCount )
		throw NEWEX( errInvalidSubAuthIndex,
			"sid::GetSubAuthority(): invalid subauthority index" );

	return subAuth[index];
}


/*! \return a DWORD with the sid's current subauthority count
\exception errInvalidSid */
DWORD sid::GetSubAuthorityCount() const
{
	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::GetSubAuthorityCount(): invalid SID" );

	return subAuthCount;
}


/*! If the sid is initialized, it builds an NT SID and runs it through
::IsValidSid(). If both tests are met, the sid is considered valid.
This function is guaranteed to never throw an exception.
\retval true if the sid is valid
\retval false if the sid is not initialized or does not pass ::IsValidSid()
\exception none */
bool sid::IsValid() const
{
	PSID p;

	if ( ! isValid )
		return false;

	try { p = MakePSID(); }
	catch ( ex *e )
	{
		delete e;
		return false;
	}

	if ( p == 0 )
		return false;

	return !! IsValidSid( p );
}


/*! SnuToText() looks up a short textual representation for the
SID_NAME_USE argument value. This method does not return localized
strings.
\param snu the SID_NAME_USE value for which a name is sought
\return a const TCHAR* to the description string, or to the string 
"*SNU?*" if the argument is an unknown SID_NAME_USE value.
\exception none */
const TCHAR *sid::SnuToText( SID_NAME_USE snu )
{
	static TCHAR *snuText[16] = { 0 };
	static const TCHAR *badSnuText = _T( "*SNU?*" );
	static bool snuTextInitialized = false;

	if ( ! snuTextInitialized )
	{
		snuTextInitialized = true;
		snuText[SidTypeUser]			= _T( "user" );
		snuText[SidTypeGroup]			= _T( "group" );
		snuText[SidTypeDomain]			= _T( "domain" );
		snuText[SidTypeAlias]			= _T( "alias" );
		snuText[SidTypeWellKnownGroup]	= _T( "well-known group" );
		snuText[SidTypeDeletedAccount]	= _T( "deleted" );
		snuText[SidTypeInvalid]			= _T( "invalid" );
		snuText[SidTypeUnknown]			= _T( "unknown" );
		snuText[SidTypeComputer]		= _T( "computer" );
	}

	if ( snu < (SID_NAME_USE) 1 || snu > lenof( snuText ) || snuText[snu] == 0 )
		return badSnuText;

	return snuText[snu];
}


/*! Produces a string representation of the sid object's contents 
in the same format as NT5's ::ConvertSidToStringSid(), but does
not rely on running under NT5.

If the sid is not currently valid, the returned string has the 
value "*invalid*". No exceptions are thrown.
\return an instance of fkstr (which maps to std::string or 
std::wstring, depending on the UNICODE setting) containing
the stringified sid.
\exception none */
fkstr sid::ConvertToStringSid() const
{
	// S-rev- + SIA + subauthlen*maxsubauth + terminator
	TCHAR buf[15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1];
	TCHAR *p = &buf[0];
	DWORD i;

	// Validate the binary SID.

	if ( ! IsValid() )
		return fkstr( _T( "*invalid*" ) );

	p += _sntprintf( p, &buf[lenof( buf )] - p, _T( "S-%lu-" ), SID_REVISION );

	if ( ( sia.Value[0] != 0 ) || ( sia.Value[1] != 0 ) )
		p += _sntprintf( p, &buf[lenof( buf )] - p, _T( "0x%02hx%02hx%02hx%02hx%02hx%02hx" ),
			(USHORT) sia.Value[0], (USHORT) sia.Value[1],
			(USHORT) sia.Value[2], (USHORT) sia.Value[3],
			(USHORT) sia.Value[4], (USHORT) sia.Value[5] );
	else
		p += _sntprintf( p, &buf[lenof( buf )] - p, _T( "%lu" ),
			(ULONG) ( sia.Value[5]       ) + (ULONG) ( sia.Value[4] << 8  ) +
			(ULONG) ( sia.Value[3] << 16 ) + (ULONG) ( sia.Value[2] << 24 ) );

	// Add SID subauthorities to the string.

	for ( i = 0; i < subAuthCount; ++ i )
		p += _sntprintf( p, &buf[lenof( buf )] - p, _T( "-%lu" ), subAuth[i] );

	return fkstr( buf );
}


/*! StoreSid() fills a client-allocated buffer with the NT-formatted 
SID corresponding to *this' contents, unless size is less than
needed; in that case, an exception is raised.
\param ps points to the (caller-allocated) buffer in which to place the NT-formatted SID
\param size is the size, in bytes, of the buffer provided by the caller
\exception errInvalidSid
\exception errBufferTooSmall */
void sid::StoreSid( PSID ps, DWORD size ) const
{
	DWORD i;

	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::StoreSid(): invalid SID" );

	i = GetLength();
	if ( size < i )
		throw new ex( _T( __FILE__ ), __LINE__, errBufferTooSmall,
			_T( "sid::StoreSid(): provided buffer is too small, ex::GetData() gives required size" ), 0, i );

	if ( InitializeSid( ps, &sia, (byte) subAuthCount ) )
		for ( i = 0; i < subAuthCount; ++ i )
			*GetSidSubAuthority( ps, i ) = subAuth[i];
	else
		throw NEWEX32( errInvalidSid,
			"sid::StoreSid(): InitializeSid() failed, see GetErrWin32()", GetLastError() );
}


/*! This method is the complement to ConvertToStringSid(). It attempts
to parse the format produced by that function and, if successful,
sets *this to the parsed SID. If unsuccessful, an exception is
raised, and the state of *this is unchanged.
\param stringsid a pointer to a null-terminated string representing
a SID, such as \c S-1-5-18
\exception errInvalidSid */
void sid::ConvertFromStringSid( const TCHAR *stringsid )
{
	// a string SID has the form
	// S-rev-sia-rid-rid...
	DWORD i;
	unsigned __int64 r;
	SID_IDENTIFIER_AUTHORITY tempsia = { 0 };
	DWORD rids[SID_MAX_SUB_AUTHORITIES];

	if ( stringsid == 0 )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (NULL)" );

	if ( *stringsid != _T( 's' ) && *stringsid != _T( 'S' ) )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (first char not 'S')" );

	++ stringsid; // skip 'S'

	if ( ! CvsGetUInt64( stringsid, r ) )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (cannot parse revision)" );
	if ( r != SID_REVISION )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (revision != SID_REVISION)" );

	if ( ! CvsGetUInt64( stringsid, r ) )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (cannot parse SIA)" );
	if ( r == 0 || r > 0xffffffffffffUI64 )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (SIA out of range)" );
	// SIA is stored high-byte first; to avoid machine dependency,
	// we fill it byte for byte
	for ( i = 0; i < lenof( tempsia.Value ); ++ i )
	{
		tempsia.Value[lenof( tempsia.Value ) - i - 1] = (byte) ( r & 0xff );
		r >>= 8;
	}

	for ( i = 0; i < SID_MAX_SUB_AUTHORITIES; ++ i )
	{
		if ( ! CvsGetUInt64( stringsid, r ) )
			break;
		if ( r > 0xffffffffUI64 )
			throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (RID out of range)" );
		rids[i] = (DWORD) r;
	}
	// we ran out of array space, or the SID was finished.
	// in either case, stringsid should point to a '\0'.

	if ( *stringsid != _T( '\0' ) )
		throw NEWEX( errInvalidSid, "sid::ConvertFromStringSid(): invalid SID (cannot parse RID, or trailing garbage in string)" );

	// we have a complete SID. Stash it.
	ReleasePSID();
	Init();
	sia = tempsia;
	subAuthCount = i;
	memcpy( subAuth, rids, subAuthCount * sizeof rids[0] );
	isValid = true;
}


/*! LookupName() uses ::LookupAccountName to query the named server
(local machine if server is NULL or points to an empty string) for
the SID of the account named. If successful, *this is set to this
SID, else an exception is raised.
\param server pointer to a null-terminated string containing the
server name to perform the lookup on. If server is
NULL or an empty string, the local computer is used
\param name pointer to a null-terminated string containing the account
name to look up, like \c felixk, \c MVPS\\felixk, or \c felixk@nt.mvps.org
\exception errNoMemory
\exception errInvalidSid */
void sid::LookupName( const TCHAR *server, const TCHAR *name )
{
	PSID ps;
	DWORD pslen, domlen;
	SID_NAME_USE snu;
	TCHAR domain[256];

	domlen = lenof( domain );
	pslen = GetSidLengthRequired( SID_MAX_SUB_AUTHORITIES );
	ps = new byte[pslen];
	if ( ps == 0 )
		throw NEWEX( errNoMemory, "sid::LookupName(): no memory for SID buffer" );

	ReleasePSID();
	if ( ::LookupAccountName( server, name, ps, &pslen, domain, &domlen, &snu ) )
		*this = ps;
	else
	{
		delete [] ps;
		throw NEWEX32( errInvalidSid, "sid::LookupName(): failed, see GetErrWin32()", GetLastError() );
	}

	delete [] ps;
}


/*! This method uses ::LookupAccountSid() to query the named server 
(local machine if server == NULL or points to an empty string) 
for the name and domain of the account represented by the sid.
\param server pointer to a null-terminated string containing the
server name to perform the lookup on. If server is
NULL or an empty string, the local computer is used
\param name writable reference to an fkstr to receive the account
name represented by *this
\param domain writable reference to an fkstr to receive the
domain of the account name represented by *this
\param anu writable reference to a SID_NAME_USE enum variable to
receive the type of the account represented by *this
\return no direct return; side effects: name, domain, snu changed 
if successful.
\exception errInvalidSid
\exception errNoMemory */
void sid::LookupSid( const TCHAR *server, fkstr &name, fkstr &domain, SID_NAME_USE &snu ) const
{
	PSID ps;
	DWORD rc, tempnamelen, tempdomainlen;
	TCHAR *tempname = 0, *tempdomain = 0;

	try { ps = MakePSID(); }
	RETHROWEX( "sid::lookupSid(): cannot generate NT-formatted SID" );

	if ( ps == 0 )
		throw NEWEX( errNoMemory, "sid::LookupSid(): no memory for SID buffer" );

	rc = 0; // assume all is well
	tempnamelen = tempdomainlen = 256;
	tempname = new TCHAR[tempnamelen];
	tempdomain = new TCHAR[tempdomainlen];
	if ( ! ::LookupAccountSid( server, ps, tempname, &tempnamelen,
		tempdomain, &tempdomainlen, &snu ) )
	{
		// it failed == buffers too small?
		rc = GetLastError();
		delete [] tempname;
		delete [] tempdomain;
		if ( rc == ERROR_INSUFFICIENT_BUFFER )
		{
			tempname = new TCHAR[tempnamelen];
			tempdomain = new TCHAR[tempdomainlen];
			if ( ! ::LookupAccountSid( server, ps, tempname, &tempnamelen,
				tempdomain, &tempdomainlen, &snu ) )
			{
				delete [] tempname;
				delete [] tempdomain;
				throw NEWEX32( errInvalidSid, "sid::LookupSid(): LookupAccountSid() failed, see GetErrWin32()", GetLastError() );
			}
		}
		else
			throw NEWEX32( errInvalidSid, "sid::LookupSid(): LookupAccountSid() failed, see GetErrWin32()", rc );
	}

	name = tempname;
	domain = tempdomain;

	delete [] tempname;
	delete [] tempdomain;
}


/*! This method finds out whether the SID is in the local SAM, 
whether it comes from the domain that this machine is a server 
of, or whether it is a "special" SID such as the ones in the 
BUILTIN domain.
\return a sid::SidType enumeration value representing the SID 
status.
\exception errInvalidSid
\exception errNoPrefixSid
\exception errTooManySubauths (from AppendSubAuthority() only) */
sid::SidType sid::LookupSidType()
{
	const SID_IDENTIFIER_AUTHORITY sec_nt_auth = SECURITY_NT_AUTHORITY;
	DWORD rc;
	byte *buf = 0;

	byte buf2[SID_MAX_SUB_AUTHORITIES * sizeof DWORD + sizeof SID_IDENTIFIER_AUTHORITY + sizeof DWORD];
	TCHAR refdom[256], dom[256];
	SID_NAME_USE snu;
	wchar_t *ws;
	sid temp;
	DWORD sidsize = sizeof buf2, refdomsize = lenof( refdom );

	if ( ! IsValid() )
		throw NEWEX( errInvalidSid, "sid::LookupSidType(): invalid SID" );

	if ( memcmp( &sia, &sec_nt_auth, sizeof sia ) != 0 )
		return stWellKnown;

	// for SECURITY_NT_AUTHORITY, we need to look at the first RID, too.
	if ( GetSubAuthorityCount() < 1 )
		throw NEWEX( errInvalidSid, "sid::LookupSidType(): invalid SID" );

	// local account?
	if ( GetSubAuthority( 0 ) == SECURITY_BUILTIN_DOMAIN_RID )
		return stWellKnown;

	// domain account?
	if ( GetSubAuthority( 0 ) == SECURITY_NT_NON_UNIQUE )
	{
		rc = NetUserModalsGet( 0, 2, &buf );
		if ( rc != ERROR_SUCCESS )
			throw NEWEX32( errNoPrefixSid, "sid::LookupSidType(): can't get local domain prefix", rc );

		try {
			if ( ( (USER_MODALS_INFO_2 *) buf )->usrmod2_domain_id == 0 )
				throw NEWEX( errNoPrefixSid, "sid::LookupSidType(): NUMG() returned a NULL PSID. Feh!" );

			temp = ( (USER_MODALS_INFO_2 *) buf )->usrmod2_domain_id;
			NetApiBufferFree( buf );
			buf = 0;
			temp.AppendSubAuthority( 0 );
			if ( EqualPrefix( temp ) )
				return stLocal;
			else
			{
				// it's not local; now check if the SID belongs to the domain
				// that we are a member of (if we are, that is).

				// first, find the domain name
				rc = NetWkstaGetInfo( 0, 100, &buf );
				if ( rc != ERROR_SUCCESS )
					throw NEWEX32( errNoPrefixSid, "sid::LookupSidType(): cannot get member domain name", rc );

				// so, are we a domain member in the first place?
				ws = (wchar_t *) ( (WKSTA_INFO_100 *) buf )->wki100_langroup;
				if ( ws == 0 || ws[0] == L'\0' )
				{
					NetApiBufferFree( buf );
					return stForeign;
				}

#ifdef UNICODE
				wcscpy( dom, ws );
#else
				wcstombs( dom, ws, sizeof dom );
#endif
				NetApiBufferFree( buf );
				buf = 0;

				// now, get the domain SID
				if ( ! LookupAccountName( 0, dom, buf2, &sidsize, refdom, &refdomsize, &snu ) )
					throw NEWEX32( errNoPrefixSid, "sid::LookupSidType(): cannot get member domain SID", GetLastError() );

				try {
					temp = buf2;
					temp.AppendSubAuthority( 0 );
					if ( EqualPrefix( temp ) )
						return stDomain;
					else
						return stForeign;
				}
				RETHROWEX( "sid::LookupSidType(): compare to domain acct prefix failed" )
			}
		}
		catch ( ex *e )
		{
			e->FKSECADDHOP( "sid::LookupSidType(): compare to machine acct prefix failed" );
			if ( buf != 0 )
				NetApiBufferFree( buf );
			throw;
		}
	}

	return stWellKnown;
}


/*! This method uses ::NetUserGetGroups & ::NetUserGetLocalGroups to retrieve
the list of groups that this user is a member of. The server to perform this
check on can optionally be specified (by default it is the local machine), the
server must be specified in UNC format, and remember to escape the \\'s 
(e.g. _T("\\\\\\\\someServer").
Note that the Net* Functions are Unicode only; if this code is built as ANSI
it will perform the relevant conversions required, but obviously building the
Unicode version is recommended.
\param bIncludeGlobal	 controls whether the domain global groups are queried.
\param bIncludeLocal	 controls whether the server local groups are queried.
\param bIncludeIndirect for local groups, if this is specified, the list includes any
groups that the user is an indirect member (by virtual of
being a member of a global group, which is a member of a local group)
\param server specify the UNC name of the server to run the query against.
\return a SidList of the groups.
\exception errInvalidSid
\exception errNoMemory 
\exception errNetApi32 */
SidList sid::MemberOf(bool bIncludeGlobal, bool bIncludeLocal, bool bIncludeIndirect, const TCHAR *server)
{
	SidList list ;
	fkstr name, domain ;
	SID_NAME_USE snu ; 
	DWORD cRead, cTotal ;
	NET_API_STATUS rc = NERR_Success ;
	try {
		LookupSid( server, name, domain, snu );
	}
	RETHROWEX("sid::MemberOf(): sid::LookupSid() failed")
	
#ifdef _UNICODE
		LPCWSTR szName = name.c_str() ;
		LPCWSTR szServer = server ;
#else
		// the Net* API is UNICODE only, so for ANSI builds, we need to mess around with W2A & A2W conversions
		std::auto_ptr<WCHAR> swName ( Ansi2Unicode(name.c_str()) ) ;
		LPCWSTR szName = swName.get() ;
		LPCWSTR szServer = NULL ;
		std::auto_ptr<WCHAR> swServer ;
		if ( server )
		{
			swServer = Ansi2Unicode(server) ;
			szServer = swServer.get() ;
		}
		static const int CONV_BUFF_LEN = UNCLEN + GNLEN + 2 ;
		char szConvBuffer[CONV_BUFF_LEN] ;
#endif

	if ( bIncludeGlobal )
	{
		GROUP_USERS_INFO_0 * buf = 0 ;
		rc = ::NetUserGetGroups( szServer, szName, 0, (BYTE **)&buf, MAX_PREFERRED_LENGTH, &cRead, &cTotal ) ;
		if ( NERR_Success == rc )
		{
			list.reserve(cTotal) ;
			sid s ;
			while ( cRead-- )
			{
				// arrrghh, the PSID constructor / assignment operator, means the compiler won't pick an ANSI/UNICODE mismatch here
				#ifdef _UNICODE
					s = buf[cRead].grui0_name ;
				#else
					WideCharToMultiByte ( CP_ACP, 0 , buf[cRead].grui0_name, -1, szConvBuffer, CONV_BUFF_LEN, NULL, NULL ) ;
					s = szConvBuffer ;
				#endif
				list.push_back(s) ;
			}
			NetApiBufferFree(buf) ;
			buf = 0 ;
		}
		else
			throw NEWEX32( errNetApi32, "sid::MemberOf(): NetUserGetGroups() failed, see GetErrWin32()", rc ) ;
	}

	if ( bIncludeLocal )
	{
		LOCALGROUP_USERS_INFO_0 * buf = 0 ;
		rc = ::NetUserGetLocalGroups(szServer, szName, 0, bIncludeIndirect ? LG_INCLUDE_INDIRECT : 0, (BYTE **)&buf, MAX_PREFERRED_LENGTH, &cRead, &cTotal ) ;
		if ( NERR_Success == rc )
		{
			list.reserve(list.size() + cTotal ) ;
			sid s ;
			while ( cRead-- )
			{
				#ifdef _UNICODE
					s = buf[cRead].lgrui0_name ;
				#else
					WideCharToMultiByte ( CP_ACP, 0 , buf[cRead].lgrui0_name, -1, szConvBuffer, CONV_BUFF_LEN, NULL, NULL ) ;
					s = szConvBuffer ;
				#endif
				list.push_back(s);
			}
			NetApiBufferFree(buf) ;
			buf = 0 ;
		}
		else
			throw NEWEX32 ( errNetApi32, "sid::MemberOf(): NetUserGetLocalGroups() failed, see GetErrWin32()", rc ) ;
	}
	return list ;
}


/*! This method uses ::NetLocalGroupGetMembers or ::NetGroupGetUsers to retrieve
the list of members for this group. The server to perform this
check on can optionally be specified (by default it is the local machine), the
server must be specified in UNC format, and remember to escape the \\'s 
(e.g. _T("\\\\\\\\someServer").
Note that the Net* Functions are Unicode only; if this code is built as ANSI
it will perform the relevant conversions required, but obviously building the
Unicode version is recommended.
\param server specify the UNC name of the server to run the query against.
\return a SidList of the group members
\exception errInvalidSid
\exception errNoMemory 
\exception errNetApi32 */
SidList sid::Members(const TCHAR *server)
{
	SidList list ;
	fkstr name, domain ;
	SID_NAME_USE snu ; 
	DWORD cRead, cTotal ;
	NET_API_STATUS rc = NERR_Success ;
	BYTE * buf = 0 ;
	try {
		LookupSid( server, name, domain, snu );
	}
	RETHROWEX("sid::MemberOf(): sid::LookupSid() failed")

#ifdef _UNICODE
		LPCWSTR szName = name.c_str() ;
		LPCWSTR szServer = server ;
#else
		// the Net* API is UNICODE only 
		std::auto_ptr<WCHAR> swName = Ansi2Unicode(name.c_str()) ;
		LPCWSTR szName = swName.get() ;
		std::auto_ptr<WCHAR> swServer ;
		LPCWSTR szServer = NULL ;
		if ( server )
		{
			swServer = Ansi2Unicode(server) ;
			szServer = swServer.get() ;
		}
		static const int CONV_BUFF_LEN = UNCLEN + GNLEN + 2 ;
		char szConvBuffer[CONV_BUFF_LEN] ;
#endif

	if ( SidTypeAlias == snu )
	{
		LOCALGROUP_MEMBERS_INFO_0 * buf = 0 ;
		rc = ::NetLocalGroupGetMembers ( szServer, szName, 0, (BYTE **)&buf, MAX_PREFERRED_LENGTH, &cRead, &cTotal, NULL ) ;
		if ( NERR_Success == rc )
		{
			list.reserve(cTotal) ;
			while ( cRead-- )
				list.push_back(buf[cRead].lgrmi0_sid) ;
		}
		else
			throw NEWEX32 ( errNetApi32, "sid::Members(): NetLocalGroupGetMembers failed, see GetErrWin32()", rc) ;
	}
	else
	{
		GROUP_USERS_INFO_0  * buf = 0 ;
		rc = ::NetGroupGetUsers ( szServer, szName, 0, (BYTE **)&buf, MAX_PREFERRED_LENGTH, &cRead, &cTotal, NULL ) ;
		if ( NERR_Success == rc ) 
		{
			list.reserve(list.size() + cTotal) ;
			sid s ;
			while ( cRead-- )
			{
				#ifdef _UNICODE
					s = buf[cRead].grui0_name ;
				#else
					WideCharToMultiByte ( CP_ACP, 0 , buf[cRead].grui0_name, -1, szConvBuffer, CONV_BUFF_LEN, NULL, NULL ) ;
					s = szConvBuffer ;					
				#endif
				list.push_back(s) ;
			}
			NetApiBufferFree(buf) ;
			buf = 0 ;
		}
		else
			throw NEWEX32 ( errNetApi32, "sid::Members(): NetGroupGetUsers() failed, see GetErrWin32()", rc ) ;
	}

	return list ;
}



// --- inserters ---

/*! Note that fkostream is a typedef for either std::ostream or 
std::wostream, depending on the UNICODE setting.
\param o a reference to an ostream or wostream to insert the sid into
\param s a reference to a sid to insert
\return the stream reference \a o
\exception none */
fkostream &fksec::operator<<( fkostream &o, const sid &s )
{
	fkstr name, domain;
	SID_NAME_USE snu;

	o << _T( "[" ) + s.ConvertToStringSid() + _T( "]" );

	try { s.LookupSid( 0, name, domain, snu ); }
	catch ( ex *e )
	{
		// this didn't work too well. Don't display names, then.
		domain.erase();
		name.erase();
		delete e;
	}

	if ( ! domain.empty() || ! name.empty() )
	{
		o << _T( " (" );
		if ( ! domain.empty() )
			o << domain << _T( "\\" );
		o << name << _T( ", " ) << s.SnuToText( snu ) << _T( ")" );
	}

	return o;
}



// --- helpers ---

/*! \excption none */
void sid::Init()
{
	isValid = false;
	memset( &sia, '\0', sizeof sia );
	subAuthCount = 0;
	memset( subAuth, '\0', sizeof subAuth );
}


/*! This method does not release memory allocated for psid. 
Use with care.
\exception none */
void sid::ClearPSID() const
{
	havePSID = false;
	psid = 0;
}


/*! \exception none */
void sid::ReleasePSID() const
{
	if ( havePSID )
	{
		delete [] (byte *) psid;
		psid = 0;
		havePSID = false;
	}
}


/*! CvsGetUInt64() expects str to point at a string consisting of 
a hyphen and a number. The number itself may be decimal (default), 
octal (if there is a leading zero), or hex (leading zero followed 
by a lower- or uppercase 'x'). The method advances str past the
characters it has successfully read.

The return value is false if either the input string's syntax 
does not match the method's expectations, or if the number (or 
the part following the base-prefix, if any) has no convertible 
digits. Otherwise, the return value is true, and the unsigned 
__int64 reference r stores the result.
\param str reference to a pointer to the string to be converted.
After conversion, the pointer will be advanced to reflect the
converted characters.
\param r a reference to an unsigned __int64 in which to store
the conversion result
\retval true if a number was successfully converted, in which 
case str points at the first unconverted character, and r holds 
the result
\retval false if a syntax error was encountered.
\exception none */
bool sid::CvsGetUInt64( const TCHAR *&str, unsigned __int64 &r )
{
	DWORD base = 10, d;
	const TCHAR *startOfNumber;
	static byte value[256] = { 0 };

	if ( str == 0 || *str != _T( '-' ) )
		return false;

	if ( value[0] == 0 ) // array not yet initialized
	{
		memset( value, '\xff', sizeof value );
		for ( d = '0'; d <= '9'; ++ d )
			value[d] = (byte) d - '0';
		for ( d = 'A'; d <= 'F'; ++ d )
			value[d | 0x20] = value[d] = (byte) d - '7';
	}

	r = 0;
	++ str;
	if ( *str == _T( '0' ) )
	{
		base = 8;
		++ str;
		if ( *str == _T( 'x' ) || *str == _T( 'X' ) )
		{
			base = 16;
			++ str;
		}
	}

	startOfNumber = str;
	for ( ; ; )
	{
		d = value[(DWORD) (byte) *str]; // would hate to have an o-o-b index
		if ( d >= base )
			break;
		r = r * base + (unsigned __int64) d;
		++ str;
	}

	// no digits converted?
	// if base != 10, we have seen a leading zero ... which, in this case,
	// was not a base prefix but the entire number. Not an error!
	if ( str == startOfNumber && base == 10 )
		return false;

	return true;
}



/*! MakePSID() takes no action if havePSID is already true. If 
havePSID is false, the method allocates a buffer for a SID and 
fills it with the SID components in *this. The member psid is 
set to the address of the buffer, and havePSID is set to true.
\return the value of psid, pointing to the SID.
\exception errInvalidSid
\exception errNoMemory */
PSID sid::MakePSID() const
{
	if ( ! isValid )
		throw NEWEX( errInvalidSid, "sid::MakePSID(): invalid SID" );

	if ( ! havePSID )
	{
		DWORD i;

		psid = (PSID) new byte[GetLength()];
		if ( psid == 0 )
			throw NEWEX( errNoMemory, "sid::MakePSID(): no memory for SID buffer" );

		if ( InitializeSid( psid, &sia, (byte) subAuthCount ) )
			for ( i = 0; i < subAuthCount; ++ i )
				*GetSidSubAuthority( psid, i ) = subAuth[i];
		else
		{
			delete [] (byte *) psid;
			psid = 0;
			throw NEWEX( errInvalidSid, "sid::MakePSID(): invalid SID" );
		}

		havePSID = true;
	}

	return psid;
}



//! S-1-0-0 null SID
const sid sid::sidNull( 0, 1, 0 );
//! S-1-1-0 World (Everyone)
const sid sid::sidWorld( 1, 1, 0 );
//! S 1-2-0 Local
const sid sid::sidLocal( 2, 1, 0 );
//! S-1-3-0 Creator Owner
const sid sid::sidCreatorOwner( 3, 1, 0 );
//! S-1-3-1 Creator Group
const sid sid::sidCreatorGroup( 3, 1, 1 );
//! S-1-3-2 Creator Owner Server
const sid sid::sidCreatorOwnerServer( 3, 1, 2 );
//! S-1-3-3 Creator Group Server
const sid sid::sidCreatorGroupServer( 3, 1, 3 );
//! S-1-5- prefix for built-in accounts and groups
const sid sid::sidNtAuthority( 5, 0 );
//! S-1-5-1 Dialup users
const sid sid::sidDialup( 5, 1, 1 );
//! S-1-5-2 Network logons
const sid sid::sidNetwork( 5, 1, 2 );
//! S-1-5-3 Batch logons
const sid sid::sidBatch( 5, 1, 3 );
//! S-1-5-4 Interactive logons
const sid sid::sidInteractive( 5, 1, 4 );
//! S-1-5-5- prefix for logon session SIDs, requires two more RIDs
const sid sid::sidLogon( 5, 1, 5 );
//! S-1-5-6 Service logons
const sid sid::sidService( 5, 1,6  );
//! S-1-5-7 Anonymous (null session)
const sid sid::sidAnonymousLogon( 5, 1, 7 );
//! S-1-5-8 Logon by proxy
const sid sid::sidProxy( 5, 1, 8 );
//! S-1-5-9 DC account
const sid sid::sidServerLogon( 5, 1, 9 );
//! S-1-5-10 Self (current caller)
const sid sid::sidSelf( 5, 1, 10 );
//! S-1-5-11 Authenticated users (as opposed to World)
const sid sid::sidAuthenticated( 5, 1, 11 );
//! S-1-5-12 Indicates a restricted token
const sid sid::sidRestricted( 5, 1, 12 );
//! S-1-5-13 Token from Terminal Server
const sid sid::sidTerminalServer( 5, 1, 13 );
//! S-1-5-18 LocalSystem (NT AUTHORITY\SYSTEM)
const sid sid::sidLocalSystem( 5, 1, 18 );
//! S-1-5-21- prefix for domains, domain accounts, etc.
const sid sid::sidNonUnique( 5, 1, 21 );
//! S-1-5-32 built-in domain
const sid sid::sidBuiltin( 5, 1, 32 );
//! S-1-5-32-500 local admin account
const sid sid::sidLocalAdministrator( 5, 2, 32, 500 );
//! S-1-5-32-501 local guest account
const sid sid::sidLocalGuest( 5, 2, 32, 501 );
//! S-1-5-32-544 Administrators
const sid sid::sidLocalAdministrators( 5, 2, 32, 544 );
//! S-1-5-32-545 Users
const sid sid::sidLocalUsers( 5, 2, 32, 545 );
//! S-1-5-32-546 Guests
const sid sid::sidLocalGuests( 5, 2, 32, 546 );
//! S-1-5-32-547 Power Users
const sid sid::sidLocalPowerUsers( 5, 2, 32, 547 );
//! S-1-5-32-548 Account Operators
const sid sid::sidLocalAccountOperators( 5, 2, 32, 548 );
//! S-1-5-32-549 System Operators
const sid sid::sidLocalSystemOperators( 5, 2, 32, 549 );
//! S-1-5-32-550 Print Server Operators
const sid sid::sidLocalPrintOperators( 5, 2, 32, 550 );
//! S-1-5-32-551 Backup Operators
const sid sid::sidLocalBackupOperators( 5, 2, 32, 551 );
//! S-1-5-32-552 File replicator account
const sid sid::sidLocalReplicator( 5, 2, 32, 552 );
//! S-1-5-32-553 Ras servers
const sid sid::sidLocalRasServers( 5, 2, 32, 553 );
//! S-1-5-32-554 SID used to validate Net*() access from NT4 machines
const sid sid::sidLocalPreW3KCompAccess( 5, 2, 32, 554 );
