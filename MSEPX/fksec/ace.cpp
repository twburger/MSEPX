// recommended includes in stdafx.h (or in the precompiled header, to be precise):
// windows.h, tchar.h, string, vector, algorithm, exception, sstream, iomanip

#include "stdafx.h"
#define FKSEC_NO_AUTO_INCLUDES 1
#include "fksec.h"
#include "ex.h"
#include "sid.h"
#include "ace.h"
#include "strconv.h"

using namespace fksec;


/*! \file ace.cpp
\brief implements the fksec::ace class */


/*! \sa GetAceSortOrder()
\sa SetAceSortOrder() */
ace::AceSortOrder ace::currentAceSortOrder = asoDefault;



// --- ctors/dtor ---

/*! \exception none */
ace::ace()
  :	aceType( 0 ),
	aceFlags( 0 ),
	aceMask( 0 ),
	aceInheritance( 0 ),
	aceSid(),
	haveAceType( false ),
	haveAceMask( false ),
	haveAceFlags( false ),
	haveAceInheritance( false ),
	aceObjectFlags( 0 ),
	aceObjectTypeGUID( GUID_NULL ),
	aceInheritedObjectTypeGUID( GUID_NULL )
{
	ClearPACE();
}


/*! \param a the ace to be copied
\exception none */
ace::ace( const ace &a )
  :	aceType( a.aceType ),
	aceFlags( a.aceFlags ),
	aceMask( a.aceMask ),
	aceInheritance( a.aceInheritance ),
	aceSid( a.aceSid ),
	haveAceType( a.haveAceType ),
	haveAceMask( a.haveAceMask ),
	haveAceFlags( a.haveAceFlags ),
	haveAceInheritance( a.haveAceInheritance ),
	aceObjectFlags( a.aceObjectFlags ),
	aceObjectTypeGUID( a.aceObjectTypeGUID ),
	aceInheritedObjectTypeGUID( a.aceInheritedObjectTypeGUID )
{
	ClearPACE();
}


/*! \param a pointer to an NT-formatted ACE
\exception none */
ace::ace( const void *a )
  :	aceObjectFlags( 0 ),
	aceObjectTypeGUID( GUID_NULL ),
	aceInheritedObjectTypeGUID( GUID_NULL )
{
	ClearPACE();
	InitFromPACE( a );
}


/*! \param type the type of ace to construct; the most common values are
\c ACCESS_ALLOWED_ACE_TYPE, \c ACCESS_DENIED_ACE_TYPE, and
\c SYSTEM_AUDIT_ACE_TYPE
\param flags a set of bits specifying whether a system audit ACE triggers
on a successful access, a failed access, or both; can be \c
SUCCESSFUL_ACCESS_ACE_FLAG, \c FAILED_ACCESS_ACE_FLAG, both ORed together,
or none
\param inheritance a set of bits defining the ACE's behaviour; too complex
to go into here.  You may or any of these constants together: \c
OBJECT_INHERIT_ACE, \c CONTAINER_INHERIT_ACE, \c NO_PROPAGATE_INHERIT_ACE,
\c INHERIT_ONLY_ACE.  \c INHERITED_ACE may only be set by the OS.
\param mask a bit mask specifying which permissions this ACE will grant,
deny, or audit.  Possible values depend on the object type for which *this
is intended.
\param newSid the SID of the user or group whose access is being granted,
denied, or audited.  Thanks to the amazing versatility of the fksec::sid
class :-), you can also plug a PSID into this argument.
\param ObjectTypeGUID restricts, for object ACEs, the subobjects to which
the ACE applies.  This is orthogonal to the conventional parent/child
relationship.  For more information, see the page for \c ACCESS_ALLOWED_OBJECT_ACE
in the SDK documentation.
\param InheritedObjectTypeGUID is, if present, an additional restriction
on the kind of child eligible to inherit this ACE.
\exception errNoMemory
\exception errInvalidSid */
ace::ace( byte type, byte flags, byte inheritance,
	ACCESS_MASK mask, const sid &newSid, 
	const GUID &ObjectType /* = GUID_NULL */,
	const GUID &InheritedObjectType /* = GUID_NULL */ )
  :	aceType( type ),
	aceFlags( flags ),
	aceMask( mask ),
	aceInheritance( inheritance ),
	aceSid( newSid ),
	haveAceType( true ),
	haveAceMask( true ),
	haveAceFlags( true ),
	haveAceInheritance( true ),
	aceObjectFlags( 0 ),
	aceObjectTypeGUID( GUID_NULL ),
	aceInheritedObjectTypeGUID( GUID_NULL )
{
	ClearPACE();
	if ( ObjectType != GUID_NULL )
		SetObjectType(ObjectType) ;

	if ( InheritedObjectType != GUID_NULL )
		SetInheritedObjectType(InheritedObjectType) ;
}
	

/*! \exception none */
ace::~ace()
{
	ReleasePACE();
}



// --- assignment ---

// from another ace
/*! \param s the ace whose contents are to be copied
\return a const reference to *this
\exception none (but if s is invalid, *this will be, too) */
const ace &ace::operator=( const ace &s )
{
	if ( this != &s )
	{
		ReleasePACE();
		aceType = s.aceType;
		aceFlags = s.aceFlags;
		aceMask = s.aceMask;
		aceInheritance = s.aceInheritance;
		aceSid = s.aceSid;
		haveAceType = s.haveAceType;
		haveAceMask = s.haveAceMask;
		haveAceFlags = s.haveAceFlags;
		haveAceInheritance = s.haveAceInheritance;
		aceObjectFlags = s.aceObjectFlags ;
		aceObjectTypeGUID = s.aceObjectTypeGUID ;
		aceInheritedObjectTypeGUID = s.aceInheritedObjectTypeGUID ;
	}
	return *this;
}

// from PACE
/*! \param s pointer to an NT-formatted ACE; the pointer can be released as
soon as this function returns
\return a const reference to *this
\exception none (but if s is invalid, *this will be, too) */
const ace &ace::operator=( const void *s )
{
	if ( havePACE && pace == s )
		return *this;

	ReleasePACE();
	InitFromPACE(s);
	return *this;
}



// --- conversions ---

/*! The returned pointer must not be freed by the caller and is valid only
until the next call to a method of *this. (Actually, it is valid until
the next call that changes the state of *this, but who is counting?)
\result a pointer to an NT-formatted ACE.
\exception errInvalidAce
\exception errNoMemory
\exception errBufferTooSmall this one should never happen
\exception errInvalidSid */
ace::operator const void *() const
{
	const void *p;

	try { p = MakePACE(); }
	RETHROWEX( "ace::operator const void *()" )

	return p;
}



// --- comparisons ---

/*! \param r ace to compare *this against
\retval true if all of type, flags, inheritance, sid, and GUIDS (where used) are equal
\retval false otherwise
\exception errInvalidAce
\exception errInvalidSid */
bool ace::operator==( const ace &r )
{
	if ( ! IsValid() || ! r.IsValid() )
		throw NEWEX( errInvalidAce, "ace::operator==(): invalid ACE" );

	if ( aceType != r.aceType || aceFlags != r.aceFlags ||
		aceInheritance != r.aceInheritance || aceSid != r.aceSid ||
		aceObjectFlags != r.aceObjectFlags )
		return false;

	// examine object type GUID
	if ( ( aceObjectFlags & ACE_OBJECT_TYPE_PRESENT ) &&
		( aceObjectTypeGUID != r.aceObjectTypeGUID ) )
		return false;

	if ( ( aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT ) &&
		( aceInheritedObjectTypeGUID != r.aceInheritedObjectTypeGUID ) )
		return false;

	return true;
}


/*! \param r ace to compare *this against
\retval true if any of type, flags, inheritance, and sid are unequal
\retval false otherwise
\exception errInvalidAce
\exception errInvalidSid */
bool ace::operator!=( const ace &r )
{
	if ( ! IsValid() || ! r.IsValid() )
		throw NEWEX( errInvalidAce, "ace::operator!=(): invalid ACE" );

	if ( aceType != r.aceType || aceFlags != r.aceFlags ||
		aceInheritance != r.aceInheritance || aceSid != r.aceSid ||
		aceObjectFlags != r.aceObjectFlags )
		return true;

	if ( ( aceObjectFlags & ACE_OBJECT_TYPE_PRESENT ) &&
		aceObjectTypeGUID != r.aceObjectTypeGUID )
		return true;

	if ( ( aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT ) &&
		aceInheritedObjectTypeGUID != r.aceInheritedObjectTypeGUID )
		return true;

	return false;
}


// operator<() orders ACEs.  The algorithm is empirically derived,
// as none of the three I found in MS docs produces the same results
// as the GUI utilities of NT.
/*! In this context, "smaller" means "should be placed before", according to the
rules for ordering ACEs in an ACL.
\param r ace to compare *this against
\retval true if *this should come before r
\retval false otherwise
\exception errInvalidAce
\exception errInvalidSid
\anchor acesortrules */
bool ace::operator<( const ace &r )
{
	// the lt* flags determine the relation for single criterion;
	// their precedence is then determined by the ACE sort order.
	int ltAutoInherited; // == -1 if LHS.auto-i < RHS.auto-i (not auto-i goes first)
	int ltType; // == -1 if LHS.type < RHS.type (deny goes first)
	int ltSid; // == -1 if LHS.sid < RHS.sid
	int ltEffective; // == -1 if LHS.effective < RHS.effective (effective goes first)

	static int typeMap[ACCESS_MAX_MS_ACE_TYPE + 1] = { -1 }; // basically, a collating seq for ACE types

	// why do I init explicitly instead of setting up an initialized array?
	// Because this is easier to read. Bear with me.
	if ( typeMap[0] == -1 )
	{
		typeMap[ACCESS_DENIED_ACE_TYPE]				= 0;
		typeMap[ACCESS_DENIED_OBJECT_ACE_TYPE]		= 1;
		typeMap[ACCESS_ALLOWED_ACE_TYPE]			= 2;
		typeMap[ACCESS_ALLOWED_COMPOUND_ACE_TYPE]	= 3;
		typeMap[ACCESS_ALLOWED_OBJECT_ACE_TYPE]		= 4;
		typeMap[SYSTEM_AUDIT_ACE_TYPE]				= 5;
		typeMap[SYSTEM_ALARM_ACE_TYPE]				= 6;
		typeMap[SYSTEM_AUDIT_OBJECT_ACE_TYPE]		= 7;
		typeMap[SYSTEM_ALARM_OBJECT_ACE_TYPE]		= 8;
	}

	if ( ! haveAceType || aceType >= lenof( typeMap ) ||
		! r.haveAceType || r.aceType >= lenof( typeMap ) )
		throw NEWEX( errInvalidAce, "ace::operator<(): invalid ACE type" );

	if ( aceType == r.aceType )
		ltType = 0;
	else
		ltType = ( typeMap[aceType] < typeMap[r.aceType] )? -1: 1;

	// now check inheritance bits
	if ( ( aceInheritance & INHERITED_ACE ) == ( r.aceInheritance & INHERITED_ACE ) )
		ltAutoInherited = 0; // equality?
	else // not same, no-auto-i is smaller
	{
		// if LHS.auto-i is set, then LHS is NOT < RHS
		ltAutoInherited = ( aceInheritance & INHERITED_ACE )? 1: -1;
	}

	// check SIDs
	if ( aceSid < r.aceSid )
		ltSid = -1;
	else if ( aceSid == r.aceSid )
		ltSid = 0;
	else
		ltSid = 1;

	// now check whether this ACE is an effective one, or an inherit-only
	if ( ( aceInheritance & INHERIT_ONLY_ACE ) == ( r.aceInheritance & INHERIT_ONLY_ACE ) )
		ltEffective = 0;
	else // not same; which one is effective?
		ltEffective = ( aceInheritance & INHERIT_ONLY_ACE )? 1: -1;

	switch ( GetAceSortOrder() )
	{
	case asoNT4:
		// NT4: deny before allow; effective before inherit-only
		if ( ltType != 0 )
			return ltType < 0;
		if ( ltSid != 0 )
			return ltSid < 0;
		return ltEffective < 0;

	case asoNT5:
	default:
		// NT5: no-auto-i before auto-i; deny before allow; effective before inherit-only
		if ( ltAutoInherited != 0 )
			return ltAutoInherited < 0;
		if ( ltType != 0 )
			return ltType < 0;
		if ( ltSid != 0 )
			return ltSid < 0;
		return ltEffective < 0;
	}
}



// --- accessors ---

/* \param newType the new type of the ace; the range \c ACCESS_MIN_MS_ACE_TYPE
to \c ACCESS_MAX_MS_V4_ACE_TYPE (inclusive) is supported (all known types at this time)
\exception errInvalidAce if the newType is out of range */
void ace::SetType( byte newType )
{
	if ( newType >= ACCESS_MIN_MS_ACE_TYPE &&
		newType <= ACCESS_MAX_MS_V4_ACE_TYPE  )
	{
		ReleasePACE();
		aceType = newType;
		haveAceType = true;
	}
	else
		throw NEWEX( errInvalidAce, "ace::SetType(): invalid ACE type" );
}


/*! This member cannot be used to set inheritance bits.
\param newFlags the new audit flags (any combination of \c
SUCCESSFUL_ACCESS_ACE_FLAG and \c FAILED_ACCESS_ACE_FLAG.
\exception errInvalidAce */
void ace::SetFlags( byte newFlags )
{
	if ( ( newFlags & VALID_INHERIT_FLAGS ) == 0 )
	{
		ReleasePACE();
		aceFlags = newFlags;
		haveAceFlags = true;
	}
	else
		throw NEWEX( errInvalidAce, "ace::SetFlags(): invalid ACE flags" );
}


/*! \param newMask the new permission bits to be granted, denied,
or audited, depending on the type of ACE
\exception none */
void ace::SetMask( ACCESS_MASK newMask )
{
	ReleasePACE();
	aceMask = newMask;
	haveAceMask = true;
}


/*! This member cannot be used to set audit flags.  While the
\c INHERITED_ACE bit can be set, it should not be; th system
sets that bit when an ACE is actually inherited.
\param newFlags the new inheritance bits, any combination of \c
OBJECT_INHERIT_ACE, \c CONTAINER_INHERIT_ACE, \c INHERIT_ONLY_ACE,
\c NO_PROPAGATE_INHERIT_ACE, \c INHERITED_ACE
\exception errInvalidAce */
void ace::SetInheritance( byte newInheritance )
{
	if ( ( newInheritance & ~ VALID_INHERIT_FLAGS ) == 0 )
	{
		ReleasePACE();
		aceInheritance = newInheritance;
		haveAceInheritance = true;
	}
	else
		throw NEWEX( errInvalidAce, "ace::SetInheritance(): invalid ACE inheritance flags" );
}


/*! \param newSid a reference to a sid, or through implicit conversion,
a PSID pointer to an NT-formatted SID
\exception errInvalidSid */
void ace::SetSid( const sid &newSid )
{
	if ( newSid.IsValid() )
	{
		ReleasePACE();
		aceSid = newSid;
	}
	else
		throw NEWEX( errInvalidSid, "ace::SetSid(): invalid SID" );
}

/*! \param newSid a pointer to a null-terminted string naming either
a valid account like \c felixk, \c MVPS\\felixk, or \c felixk@nt.mvps.org,
or a SID in string form, such as \c S-1-5-18
\exception errInvalidSid
\exception errNoMemory */
void ace::SetSid( const TCHAR *stringSid )
{
	sid newSid;

	try { newSid = stringSid; }
	RETHROWEX( "ace::SetSid(const TCHAR *): invalid SID" )

	if ( newSid.IsValid() )
	{
		ReleasePACE();
		aceSid = newSid;
	}
	else
		throw NEWEX( errInvalidSid, "ace::SetSid(): invalid SID" );
}


void ace::SetObjectType( const GUID &ObjectType )
{
	ReleasePACE();
	aceObjectTypeGUID = ObjectType ;
	aceObjectFlags |= ACE_OBJECT_TYPE_PRESENT ;
	// automatically convert this ace to an object type ACE, when you set an object type GUID
	if ( aceType < ACCESS_MIN_MS_OBJECT_ACE_TYPE )
		aceType += ACCESS_MIN_MS_OBJECT_ACE_TYPE ;	
}


void ace::RemoveObjectType()
{
	ReleasePACE();
	aceObjectTypeGUID = GUID_NULL ; // not required, but should help bring to light use of the GUID, when its not active
	aceObjectFlags &= ~ACE_OBJECT_TYPE_PRESENT ;
}


void ace::SetInheritedObjectType( const GUID &InheritedObjectType )
{
	ReleasePACE();
	aceInheritedObjectTypeGUID = InheritedObjectType ;
	aceObjectFlags |= ACE_INHERITED_OBJECT_TYPE_PRESENT ;
	// automatically convert this ace to an object type ACE, when you set an object type GUID
	if ( aceType < ACCESS_MIN_MS_OBJECT_ACE_TYPE )
		aceType += ACCESS_MIN_MS_OBJECT_ACE_TYPE ;	
}


void ace::RemoveInheritedObjectType()
{
	ReleasePACE();
	aceInheritedObjectTypeGUID = GUID_NULL ; // not required, but should help bring to light use of the GUID, when its not active
	aceObjectFlags &= ~ACE_INHERITED_OBJECT_TYPE_PRESENT ;
}



// --- utilities ---

// how many bytes for an NT-formatted ACE?
/*! \return the required buffer size to store *this as an NT-formatted ACE
\exception none*/
DWORD ace::GetLength() const
{
	if ( IsObjectACE() )
	{
		DWORD sz = sizeof ACCESS_ALLOWED_ACE  + aceSid.GetLength() + sizeof aceObjectFlags -
			sizeof ( ((ACCESS_ALLOWED_OBJECT_ACE *) 0)->SidStart );

		if ( aceObjectFlags & ACE_OBJECT_TYPE_PRESENT ) 
			sz += sizeof( GUID );

		if ( aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT )
			sz += sizeof( GUID );

		return sz;
	}
	else
	{
		return sizeof ACCESS_ALLOWED_ACE + aceSid.GetLength() -
			sizeof ( ((ACCESS_ALLOWED_ACE *) 0)->SidStart );
	}
}


// store a copy of the ACE where the caller wants it
/*! The caller is responsible for allocating (and eventually freeing) the buffer
and reporting its size correctly in \a sz.
\param p pointer to caller-allocated buffer
\param sz size, in bytes, of the buffer
\exception errInvalidAce
\exception errBufferTooSmall see ace::GetLength()
\exception errInvalidSid */
void ace::StoreAce( void *p, DWORD sz ) const
{
	DWORD sidSize, l;

	if ( ! IsValid() )
		throw NEWEX( errInvalidAce, "ace::StoreAce(): invalid ACE" );

	l = GetLength();
	if ( sz < l )
		throw new ex( _T( __FILE__ ), __LINE__, errBufferTooSmall,
			_T( "ace::StoreAce(): insufficient buffer, see ex::GetData() for required size" ), 0, l );

	((ACCESS_ALLOWED_ACE *) p)->Header.AceFlags = aceFlags | aceInheritance;
	((ACCESS_ALLOWED_ACE *) p)->Header.AceSize = GetLength();
	((ACCESS_ALLOWED_ACE *) p)->Header.AceType = aceType;
	((ACCESS_ALLOWED_ACE *) p)->Mask = aceMask;

	// start computing the space remaining for the (variable-length) SID.
	// Here, we account for the ACE_HEADER
	sidSize = sz - sizeof ACE_HEADER - sizeof ACCESS_MASK;

	// prep a pointer to the variable part, which starts after the access mask
	byte *next = sizeof ACCESS_MASK + (byte *) &((ACCESS_ALLOWED_OBJECT_ACE *) p)->Mask;

	if ( IsObjectACE() )
	{
		*( (DWORD *) next ) = aceObjectFlags;
		next += sizeof DWORD;
		sidSize -= sizeof DWORD;

		if ( aceObjectFlags & ACE_OBJECT_TYPE_PRESENT )
		{
			*( (GUID *) next ) = aceObjectTypeGUID;
			next += sizeof aceObjectTypeGUID;
			sidSize -= sizeof aceObjectTypeGUID;
		}

		if ( aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT )
		{
			*( (GUID *) next ) = aceInheritedObjectTypeGUID;
			next += sizeof aceInheritedObjectTypeGUID;
			sidSize -= sizeof aceInheritedObjectTypeGUID;
		}
	}

	try { aceSid.StoreSid( next, sidSize ); }
	RETHROWEX( "ace::StoreAce(): invalid SID" )
}


// test for validity
/*! \retval true if the sid is valid, and if type/flags/inheritance have been set
\retval false otherwise
\exception none */
bool ace::IsValid() const
{
	return haveAceFlags && haveAceType && haveAceInheritance && aceSid.IsValid();
}


bool ace::IsObjectACE() const
{
	return ( ACCESS_ALLOWED_OBJECT_ACE_TYPE == aceType ||
		ACCESS_DENIED_OBJECT_ACE_TYPE == aceType ||
		SYSTEM_AUDIT_OBJECT_ACE_TYPE == aceType ) ;
}


// return sort order for ACEs
// will never return asoDefault
/*! If ace::currentAceSortOrder == ace::asoDefault, the OS version is checked,
currentAceSortOrder is set to ace::asoNT4 or ace::asoNT5 as appropriate,
and the new value of currentAceSortOrder is returned.
\warning Note that the ace::currentAceSortOrder setting is global.
\retval asoNT4 ace::operator<() will order ace objects by NT4 rules
\retval asoNT5 ace::operator<() will order ace objects by NT5 rules
\retval asoDefault will never be returned
\exception none */
ace::AceSortOrder ace::GetAceSortOrder()
{
	if ( currentAceSortOrder == asoDefault )
	{
		OSVERSIONINFO ov = { sizeof ov };
		currentAceSortOrder = asoNT5;
		if ( GetVersionEx( &ov ) )
		{
			if ( ov.dwMajorVersion < 5 )
				currentAceSortOrder = asoNT4;
		}
	}

	return currentAceSortOrder;
}



// set ACE sort order
// if set to asoDefault, the next call to GetAceSortOrder()
// will resolve to either asoNT4 or asoNT5
/*! \param aso the new AceSortOrder to use.  Note that the next call to
GetAceSortOrder() will resolve asoDefault to either asoNT4 or asoNT5.
\exception none */
void ace::SetAceSortOrder( AceSortOrder aso )
{
	currentAceSortOrder = aso;
}



// --- inserters ---
// dump the ace
/*! \param o a reference to a stream derived from std::ostream or std::wostream,
depending on the UNICODE setting
\param a the ACE to dump
\return a reference to the fkostream that was passed in
\exception none */
fkostream &fksec::operator<<( fkostream &o, const ace &a )
{
	o << _T( "ace: type " );
 
	if ( a.haveAceType )
		o << _T( "0x" ) << std::hex << std::setfill( _T( '0' ) ) << std::setw( 2 ) << (int) a.aceType << std::dec << std::setfill( _T( ' ' ) );
	else
		o << _T( "-NA-" );

	o << _T( ", flags: " );
	if ( a.haveAceFlags )
		o << _T( "0x" ) << std::hex << std::setfill( _T( '0' ) ) << std::setw( 2 ) << ( a.aceFlags & 0xff ) << std::dec << std::setfill( _T( ' ' ) );
	else
		o << _T( "-NA-" );

	o << _T( ", inheritance: " );
	if ( a.haveAceInheritance )
		o << _T( "0x" ) << std::hex << std::setfill( _T( '0' ) ) << std::setw( 2 ) << ( a.aceInheritance & 0xff ) << std::dec << std::setfill( _T( ' ' ) );
	else
		o << _T( "-NA-" );

	o << _T( ", mask: " );
	if ( a.haveAceMask )
		// with printf, this would be: printf( "0x%08lX", aceMask );
		// Brave New World of C++! This stream stuff deserves retroactive abortion.
		o << _T( "0x" ) << std::hex << std::setfill( _T( '0' ) ) << std::setw( 8 ) << a.aceMask << std::dec << std::setfill( _T( ' ' ) );
	else
		o << _T( "----NA----" );

	if ( a.IsObjectACE() )
	{
		o << _T( ", objectFlags: 0x" ) << std::hex << std::setfill( _T( '0' ) ) << std::setw( 2 ) << a.aceObjectFlags << std::dec << std::setfill( _T( ' ' ) ) ;

		o << _T(", objectType: " ) ;
		if ( a.aceObjectFlags & ACE_OBJECT_TYPE_PRESENT )
			o << a.aceObjectTypeGUID ;
		else
			o << _T( "-NA-" ) ;

		o << _T(", inheritedType: " ) ;
		if ( a.aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT )
			o << a.aceInheritedObjectTypeGUID ;
		else
			o << _T( "-NA-" ) ;
	}

	o << _T( ", sid: " );
	if ( a.aceSid.IsValid() )
		o << a.aceSid;
	else
		o << _T( "-none-" );

	return o;
}



// initialize the PACE part
/*! \exception none */
void ace::ClearPACE() const
{
	havePACE = false;
	pace = 0;
}


// release the PACE part
/*! \exception none */
void ace::ReleasePACE() const
{
	if ( havePACE )
	{
		delete [] (byte *) pace;
		havePACE = false;
	}
}


// make sure we have a current NT ACE
/*! \exception errInvalidAce
\exception errNoMemory
\exception errInvalidSid
\exception errBufferTooSmall this should never happen */
void *ace::MakePACE() const
{
	DWORD sz;

	if ( ! havePACE )
	{
		if ( ! IsValid() )
			throw NEWEX( errInvalidAce, "ace::MakePACE(): invalid ACE" );

		sz = GetLength();

		pace = (ACCESS_ALLOWED_ACE *) new byte[sz];
		if ( pace == 0 )
			throw NEWEX( errNoMemory, "ace::MakePACE(): no memory for ACE buffer" );

		try { StoreAce( pace, sz ); }
		catch ( ex *e )
		{
			e->FKSECADDHOP( "ace::MakePACE()" );
			delete (byte *) pace;
			throw;
		}

		havePACE = true;
	}

	return (void *) pace;
}


// initalization from a PACE
/*! reads an ACE at address \a a, parses it, and sets *this up so that
it mirrors the ACE's contents.
\param a address of ACE to copy into *this
\exception errInvalidSid */
void ace::InitFromPACE(const void *a)
{
	aceType = ((ACE_HEADER *) a)->AceType;
	aceFlags = ((ACE_HEADER *) a)->AceFlags & ~ VALID_INHERIT_FLAGS;
	aceMask = ((ACCESS_ALLOWED_ACE *) a)->Mask;
	aceInheritance = ((ACE_HEADER *) a)->AceFlags & VALID_INHERIT_FLAGS;
	haveAceType = true;
	haveAceMask = true;
	haveAceFlags = true;
	haveAceInheritance = true;

	// prep a pointer to the variable part, which starts after the access mask
	byte *next = sizeof ACCESS_MASK + (byte *) &((ACCESS_ALLOWED_OBJECT_ACE *) a)->Mask;

	if ( IsObjectACE() )
	{
		aceObjectFlags = *( (DWORD *) next );
		next += sizeof DWORD;

		if ( aceObjectFlags & ACE_OBJECT_TYPE_PRESENT )
		{
			aceObjectTypeGUID = *( (GUID *) next );
			next += sizeof aceObjectTypeGUID;
		}

		if ( aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT )
		{
			aceInheritedObjectTypeGUID = *( (GUID *) next );
			next += sizeof aceInheritedObjectTypeGUID;
		}
	}

	try { aceSid = (PSID) next; }
	RETHROWEX( "ace::StoreAce(): invalid SID" )

}
