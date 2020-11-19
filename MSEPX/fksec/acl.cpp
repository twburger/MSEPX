// recommended includes in stdafx.h (or in the precompiled header, to be precise):
// windows.h, tchar.h, string, vector, algorithm, exception, sstream, iomanip

#include "stdafx.h"
#define FKSEC_NO_AUTO_INCLUDES 1
#include "fksec.h"
#include "ex.h"
#include "sid.h"
#include "ace.h"
#include "acl.h"

using namespace fksec;


/*! \file acl.cpp
\brief implements the fksec::acl class */


// --- ctors/dtor ---

// construct an empty acl object
/*! Constructs *this as an empty acl object.
\exception none */
acl::acl()
{
	Init();
}


// construct from another acl object
/*! Constructs *this as a deep copy of another acl object.
\param a the acl to be copied
\exception errInvalidAcl */
acl::acl( const acl &a )
{
	Init();
	if ( a.IsValid() )
	{
		aces = a.aces;
		additionalBytes = a.additionalBytes;
	}
	else
		throw NEWEX( errInvalidAcl, "acl::acl(const acl&): invalid ACL" );

}


// construct from a PACL
/*! Constructs *this as a deep copy of an NT-formatted ACL structure.

Note that the acl class does not wrap NT-formatted ACLs; \a a
therefore belongs to you, and you must free it, if necessary.
\param a a pointer to an NT-formatted ACL, whose contents are copied into *this
\exception errInvalidAcl
\exception errInvalidSid */
acl::acl( ACL *a )
{
	ACL_SIZE_INFORMATION asi;
	DWORD i, n;
	void *pace;

	Init();
	if ( IsValidAcl( a ) && ( a->AclRevision == ACL_REVISION ||
		a->AclRevision == ACL_REVISION_DS ) )
	{
		GetAclInformation( a, &asi, sizeof asi, AclSizeInformation );
		additionalBytes = asi.AclBytesFree;
		n = asi.AceCount;
		for ( i = 0; i < n; ++ i )
		{
			if ( ::GetAce( a, i, &pace ) )
			{
				try { AddAce( (DWORD) -1, pace ); }
				catch ( ex *e )
				{
					e->FKSECADDHOP( "acl::ace(ACL *): failed to add an ACE" );
					aces.clear();
					throw;
				}
			}
		}
	}
	else
		throw NEWEX( errInvalidAcl, "acl::acl(ACL *): invalid ACL, or bad revision" );
}


// clean up
/*! Destroys an acl object and releases any internal buffers.
\exception none */
acl::~acl()
{
	ReleasePACL();
	aces.clear();
}



// --- assignment ---

// from another acl
/*! This overload of the assignment operator deep-copies another
acl object into *this.
\param a the acl to be copied
\return a const reference to *this
\exception errInvalidAcl */
const acl &acl::operator=( const acl &s )
{
	if ( this != &s )
	{
		ReleasePACL();
		if ( s.IsValid() )
		{
			aces = s.aces;
			additionalBytes = s.additionalBytes;
		}
		else
			throw NEWEX( errInvalidAcl, "acl::operator=(const acl&): invalid ACL" );
	}

	return *this;
}


// from PACL
/*! This overload of the assignment operator deep-copies an NT-formatted
ACL structure into *this.
Note that the acl class does not wrap NT-formatted ACLs; \a s
therefore belongs to you, and you must free it, if necessary.
\param a a pointer to an NT-formatted ACL, whose contents are copied into *this
\return a const reference to *this
\exception errInvalidAcl
\exception errInvalidSid */
const acl &acl::operator=( ACL *s )
{
	ACL_SIZE_INFORMATION asi;
	DWORD i, n;
	void *pace;

	if ( havePACL && pacl == s )
		return *this;

	try
	{
		ReleasePACL();
		this->Init();

		if ( IsValidAcl( s ) )
		{
			GetAclInformation( s, &asi, sizeof asi, AclSizeInformation );
			additionalBytes = asi.AclBytesFree;
			n = asi.AceCount;
			for ( i = 0; i < n; ++ i )
			{
				if ( ::GetAce( s, i, &pace ) )
				{
					try { AddAce( (DWORD) -1, pace ); }
					catch ( ex *e )
					{
						e->FKSECADDHOP( "acl::operator=(ACL *): failed to add an ACE" );
						aces.clear();
						throw;
					}
				}
			}
		}
		else
			throw NEWEX( errInvalidAcl, "acl::operator=(ACL *): invalid ACL" );
	}
	catch(...)
	{
		throw NEWEX( errInvalidAcl, "acl::operator=(ACL *): invalid ACL" );
	}

	return *this;
}



// --- conversions ---

// return a pointer to an internally-maintained ACL
/*! This operator offers a way to plug in an acl instance wherever
a PACL is required -- \b unless the PACL would be written to.
\warning The returned pointer is non-const because NT APIs demand
such non-const pointers in most locations. You, however, \em must
treat the return value as a \c const pointer -- do not write through
the pointer, and most of all, do not ever free it.

\warning The returned pointer is valid only as long as no changes are
made to *this. To be on the safe side, assume that the result becomes
invalid as soon as you invoke any other method on *this.
\return a pointer to an internally maintained buffer containing *this,
formatted as an NT ACL.
\exception errBufferTooSmall (from acl::StoreAcl())
\exception errInvalidAcl
\exception errNoMemory */
acl::operator ACL *() const
{
	ACL *p;

	try { p = MakePACL(); }
	RETHROWEX( "acl::operator const ACL *(): MakePACL() failed" )

	return p;
}



// --- accessors ---

// return a ref to the Nth ACE
/*! GetAce() returns a reference to a specific ace managed by *this.
This overload returns a const reference and therefore works on const
objects.
\param index the zero-based index (range 0..GetCount()-1) of the ace to return
\return a const reference to the index<sup>th</sup> ace
\exception errInvalidAceIndex */
const ace &acl::GetAce( DWORD index ) const
{
	if ( index >= GetCount() )
		throw NEWEX( errInvalidAceIndex, "acl::GetAce(): ACE index out of range" );

	return aces[index];
}


/*! GetAce() returns a reference to a specific ace managed by *this.
This overload returns a read/write reference and therefore works only
on non-const objects.
\param index the zero-based index (range 0..GetCount()-1) of the ace to return
\return a reference to the index<sup>th</sup> ace
\exception errInvalidAceIndex */
ace &acl::GetAce( DWORD index )
{
	if ( index >= GetCount() )
		throw NEWEX( errInvalidAceIndex, "acl::GetAce(): ACE index out of range" );

	return aces[index];
}


// return bytes required incl. desired free bytes
/*! GetSize() returns the number of bytes required by *this when
formatted as an NT ACL, accounting also for the number of extra
bytes requested by the owner of *this.
\return a DWORD indicating the minimum-size buffer required for
StoreAcl(), in bytes
\exception none */
DWORD acl::GetSize() const
{
	return GetLength() + additionalBytes;
}


// return count of ACEs
/*! GetCount() retrieves the number of aces currently managed by *this.
\return a DWORD with the number of aces in the list
\exception none */
DWORD acl::GetCount() const
{
	return aces.size();
}


// set amount of free bytes desired in NT ACL
/*! This function sets the number of extra bytes to include when
creating an NT-formatted ACL from *this.
\param newAdditionalBytes a DWORD giving the new extra byte count
\exception none
\sa additionalBytes */
void acl::SetFreeBytes( DWORD newAdditionalBytes )
{
	additionalBytes = newAdditionalBytes;
}


// how many bytes are extra?
/*! This function retrieves the currently set number of extra bytes.
\return a DWORD giving the currently requested extra byte count
\exception none
\sa additionalBytes */
DWORD acl::GetFreeBytes() const
{
	return additionalBytes;
}



// --- utilities ---

// add an ACE
// index gives the position _before_ which the ACE will be inserted
// (DWORD) -1 inserts at end
// no need to worry about canonical order, you can always canonicalize() the ACL
/*! This overload of AddAce() takes an ace and adds it, in front
of a specified position, to the list of aces. While NT demands a
certain ordering of ACEs in ACLs, you need not worry about that;
just call canonicalize() when you are done inserting.
\param index the position (zero-based) at which to insert the new ace.
Use \c (DOWRD) \c -1L to add to the end of the list.
\param a the ace to insert
\exception none */
void acl::AddAce( DWORD index, const ace &a )
{
	AceListIter i;

	if ( index >= aces.size() )
		i = aces.end();
	else
		i = aces.begin()+index;//i = &aces[index]

	aces.insert( i, a );
}


/*! This overload of AddAce() constructs an ace from bits and pieces
and adds it, in front of a specified position, to the list of aces.
While NT demands a certain ordering of ACEs in ACLs, you need not
worry about that; just call canonicalize() when you are done
inserting.
\param index the position (zero-based) at which to insert the new ace.
Use \c (DOWRD) \c -1L to add to the end of the list.
\param type the type of ace to construct; the most common values are
\c ACCESS_ALLOWED_ACE_TYPE, \c ACCESS_DENIED_ACE_TYPE, and
\c SYSTEM_AUDIT_ACE_TYPE
\param flags a set of bits specifying whether a system audit ACE triggers
on a successful access, a failed access, or both; can be \c
SUCCESSFUL_ACCESS_ACE_FLAG, \c FAILED_ACCESS_ACE_FLAG, both ORed together,
or none
\param inheritance a set of bits defining the ACE's behaviour; too complex
to go into here. You may or any of these constants together: \c
OBJECT_INHERIT_ACE, \c CONTAINER_INHERIT_ACE, \c NO_PROPAGATE_INHERIT_ACE,
\c INHERIT_ONLY_ACE. \c INHERITED_ACE may only be set by the OS.
\param mask a bit mask specifying which permissions this ACE will grant,
deny, or audit. Possible values depend on the object type for which *this
is intended.
\param newSid the SID of the user or group whose access is being granted,
denied, or audited. Thanks to the amazing versatility of the fksec::sid
class :-), you can also plug a PSID into this argument.
\param ObjectTypeGUID restricts, for object ACEs, the subobjects to which
the ACE applies. This is orthogonal to the conventional parent/child
relationship. For more information, see the page for \c ACCESS_ALLOWED_OBJECT_ACE
in the SDK documentation.
\param InheritedObjectTypeGUID is, if present, an additional restriction
on the kind of child eligible to inherit this ACE.
\exception errNoMemory
\exception errInvalidSid */
void acl::AddAce( DWORD index, byte type, byte flags, byte inheritance,
	ACCESS_MASK mask, const sid &newSid, const GUID &ObjectType /* = GUID_NULL */,
	const GUID &InheritedObjectType /* = GUID_NULL */ )
{
	AceListIter i;

	if ( index >= aces.size() )
		i = aces.end();
	else
		//i = &aces[index];
		i = aces.begin()+index;

	aces.insert( i, ace( type, flags, inheritance, mask,
		newSid, ObjectType, InheritedObjectType ) );
}


// delete an ACE
/*! This function deletes an ace specified by its position
in the list.
\param index index of the ace to be deleted (range: 0 .. GetCount()-1)
\exception errInvalidAceIndex */
void acl::DeleteAce( DWORD index )
{
	if ( index < aces.size() )
		aces.erase( aces.begin()+index); //&aces[index] );
	else
		throw NEWEX( errInvalidAceIndex, "acl::DeleteAce(): ACE index out of range" );
}


// delete all ACEs for the specified SID
/*! DeleteAcesForSid() eliminates all ACEs that list a given SID.
Note that this operation ("revoking" someone's access) is not the
same as denying someone access.
\param delSid the SID whose ACEs are to be deleted from *this
\exception none */
void acl::DeleteAcesForSid( const sid &delSid )
{
	int i;

	for ( i = aces.size() - 1; i >= 0; -- i )
	{
		if ( aces[i].GetSid() == delSid )
			aces.erase( aces.begin()+i ); //&aces[i] );
	}
}


/*! GetEffectiveRights() keeps two \c ACCESS_MASK values, one
for denied permissions and one for granted permissions, both
initialized to 0. It traverses the ACL, looking up each ACE's
SID in the \a sids list. If the SID is not present, the ACE is
ignored; if it is present, then the permission bits from the ACE
are ORed into either the denied- or the granted- \c ACCESS_MASK,
depending on whether the ACE's type is deny or allow. After all
ACEs have been examined, any denied permissions are cleared from
the granted ones, and the result is returned.
\param sids the list of SIDs to check against; usually includes
also the SIDs of any groups that a user belongs to. Owner
semantics are (obviously) not implemented; neither are privileges
(\c ACCESS_SYSTEM_SECURITY, e.g., requires \c SeSecurityPrivilege
to be available).
\warning For ACLs that do not obey the canonical sort order for
ACEs, the results may differ from those that NT's SRM would arrive
at. <b>Canonicalize your ACLs!</b>
\todo Provide a wrapper for acl::GetEffectiveRights() that takes
a single SID, gets all its groups, and optionally adds the usual
group of suspects (SIDs for interactive/network/... logons, logon
session SID, authenticated-users SID, etc.)
\return an ACCESS_MASK with every permission bit set that would
be granted for the given list of SIDs.
\exception errInvalidAcl */
ACCESS_MASK acl::GetEffectiveRights( const SidList& sids )
{
	AceListConstIter i;
	ACCESS_MASK denied = 0, granted = 0;

	if ( ! IsValid() )
		throw NEWEX( errInvalidAcl, "acl::GetEffectiveRights(): invalid ACL" );

	for ( i = aces.begin(); i != aces.end(); ++ i )
	{
		// note: if sids.size() * aces.size() is large and
		// sids.size() is middling to large, it might be
		// worthwhile to create a hashed or treed copy of
		// the sids list and use that ...
		if ( sids.end() != std::find( sids.begin(), sids.end(), i->GetSid() ) )
		{
			switch ( i->GetType() )
			{
			case ACCESS_ALLOWED_ACE_TYPE:
			case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
			case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
				granted |= i->GetMask();
				break;
			case ACCESS_DENIED_ACE_TYPE:
			case ACCESS_DENIED_OBJECT_ACE_TYPE:
				denied |= i->GetMask();
				break;
			default:
				throw NEWEX( errInvalidAcl, "acl::GetEffectiveRights(): only allow- and deny-ACEs are supported" );
			}
		}
	}

	granted &= ~denied;
	return granted;
}


// normalize ACEs -- ACEs with same type, flags, inheritance,
// and SID are merged by ORing their masks. This means you can
// just blindly add ACEs and then call normalize().
void acl::normalize()
{
	int i, j;

	for ( i = 0; i < (int) aces.size() - 1; ++ i )
	{
		for ( j = aces.size() - 1; j > i; -- j )
		{
			if ( aces[i] == aces[j] )
			{
				aces[i].SetMask( aces[i].GetMask() | aces[j].GetMask() );
				aces.erase( aces.begin()+j ); //&aces[j] );
			}
		}
	}
}


// sort ACEs into canonical order: deny-ACEs first, then allow-ACEs,
// then all others. This is a stable sort.
void acl::canonicalize()
{
	std::sort( aces.begin(), aces.end() );
}


// how many bytes for an NT-formatted ACL, without extra free space?
DWORD acl::GetLength() const
{
	AceListConstIter i;
	DWORD totsize;

	for ( totsize = 0, i = aces.begin(); i != aces.end(); ++ i )
	{
		try { totsize += i->GetLength(); }
		RETHROWEX( "acl::GetLength(): failed to retrieve an ACE's size" )
	}

	totsize += sizeof ACL;
	return totsize;
}


// store a copy of the ACL where the caller wants it
/*! acl::StoreAcl() creates an NT-formatted ACL in a caller-supplied
buffer. It does so by laying out the header and then iterating over
the list of aces, telling each one to stash itself at the next free
buffer location.
\param p pointer to the buffer in which the ACL will be stored
\param sz number of bytes available in that buffer
\exception errBufferTooSmall
\exception errInvalidAce
\exception errInvalidAcl
\exception errInvalidSid */
void acl::StoreAcl( ACL *p, DWORD sz ) const
{
	AceListConstIter i;
	void *a;
	DWORD remaining, acelen;

	if ( ! IsValid() )
		throw NEWEX( errInvalidAcl, "acl::StoreAcl(): invalid ACL" );

	remaining = GetSize();
	if ( sz < remaining )
	{
		ex *e = NEWEX( errBufferTooSmall,
			"acl::StoreAcl(): insufficient buffer, see ex::GetData() for required size" );
		e->SetData( remaining );
		throw e;
	}

	if ( ! ::InitializeAcl( p, remaining, GetRequiredAclRevision() ) )
		throw NEWEX32( errInvalidAcl,
			"acl::StoreAcl(): ::InitializeAcl() failed, see ex::GetErrWin32",
			GetLastError() );

	p->AceCount = aces.size();
	a = (void *) &p[1]; // point to first ACE slot
	remaining -= sizeof ACL;

	for ( i = aces.begin(); i != aces.end(); ++ i )
	{
		try
		{
			acelen = i->GetLength();
			i->StoreAce( a, remaining );
		}
		RETHROWEX( "acl::StoreAcl(): ran into a stubborn ACE" )
		a = (void *) ( (byte *) a + acelen );
		remaining -= acelen;
	}

	// at this point, the remaining bytes should be exactly those that
	// the user wanted to be allocated in excess of the minimum.
	if ( remaining != additionalBytes || ! IsValidAcl( p ) )
		throw NEWEX( errInvalidAcl,
			"acl::StoreAcl(): size calculation incorrect, or invalid ACL produced" );
}


// test for validity
/*! This function tests *this for validity by aggregating
the validity of the ACEs it represents, and by enforcing a
less-than-inspired 64KB limit caused by the use of shorts
in the NT-defined ACL header.
\return a bool indicating the validity of *this
\retval true if all aces are valid, and if the ACL would be
under 64 KB-1 in NT's ACL format
\retval false otherwise
\exception none */
bool acl::IsValid() const
{
	bool result = true;

	try
	{
		for ( AceListConstIter i = aces.begin(); result && i != aces.end(); ++ i )
			result = result && i->IsValid();
	}
	catch ( ex *e )
	{
		delete e;
		return false;
	}

	if ( GetSize() > 65535 )
		return false;

	return true;
}


/*! IsObjectACL() checks for the presence of object-ACEs.
\return a bool indicating whether object-ACEs are present
\retval true at least one object-ACE was found
\retval false otherwise
\exception none */
bool acl::IsObjectACL() const
{
	AceListConstIter i;

	for ( i = aces.begin(); i != aces.end(); ++ i )
	{
		if ( i->IsObjectACE() )
			return true;
	}
	return false;
}


// what type of Acl Revision do we want
/*! Returns the revision with which the ACL header must be
initialized. This is either \c ACL_REVISION_DS (if the acl
contains object-ACEs) or \c ACL_REVISION (if it doesn't).
\return the minimum ACL revision to support the ACEs represented
by *this.
\retval ACL_REVISION_DS if at least one ACE is of a GUID-carrying type
\retval ACL_REVISION otherwise
\exception none */
DWORD acl::GetRequiredAclRevision() const
{
	return IsObjectACL()? ACL_REVISION_DS: ACL_REVISION;
}


// --- inserters ---

// dump this acl
/*! Inserts \a a in reasonably human-readable form into the output
stream \a o. Note that fksec requires the use of the newer headers
from the C++ Standard Library -- \c \<iostream\> instead of \c \<iostream.h\>.
\param o a reference to an fkostream (resolving to either std::ostream or
std::wostream, depending on the ambient character size) to which the acl is
written
\param a a const reference to the acl object to insert into the output stream
\return a reference to the stream passed as the argument \a o
\exception none */
fkostream &fksec::operator<<( fkostream &o, const acl &a )
{
	o << _T( "acl, " ) << a.aces.size() << _T( " ACEs, " )
		<< a.additionalBytes << _T( " bytes extra space" ) << std::endl;

	for ( AceListConstIter i = a.aces.begin(); i != a.aces.end(); ++ i )
		o << _T( "  " ) << (*i) << std::endl;

	return o;
}


/*! Initializes *this by clearing the ace vector &c.
\exception none */
void acl::Init()
{
	aces.clear();
	additionalBytes = 0;
	ClearPACL();
}


// initialize the PACL part
/*! Initializes havePACL to false, indicating that pacl is not valid.
\exception none */
void acl::ClearPACL() const
{
	havePACL = false;
	pacl = 0;
}


// release the PACL part
/*! Called by other member functions whenever a change to the internal
data invalidates the NT-formatted ACL.
\exception none */
void acl::ReleasePACL() const
{
	if ( havePACL )
	{
		delete [] (byte *) pacl;
		pacl = 0;
		havePACL = false;
	}
}


/*! Allocates a buffer and invokes StoreAcl() to deposit an NT-formatted ACL
into that buffer.
\warning The returned pointer is valid only as long as no changes are
made to *this. To be on the safe side, assume that the result becomes
invalid as soon as you invoke any other method on *this.
\return a pointer to an internally maintained buffer containing *this,
formatted as an NT ACL.
\exception errBufferTooSmall
\exception errInvalidAce
\exception errInvalidAcl
\exception errInvalidSid
\exception errNoMemory */
ACL *acl::MakePACL() const
{
	DWORD sz;

	if ( ! havePACL )
	{
		if ( ! IsValid() )
			throw NEWEX( errInvalidAcl, "acl::MakePACL(): invalid ACL" );

		sz = GetSize();

		pacl = (ACL *) new byte[sz];
		if ( pacl == 0 )
			throw NEWEX( errNoMemory, "acl::MakePACL(): no memory for ACL buffer" );

		try { StoreAcl( pacl, sz ); }
		catch ( ex *e )
		{
			e->FKSECADDHOP( "acl::MakePACL(): StoreAcl() is insubordinate" );
			delete (byte *) pacl;
			throw;
		}

		havePACL = true;
	}

	return pacl;
}
