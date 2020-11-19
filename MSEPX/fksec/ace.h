// ace.h: DO NOT include this file. #include fksec.h instead!



#if ! defined( AFX_ACE_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_ACE_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


/*! \file ace.h
\brief declares the fksec::ace class */


/*! \class fksec::ace
\anchor aceintro \brief The ace class represents an ACE (Access-Control Entry).

<h3>Introduction and mini-tutorial</h3>

An ACE, usually part of an access-control list, is a combination of
a SID identifying a user or group; a bitmask of permissions; a type
field which determines whether the ACE denies, grants, or audits
these permissions; and a flag field that defines specific aspects
of the ACE's behaviour.

The ace class presents this with a few modifications: the SID is
replaced by an instance of the fksec::sid class; the flags are split
into two fields, flags and inheritance bits; and the layout of the
variable-length struct that NT uses for ACEs is abstracted.

The class offers a conversion operator to generate NT-formatted
ACEs as needed, but it is more suitably employed directly; for instance,
fksec::acl, the ACL class, manages a list of ace objects.

<h3>ACE types</h3>

One way to categorise ACEs is by their function. The most common kinds
are the \c ACCESS_ALLOWED_ACE, the \c ACCESS_DENIED_ACE, and the \c
SYSTEM_AUDIT_ACE. There are also variations on these that
sport two GUIDs per ACE; these so-called object ACEs are used for
Active Directory security.

A \c SYSTEM_AUDIT_ACE appears only in the SACL of a securable object; there,
it specifies which accesses will be audited (logged).  Such an ACE has
two flag bits, packed into the highest bits of the byte that also
contains the inheritance bits, which denote whether a denied access
should be logged, or a successful one, or both.

The \c ACCESS_DENIED_ACE occurs only in DACLs and does what the name
implies.  To make sure that denied access takes priority over granted
access, these ACEs are, all other things being equal, sorted before
those ACEs that grant access (see below for more on ACE sort order).
A deny-ACE is considered a match if at least one of the permission-
(here, actually denial-) bits it has set is also set in the bitmask
of requested permissions.

\c ACCESS_ALLOWED_ACE is the permission-granting counterpart, although
the matching process is slightly different: the list of allow-ACEs is
traversed, and for every ACE whose SID is found among the user and
group SIDs to which the requestor belongs, the permissions bits are
toted up (actually, ORed together).  If the result has all the bits
set that the requestor asked for, access is granted.

<h3>Access masks</h3>

This brings us to the \c ACCESS_MASK.  This is just a 32-bit DWORD,
regarded as split into three distinct fields.  The right-most (lowest)
sixteen bits are particular to the NT object type under consideration;
the same bit that, for a file, denotes permission to write its Extended
Attributes means "permission to start the service" when associated with
an NT service.

The next twelve bits (16 through 27) are permissions that apply to
nearly any kind of NT object: \c DELETE, \c SYNCHRONIZE, and others are found
here.

The leftmost four bits are the generic permissions: For every NT
object type, there is a list of four DWORDs, one per generic-bit, that
translates these bits into combinations of non-generic bits.  This
allows us to use \c GENERIC_READ for both registry keys and files, despite
the fact that the actual type-specific permission bits are quite different.
Note that when evaluating ACEs for granting or denying access, these
generic bits are translated into "real" permission bits before being
checked.

The \#defined names of permission bits may be found in the Platform
SDK documentation. Some relevant page titles are:
	- Generic Access Rights
	- Standard Access Rights
	- SACL Access Right
	- File and Directory Security
	- Named Pipe Security
	- Anonymous Pipe Security
	- Process Security And Access Rights
	- Thread Security and Access Rights
	- File-Mapping Security and Access Rights
	- Access Rights for Access-Token Objects
	- Window-Station Security and Access Rights
	- Desktop Security and Access Rights
	- Registry Key Security and Access Rights
	- Service Security
	- Synchronization Object Security and Access Rights
	- Job Object Security and Access Rights

Permission bits for printers, print servers, and print jobs are
best looked up in winspool.h (search for the \c PRINTER_ACCESS_USE
\#define), and similarly permission bits for shares should be looked up in
lmaccess.h (\c ACCESS_READ is of interest).

<h3>Audit bits</h3>

The audit bits, mentioned above already, come into play when auditing is
globally enabled, a user has requested access to a secured object, and
the object's SACL contains an ACE with either the SID of the user or the
SID of a group of which the user is a member:  In this case, they decide
whether only a successful access should be logged, or only a failed one,
or either.  The names of the corresponding bits are \c SUCCESSFUL_ACCESS_ACE_FLAG
and \c FAILED_ACCESS_ACE_FLAG.

<h3>Inheritance</h3>

Inheritance is an under-documented area of NT security.  To make things
worse, there are two kinds: old-style inheritance (as on NT4 without the
SCE add-on) and auto-inheritance, which is the rule for NT5. (The SCE,
Security Configuration Editor, was introduced as part of Service Pack 4
for NT4 and brought new security dialogs as well as a tool to apply
generalised lists of permissions to file-system and registry objects.)

The former kind is relatively simple:  When a new object or sub-container
(file or directory) is created in an existing object (directory), the
DACL and SACL of the parent object are traversed, and each ACE is looked
at with regard to inheritance.  Whether or not the ACE is copied to the
child's ACL depends on whether the child is a container or not, and on the
ACE's inheritance bits.

For children that are containers, the following rules hold:

	- If an ACE has the \c OBJECT_INHERIT_ACE bit set, but not the
	  \c CONTAINER_INHERIT_ACE bit, then the ACE is copied, but the
	  copy gets the \c INHERIT_ONLY_ACE bit: the new ACE has no
	  effect on the child but will be inherited by grandchildren.
	  If \c NO_PROPAGATE_INHERIT_ACE is also set, then the new ACE
	  would not be inheritable; an ACE that is neither effective
	  nor inheritable is useless, and so it is skipped.

	- If an ACE has the \c CONTAINER_INHERIT_ACE bit set, the state
	  of the \c OBJECT_INHERIT_ACE bit is irrelevant.  The child
	  gets an effective ACE (which affects the child itself), which
	  is also inheritable. If \c NO_PROPAGATE_INHERIT_ACE was also
	  set, then the inheritability is removed: grandchildren will
	  not get a copy, but the ACE still affects the child itself.

For children that are not containers, the rules are simpler:

	- \c CONTAINER_INHERIT_ACE is irrelevant; if the ACE has the
	  \c OBJECT_INHERIT_ACE bit set, it is copied to the child as
	  an effective ACE.

Normally, generic permission bits are mapped into the real permission
bits during the copy; similarly, generic SIDs (like the \c CREATOR \c
OWNER SID) are replaced by the actual creator of an object, thus fixing
him as the owner.  If an ACE has the \c INHERIT_ONLY_ACE bit set, however,
then generic permissions and SIDs are left intact (so that a sub-directory
will still have an ACE with \c CREATOR \c OWNER which it can pass on to
newly created files).

The newer kind, automatic inheritance, adds a twist to this scheme. The
passing-on of ACEs no longer happens only when an object is being created;
it happens every time a security descriptor is written back to an object
while having its \c SE_DACL_AUTO_INHERIT_REQ bit set (or its equivalent
bit for the SACL).  For more on this, consult the fksec::sd documentation
(provided, that is, that I manage to finish it sometime) while keeping
in mind that an ACE with \c INHERITED_ACE set should not be messed with,
unless you want to convert an inherited permission into a directly-applied
one.  In particular, you should never set this bit in new ACEs or in ACEs
where that bit was originally clear.

\anchor acesort <h3>ACE ordering</h3>

The ordering of ACEs is important, as the user will expect denied access to
take precedence over granted access, and direct permissions precedence over
inherited ones.  fksec::ace implements a less-than operator which more or
less guarantees proper ordering.  The actual ordering depends (see above)
also on the version of the OS for which the sort is done; this can, however,
be overridden.

\author Simon Fell \<simon@zaks.demon.co.uk\>
\author Felix Kasza \<felixk@mvps.org\>
\author see http://mvps.org/win32/security/fksec.html
*/

namespace fksec {

	class ace
	{
	public:
		// --- ctors/dtor ---
		//! constructs an empty ace object
		ace();
		//! constructs *this as a copy of another ace object
		ace( const ace &a );
		//! constructs *this from a PACE
		ace( const void *a );
		//! constructs *this as a (possible object) ACE from bits and pieces
		ace( byte type, byte flags, byte inheritance, ACCESS_MASK mask, const sid &newSid,
			const GUID &ObjectType = GUID_NULL, const GUID &InheritedObjectType = GUID_NULL );

		//! cleans up an ace object
		virtual ~ace();

		// --- assignment ---
		//! assigns another ace to *this
		const ace &operator=( const ace &s );
		//! assigns an NT-formatted ACE to *this
		const ace &operator=( const void *s );

		// --- conversions ---
		//! returns a pointer to an internally-maintained ACE
		operator const void *() const;

		// --- comparisons ---
		//! returns true if all of type, flags, inheritance, and sid are equal
		bool operator==( const ace &r );
		//! returns true if any of type, flags, inheritance, and sid are unequal
		bool operator!=( const ace &r );
		//! returns true if *this is "smaller" than r
		bool operator<( const ace &r );

		// --- accessors ---

		//! returns the ACE type
		/*! \return the type of the ace represented by *this
		\exception none */
		byte GetType() const { return aceType; }
		//! returns the ACE's audit flags
		/*! \return the audit flags of the ace represented by *this; note that the
		inheritance bits, which share this byte in an NT-formatted ACE, are separate
		\exception none */
		byte GetFlags() const { return aceFlags; }
		//! returns the ACE access mask
		/*! \return the access mask of the ace represented by *this
		\exception none */
		ACCESS_MASK GetMask() const { return aceMask; }
		//! returns the ACE size, in bytes
		/*! \return the size, in bytes, of the ace represented by *this
		\exception none */
		DWORD GetSize() const { return GetLength(); }
		//! returns the ACE inheritance bits
		/*! \return the inheritance flags of the ace represented by *this; note that the
		audit flags, which share this byte in an NT-formatted ACE, are separate
		\exception none */
		byte GetInheritance() const { return aceInheritance; }
		//! returns the ACE's sid
		/*! \return the sid of the ace represented by *this
		\exception none but the sid may still be invalid */
		const sid &GetSid() const { return aceSid; }

		//! return the ACE object Flags
		/*! \return the object flags that specify which GUID's are contained within this ace
		\exception none */
		DWORD GetObjectFlags() const { return aceObjectFlags ; }
		//! does this ACE contain an Object Type GUID
		/*! \return true, if the ACE currently contains an Object Type GUID, false otherwise
		\exception none */
		bool  HasObjectType() const { return ( aceObjectFlags & ACE_OBJECT_TYPE_PRESENT ) ? true : false ; }
		//! does this ACE contain an Inherited Object Type GUID
		/*! \return true, if the ACE currently contains an Inherited Object Type GUID, false otherwise *
		\exception none */
		bool  HasInheritedObjectType() const { return (aceObjectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT) ? true : false ; }
		//! returns the object type GUID
		/*! \return the Object Type GUID that identifies a property set, property, extended right, or type of child object
		\exception none */
		const GUID &GetObjectType() const { return aceObjectTypeGUID ; }
		//! returns the inherited object type GUID
		/*! \return the Inherited Object Type GUID that identifies the type of child object that can inherit the ACE
		\exception none */
		const GUID &GetInheritedObjectType() const { return aceInheritedObjectTypeGUID ; }

		//! sets a new ACE type
		void SetType( byte newType );
		//! sets new audit flags
		void SetFlags( byte newFlags );
		//! sets the new \c ACCESS_MASK for the ace
		void SetMask( ACCESS_MASK newMask );
		//! sets new inheritance bits
		void SetInheritance( byte newInheritance );
		//! sets a new sid into the ace
		void SetSid( const sid &newSid );
		//! sets a new sid into the ace
		void SetSid( const TCHAR *stringSid );

		//! sets a new object type GUID into the ace, the objectFlags and aceType are automatically updated
		/*! \param ObjectType the GUID of the object type
		\exception none*/
		void SetObjectType(const GUID &ObjectType ) ;
		//! removes the object type GUID from the ace, the objectFlags are automatically updated
		void RemoveObjectType() ;
		//! sets a new inherited object type GUID into the ace, the objectFlags and aceType are automatically updated
		/*! \param InheritedObjectType the GUID of the inherited object type
		\exception none*/
		void SetInheritedObjectType(const GUID &InheritedObjectType ) ;
		//! removes the inherited object type GUID from the ace, the objectFlags are automatically updated
		void RemoveInheritedObjectType() ;

		// --- utilities ---
		//! returns the required number of many bytes for an NT-formatted ACE
		DWORD GetLength() const;
		//! stores a copy of the ACE in a caller-supplied buffer.
		void StoreAce( void *p, DWORD sz ) const;
		//! tests *this for validity
		bool IsValid() const;

		//! returns true if this is an object ACE
		bool IsObjectACE() const ;

		// --- inserters ---
		//! dumps the ace to an iostream
		friend fkostream &operator<<( fkostream &o, const ace &a );

		/*! \enum AceSortOrder
		\brief ACE sort order control */
		enum AceSortOrder {
			//! Initial setting; when used, causes a check of OS version and appropriate use of asoNT4 or asoNT5
			asoDefault,
			//! uses the NT4 ACE sort order
			asoNT4,
			//! uses the NT5 ACE sort order, which handles auto-inherit ACEs
			asoNT5
		};

		//! retrieves the current sort order, never returns asoDefault
		static AceSortOrder GetAceSortOrder();

		//! sets ace::currentAceSortOrder to the argument's value.
		static void SetAceSortOrder( AceSortOrder aso );

	private:
		//! sets the internal PACE to 0
		void ClearPACE() const;
		//! releases the internal PACE, if any
		void ReleasePACE() const;
		//! creates the NT-formatted version of *this in an internal buffer
		void *MakePACE() const;
		//! initialize from a PACE
		void InitFromPACE( const void *a );

		//! keeps track of the current sort order
		static AceSortOrder currentAceSortOrder;

		// keep track of components we have
		//! true if the ace::aceType member was set at least once
		bool haveAceType;
		//! true if the ace::aceFlags member was set at least once
		bool haveAceFlags;
		//! true if the ace::aceMask member was set at least once
		bool haveAceMask;
		//! true if the ace::aceInheritance member was set at least once
		bool haveAceInheritance;
		// no "haveAceSid" -- aceSid.IsValid() serves here

		// ACE components
		//! ACE type value, such as \c ACCESS_ALLOWED_ACE_TYPE
		byte aceType;
		//! ACE flags, normally 0 except for audit ACEs
		byte aceFlags;
		//! ACE inheritance bits
		byte aceInheritance;
		//! ACE permissions (or denied-permissions) bit mask
		ACCESS_MASK aceMask;
		//! ACE sid
		fksec::sid aceSid;

		//! ACE OBJECT Flags
		DWORD aceObjectFlags ;
		//! ACE OBJECT ObjectType
		GUID aceObjectTypeGUID ;
		//! ACE OBJECT InheritedObjectType
		GUID aceInheritedObjectTypeGUID ; 

		//! true if ace::pace points to a current and valid NT-formatted ACE.
		mutable bool havePACE;
		//! points to an NT-formatted ACE, if and only if ace::havePACE is true
		mutable ACCESS_ALLOWED_ACE *pace;
	};

	//! dumps the ace to an iostream
	fkostream &operator<<( fkostream &o, const ace &a );

} // namespace fksec

#endif // ! defined( AFX_ACE_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
