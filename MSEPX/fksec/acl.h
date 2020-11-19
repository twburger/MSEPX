// acl.h: DO NOT include this file. #include fksec.h instead!


#if ! defined( AFX_ACL_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_ACL_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


/*! \file acl.h
\brief declares the fksec::acl class */


/*! \class fksec::acl
  \brief The acl class represents an ACL (Access Control List).

  <h3>Introduction</h3>
  An ACL is an NT security structure representing an access-control
  list, a list of access-control entries or ACEs. (Read more about
  ACEs in the \ref aceintro "introduction for fksec::ace".)

  Taken by themselves, ACLs are rather uninteresting, but they do
  have a few facets that may be worth a closer look.

  <h3>Evaluating effective permissions</h3>

  Whenever NT has to determine whether a requested access to an object
  is to be permitted, it runs down the list of ACEs in the ACL and
  checks for every ACE whether that ACE's SID is the user's SID, or
  in the list of the user's groups. If so, it compares the requested
  access to the access granted or denied by that ACE. If a requested
  access is explicitly denied, evaluation stops here (with a final
  result of "denied"). If the ACE grants some of the requested access
  modes (each represented by a bit), the granted access bits are added
  to the granted permission from earlier ACEs; if the sum total of
  those permissions covers all requestedpermissions, the evaluation
  stops with a final result of "granted". If the last ACE has been
  read, and there are still requested permissions that have not been
  granted, the access is denied.

  <h3>ACE ordering and its effect on permissions</h3>

  Obviously, the ordering of ACEs has a major impact on the result of
  this method of evaluating permissions. Imagine that user felixk is a
  member of group lubberly_boobies, is requesting read permission for
  some object or other, and that the object's ACL looks like this:

  <table>
    <tr>
      <td>felixk</td>
      <td>grant-read</td>
    </tr>
    <tr>
      <td>lubberly_boobies</td>
      <td>deny-read</td>
    </tr>
  </table>

  According to the above rules, this ACL would grant felixk read access
  to the object in question. This ACL, on the other hand, would deny him
  access:

  <table>
    <tr>
      <td>lubberly_boobies</td>
      <td>deny-read</td>
    </tr>
    <tr>
      <td>felixk</td>
      <td>grant-read</td>
    </tr>
  </table>

  To avoid ambiguities like this, Microsoft defines a canonical ordering
  of ACEs within an ACL.

  <h3>Canonical ACE ordering</h3>

  While NT's Security Reference Monitor will happily evaluate ACEs in any
  order that you might like to use, the GUI tools rely on a specific sort
  order -- and so does the administrator, who expects a denial of access
  for user felixk to take precedence over whatever permissions felixk's
  groups may have been granted.

  On NT5 (and on NT4 with the Security Configuration Editor upgrade, which
  comes with SP4 and higher), there are additional rules dealing with those
  ACEs that are inherited from the containing or parent object. These rules
  are discussed in the \ref acesort "ACE ordering" section of the ace docs
  and, more extensively, \ref acesortrules "in the code" itself.

  Obviously, it is a pain to get the ordering right manually; to lessen the
  discomfort, the ace class provides the member function canonicalize(),
  which will resort the ACEs into their proper order. Note that this order
  is dependent on the version of NT that you are creating the ACL for; the
  ace::operator<() takes this into account and defaults to the rules for
  the OS the code is running on, but ace::SetAceSortOrder() lets you
  override this.

  <h3>ACE folding</h3>

  Also of interest in this respect may be the normalize() function, which
  folds multiple ACEs into one. The rules for this operation are simple: if
  two ACEs are the same except for the access masks (i.e., same type, same
  SID, same inheritance, same flags), then the access mask of the second one
  is ORed into the access mask for the first one, and the second ace is
  deleted.
  
  For you as a programmer, this means that, when granting some permission
  to felixk, you no longer have to check whether there already is an ACE for
  him, and you no longer have to decide whether to update that ACE or create
  a new one -- just append a new ace object to the list, call normalize()
  and canonicalize() on the acl, and there you are.

  <h3>Inheritance and auto-inheritance</h3>

  An ACL knows nothing about inheritance at all. Insofar as it affects the
  ordering of ACEs, it is handled in the ace class; the rest is bundled with
  the security descriptors.

  <h3>Empty ACLs vs. NULL ACLs</h3>

  When looking at ACLs, there is no such thing as a NULL DACL. A NULL DACL
  refers to the complete and entire absence of a DACL. If a DACL does exist,
  it may possibly be empty (and therefore deny all access(). Since teh concept
  of a NULL DACL only makes sense in the context of a security descriptor,
  fksec handles the absence of DACL's there.

  \author Simon Fell \<simon@zaks.demon.co.uk\>
  \author Felix Kasza \<felixk@mvps.org\>
  \author see http://mvps.org/win32/security/fksec.html
*/


namespace fksec {

	//! shorthand for a list of fksec::ace
	typedef std::vector<fksec::ace> AceList;
	//! shorthand for an iterator into a list of fksec::ace
	typedef fksec::AceList::iterator AceListIter;
	//! shorthand for a reverse iterator into a list of fksec::ace
	typedef fksec::AceList::reverse_iterator AceListRevIter;
	//! shorthand for a read-only iterator into a list of fksec::ace
	typedef fksec::AceList::const_iterator AceListConstIter;

	class acl
	{
	public:
		// --- ctors/dtor ---
		//! \name Constructors, destructor
		//@{
		//! constructs an empty acl object
		acl();
		//! constructs *this from another acl object
		acl( const acl &a );
		//! constructs *this from a PACL
		acl( ACL *a );
		//! cleans up *this
		virtual ~acl();
		//@}

		// --- assignment ---
		//! \name Assignment operators
		//@{
		//! assigns another acl to *this
		const acl &operator=( const acl &s );
		//! assigns an NT-formatted ACL to *this
		const acl &operator=( ACL *s ); // why oh why does NT want a non-const ACL*?
		//@}

		// --- conversions ---
		//! \name Conversions and casts
		//@{
		//! returns a pointer to an internally-maintained ACL
		// ask me if I wish that the NT guys used "const"!
		operator ACL *() const;
		//@}

		// --- accessors ---
		//! \name Accessors
		//@{
		//! returns a const reference to the Nth ACE
		const ace &GetAce( DWORD index ) const;
		//! returns a non-const reference to the Nth ACE
		ace &GetAce( DWORD index );
		//! returns the number of bytes required for *this when formatted as an ACL
		DWORD GetSize() const;
		//! returns the minimum bytes required for *this in ACL format
		DWORD GetMinimumSize() const { return GetLength(); }
		//! returns the current number of aces
		DWORD GetCount() const;
		//! sets the amount of bytes to leave free when *this is formatted as an ACL
		void SetFreeBytes( DWORD newAdditionalBytes );
		//! returns the number of free bytes in an NT-formatted ACL
		DWORD GetFreeBytes() const;
		//@}

		// --- utilities ---
		//! \name Utility functions
		//@{
		//! adds an ACE (in fksec::ace form) to *this
		// index gives the position _before_ which the ACE will be inserted
		// (DWORD) -1 inserts at end
		// no need to worry about canonical order, you can always canonicalize() the ACL
		void AddAce( DWORD index, const ace &a );
		//! adds an ACE (in bits and pieces) to *this
		void AddAce( DWORD index, byte type, byte flags, byte inheritance,
			ACCESS_MASK mask, const sid &newSid, const GUID &ObjectType = GUID_NULL,
			const GUID &InheritedObjectType = GUID_NULL );
		//! deletes a given ace
		void DeleteAce( DWORD index );
		//! deletes all aces for a specific SID
		void DeleteAcesForSid( const sid &delSid );
		//! returns effective rights for a given user- and group-list -- correctly, one hopes
		ACCESS_MASK GetEffectiveRights( const SidList& sids );
		//! normalizes the acl (folds aces with same type/flags/inheritance/sid)
		// normalize ACEs -- ACEs with same type, flags, inheritance,
		// and SID are merged by ORing their masks. This means you can
		// just blindly add ACEs and then call normalize().
		void normalize();
		//! sorts the acl's aces into canonical order (stable sort)
		// deny-ACEs first, then allow-ACEs,
		// then all others. This is a stable sort.
		void canonicalize();
		//! returns the number of bytes that *this would take as an ACL
		DWORD GetLength() const;
		//! stores a copy of *this as an NT-formatted ACL where the caller wants it
		void StoreAcl( ACL *p, DWORD sz ) const;
		//! tests *this for validity
		bool IsValid() const;
		//! tests *this for object ACEs
		bool IsObjectACL() const;
		//@}

		// --- inserters ---
		//! \name Stream inserter
		//@{
		//! dumps *this
		friend fkostream &operator<<( fkostream &o, const acl &a );
		//@}

	private:
		//! \name Internal helper functions
		//@{
		//! initializes all members of *this
		void Init();
		//! initializes the PACL part
		void ClearPACL() const;
		//! releases the PACL part
		void ReleasePACL() const;
		//! allocates and fills the internal ACL buffer
		ACL *MakePACL() const;
		//! returns the required ACL revision depending on presence/absence of object ACEs
		DWORD GetRequiredAclRevision() const;
		//@}

		//! the vector of aces managed by *this
		fksec::AceList aces;
		//! additional (unused) bytes to allocate when creating an NT-formatted ACL
		/*! When dealing with NT's low-level functions, it is often useful to reserve
		some unused space in the ACL; later on, one may use such space to add ACEs
		without having to allocate a new, larger, block of memory and without having
		to copy the existing crud into that new allocation.
		\par
		In the context of fksec, this extra allocation is not necessary at all, as
		fksec always parses NT structures, moving the relevant bits into internal data
		structures at a small cost in processor time (and for a large gain in comfort).
		\par
		Still the feature is provided for those who create ACLs that may also be added
		to by other software. */
		DWORD additionalBytes;

		//! true if we have a current NT-formatted ACL
		// true also implies that pacl points to new-ed memory; false implies
		// the opposite. Do not rely on pacl being NULL or non-NULL!
		mutable bool havePACL;
		//! the NT-formatted ACL
		mutable ACL *pacl;
	};

	//! dumps *this
	fkostream &operator<<( fkostream &o, const acl &a );

} // namespace fksec

#endif // ! defined( AFX_ACL_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
