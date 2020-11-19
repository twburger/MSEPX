// priv.h: DO NOT include this file. #include fksec.h instead!



#if ! defined( AFX_PRIV_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_PRIV_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


/*! \file priv.h
\brief interfaces and other declarations pertaining to fksec::priv,
the privilege wrapper class. */


namespace fksec {

/*! \brief The priv class wraps an NT privilege.

Privileges are like permissions in that they allow their holder to 
perform some operation. They are unlike permissions in that privileges 
do not refer to specific objects, while permissions do: FILE_READ_DATA, 
a permission bit, always refers to a particular secured object (namely 
the one in whose ACL this bit appears); SeShutdownPrivilege refers to 
an operation which is independent of any particular object -- you have 
it, or you don't.

Internally, privileges are represented by LUIDs (small ones, at that). 
They also have names like "SeTcbPrivilege", and display names like "Act 
as part of the operating system". The display name is localized in non-US 
versions of NT; the privilege name is not. The privilege names are also 
#defined into preprocessor macros by the SDK headers; SE_TCB_NAME thus 
translates to "SeTcbPrivilege". Note that there are four privileges which 
violate these naming conventions -- the logon rights are named 
"SeInteractiveLogonRight", "SeBatchLogonRight", "SeServiceLogonRight", 
and "SeNetworkLogonRight".

Privileges are assigned to user accounts through LSA functions; see my 
<a href="http://mvps.org/win32/lsa/">LSA samples</a> or the Platform 
SDK for more information.

A privilege has, at any point in time, one of three states: absent means 
that the user was not given the privilege (to be precise: the access 
token of the current process does not list it); disabled means the privilege 
is present but not yet enabled; enabled means it is present and active. 
Transitions between these states are effected through LSA (assigning or 
revoking a privilege to/from a user) or certain token manipulation 
functions (child processes can be started with a restricted set of privs), 
and through AdjustTokenPrivileges() (between the enabled/disabled states 
of a privilege that is present in the token).

Some Win32 APIs automatically try to enable needed privileges, others 
don't. If you enable any required privs in your code, you cannot go wrong.

Finally, note that privileges are machine-specific -- in administrator 
terms, you need to point User Manager at the right machine before giving 
a privilege to a user. In other words, if you just fire up usrmgr.exe 
and assign privileges, they will only be valid for users logging on to 
the domain controller.

This implementation has a hard limit of 50 privileges per token. 
Considering that NT currently only defines 31, this seems to be an 
acceptable limitation.

The destructor of class priv does <i>not</i> reset the privilege state 
to the one that the priv had when it was first queried by the class. 
You can therefore create priv objects on the stack, and the changes to 
privilege states will persist beyond the object's lifetime.

\author Felix Kasza \<felixk@mvps.org\>
\author see http://mvps.org/win32/security/fksec.html
*/

	class priv
	{
	public:
		// --- ctors/dtor ---

		/*! \brief constructs an empty priv object.
		  \exception none
		*/
		priv();

		/*! \brief constructs *this from another priv instance.

		  This constructor sets *this to the state of the priv object s. 
		  \param s the priv object to which *this is to be set.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		priv( const priv &s );

		/*! \brief constructs *this from a LUID representing a privilege.

		  This constructor sets *this to the LUID passed in the argument s. 
		  It also does the necessary lookups to retrieve the canonical form 
		  of the name, and the display name.
		  \param s the LUID to which *this is to be set.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		priv( const LUID s );

		/*! \brief constructs *this from a LUID in __int64 form.

		  This constructor sets *this to the integer passed in s. It also 
		  does the necessary lookups to retrieve the canonical form of the 
		  name, and the display name.
		  \param s the 64bit integer to which *this is to be set.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		priv( unsigned __int64 s );

		/*! \brief constructs *this by by looking up a privilege name.

		  This ctor calls LookupValue() to look up the privilege name 
		  passed in and sets *this to the returned LUID. It also does 
		  the necessary lookups to retrieve the canonical form of the 
		  name, and the display name.
		  \param name the pointer to the name of the privilege to which *this 
		  is to be set.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		priv( const TCHAR *name );

		/*! \brief destructs a priv instance, masks exceptions.

		  The destructor attempts to close the token handle, should it be 
		  open. The current state of the privilege is not affected.
		  \exception none
		*/
		virtual ~priv();

		// --- assignment ---

		/*! \brief sets *this to the privilege corresponding to another priv instance.

		  This overload of the assignment operator sets *this to the same 
		  privilege and token handle as the priv object passed in the 
		  argument s. *this gets its own duplicate of the access token 
		  handle, if s has an open handle.
		  \param s the priv object whose state is to be copied.
		  \return a const reference to *this.
		  \exception errCloseToken
		  \exception errDupTokenHandle
		  \exception errInvalidPriv
		*/
		const priv &operator=( const priv &s );

		/*! \brief sets *this to the privilege corresponding to a LUID.

		  This overload of the assignment operator sets *this to the LUID 
		  passed in the argument s. It also does the necessary lookups to 
		  retrieve the canonical form of the name, and the display name.
		  \param s the LUID to which *this is to be set.
		  \return a const reference to *this.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		const priv &operator=( const LUID s );

		/*! \brief sets *this to the privilege corresponding to an integer.

		  This overload of the assignment operator sets *this to the integer 
		  passed in the argument s. It also does the necessary lookups to 
		  retrieve the canonical form of the name, and the display name.
		  \param s the 64bit integer to which *this is to be set.
		  \return a const reference to *this.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		const priv &operator=( unsigned __int64 s );

		/*! \brief sets *this to the privilege corresponding to name.

		  This overload of the assignment operator calls LookupValue() to look 
		  up the privilege name passed in and sets *this to the returned LUID. 
		  It also does the necessary lookups to retrieve the canonical form 
		  of the name, and the display name.
		  \param name the pointer to the name of the privilege to which *this 
		  is to be set.
		  \return a const reference to *this.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		const priv &operator=( const TCHAR *name );

		// --- comparisons ---

		/*! \brief compares two privilege numbers for equality.

		  operator ==() compares the privilege LUIDs managed by *this and 
		  argument r for equality. It does <i>not</i> compare privilege the 
		  states, and it does <i>not</i> consider whether the objects might 
		  refer to the same access token.
		  \param r the priv object to compare *this against.
		  \retval true if this->privNum == r.privNum
		  \retval false if this->privNum != r.privNum
		  \exception none
		*/
		bool operator==( const priv &r ) const;

		/*! \brief compares two privilege numbers for inequality.

		  operator !=() compares the privilege LUIDs managed by *this and the 
		  argument r for inequality. It does <i>not</i> compare privilege 
		  states, and it does <i>not</i> consider whether the objects might 
		  refer to the same access token.
		  \param r the priv object to compare *this against.
		  \retval true if this->privNum != r.privNum
		  \retval false if this->privNum == r.privNum
		  \exception none
		*/
		bool operator!=( const priv &r ) const;

		// --- utilities ---

		/*! \brief returns the name of the privilege.

		  The name of a privilege is looked up and cached as soon 
		  as the object's privNum is set. This may not be ideal from a 
		  performance point of view, but given the normal use of privs, 
		  I don't see a problem with this. Not that I wouldn't rewrite it 
		  if I had the time.
		  \return a pointer to a null-terminated string containing the 
		  privilege's name.
		  \exception none
		*/
		const TCHAR *GetPrivilegeName() const;

		/*! \brief returns the (localised) display name of the privilege.

		  The display name of a privilege is looked up and cached as soon 
		  as the object's privNum is set. This may not be ideal from a 
		  performance point of view, but given the normal use of privs, 
		  I don't see a problem with this. Not that I wouldn't rewrite it 
		  if I had the time.
		  \return a pointer to a null-terminated string containing the 
		  privilege's display name.
		  \exception none
		*/
		const TCHAR *GetDisplayName() const;

		/*! \brief enables the the privilege.

		  Enable() attempts to enable the privilege. The previous state of 
		  the privilege is returned.
		  \retval true if the privilege was enabled before this call
		  \retval false if the privilege was not enabled before this call
		  \exception errCloseToken
		  \exception errOpenToken
		  \exception errStubbornPriv
		*/
		bool Enable();

		/*! \brief disables the the privilege.

		  Disable() attempts to disable the privilege. The previous state of 
		  the privilege is returned.
		  \retval true if the privilege was enabled before this call
		  \retval false if the privilege was not enabled before this call
		  \exception errCloseToken
		  \exception errOpenToken
		  \exception errStubbornPriv
		*/
		bool Disable();

		/*! \brief inverts the state of the privilege.

		  Toggle() attempts to invert the privilege state. The previous state 
		  of the privilege is returned.
		  \retval true if the privilege was enabled before this call
		  \retval false if the privilege was not enabled before this call
		  \exception errCloseToken
		  \exception errOpenToken
		  \exception errQueryToken
		  \exception errStubbornPriv
		*/
		bool Toggle();

		/*! \brief sets the new state of the privilege.

		  SetState() takes a boolean and attempts to enable or disable the 
		  privilege, depending on newState being true or false. The previous state of the privilege is returned.
		  \param newState true to enable the privilege, false to disable it
		  \retval true if the privilege was enabled before this call
		  \retval false if the privilege was not enabled before this call
		  \exception errCloseToken
		  \exception errOpenToken
		  \exception errStubbornPriv
		*/
		bool SetState( bool newState );

		/*! \brief queries the current state of our priv.

		  GetState() checks the token for the current state of the privilege 
		  managed by *this. If the privilege is not present in the token, it 
		  is treated as disabled.

		  Note that this function will break if a token ever has more than 50 
		  privileges. However, this is unlikely, considering that there are 
		  only 31 defined privileges in the first place.
		  \retval true if the privilege is enabled
		  \retval false if the privilege is disabled or not present in the token
		  \exception errCloseToken
		  \exception errOpenToken
		  \exception errQueryToken
		*/
		bool GetState() const;

		/*! \brief sets the token handle to be used for future method calls.

		  SetHandle() takes a single argument, which may be either NULL or a 
		  valid handle to an access token opened for TOKEN_DUPLICATE access. 
		  Any previously opened token handle is closed, and if a non-NULL 
		  handle was supplied, a duplicate of that handle is created and stored 
		  in *this. The caller is responsible for closing his original handle; 
		  the priv class is responsible for closing the duplicated handle. 
		  (The issue can always be forces with a <code>SetHandle(0)</code> call.)
		  \param h The token handle to duplicate for future use with this 
		  object, or NULL to use the current thread or process token.
		  \exception errCloseToken
		  \exception errDupTokenHandle
		*/
		void SetHandle( HANDLE h );

		// --- inserters ---

		/*! \brief dumps interesting factoids about a priv instance into an
		  ostream or wostream.
		  \param o the ostream or wostream to insert the priv instance into
		  \param p the priv instance to dump
		  \return a reference to the ostream, as usual for inserters
		  \exception none
		*/
		friend fkostream &operator<<( fkostream &o, const priv& p );

	private:

		/*! \brief initialises all members of a priv object.

		  Init() creates the initial state of a priv object. No resources are 
		  released; do not call if *this has an open token handle!
		  \exception none
		*/
		void Init();

		/*! \brief open the access token, if necessary.

		  openToken() is called internally when a token handle is needed. If 
		  a token handle is already set, no action is taken. Otherwise, an 
		  attempt is made to open the current thread token; if that fails, 
		  and there is a chance of recovery (for instance, if the current thread 
		  is not impersonating), the process token is opened.
		  \exception errOpenToken
		*/
		void openToken() const;

		/*! \brief close the handle to the token.

		  closeToken() is used internally to close the handle to the process 
		  token. There is normally no need to call it explicitly.
		  \exception errCloseToken
		*/
		void closeToken() const;

		/*! \brief looks up the priv and display names for our LUID, caches them.

		  LookupNames() retrieves the privilege name and the display name for 
		  the privilege LUID that *this represents. An exception is thrown in 
		  case of failure.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		void LookupNames() const;

		/*! \brief looks up the LUID for the given privname, save in privNum.

		  LookupValue() takes a privilege name (<i>not</i> a display name), 
		  translates it to a privilege LUID, and sets *this to represent this 
		  privilege. If the name cannot be translated, an exception is thrown.
		  \param name The name of the privilege to be looked up.
		  \exception errInvalidPriv
		  \exception errNoMemory
		*/
		void LookupValue( const TCHAR *name );

		//! privNum holds the LUID of the privilege represented by *this.
		LUID privNum;

		//! privName holds the NT name for the privilege privNum.
		mutable fkstr privName; // privilege name
		
		//! privName holds the (localised) display name for the privilege privNum.
		mutable fkstr dispName; // displayName

		/*! \brief ht is the handle to the access token to be manipulated.

		  If ht == 0, the current thread or process token will automatically 
		  be opened when necessary (thread token first; if that fails, the 
		  process token).
		*/
		mutable HANDLE ht;
	};

	/*! \brief dumps interesting factoids about a priv instance into an
	  ostream or wostream.
	  \param o the ostream or wostream to insert the priv instance into
	  \param p the priv instance to dump
	  \return a reference to the ostream, as usual for inserters
	  \exception none
	*/
	fkostream &operator<<( fkostream &o, const priv& p );

} // namespace fksec

#endif // ! defined( AFX_PRIV_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
