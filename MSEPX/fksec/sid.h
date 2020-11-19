// sid.h: DO NOT include this file. #include fksec.h instead!



#if ! defined( AFX_SID_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_SID_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


/*! \file sid.h
\brief declares the fksec::sid class */


namespace fksec {

/*! \class sid
\brief The sid class mimics an NT SID object (Security Identifier).

SIDs are strings of numbers that uniquely (one hopes) identify an 
entity within a certain context.  Their major features are an "authority" 
which is basically the subsystem or general area issuing a SID, and a 
series of DWORDs (RIDs) which, in a hierarchical manner, narrow down to 
a single entry.  Here, for example, is my SID when I log on as 
Administrator, expressed as a string:

\code
	S-1-5-21-484763869-764733703-1202660629-500
\endcode

All users in my domain would have an identical SID, except for the last 
value.  This last value is technically just one of 5 RIDs that are 
present, but in practice we call the last RID "the RID," and what goes 
before it is the "prefix."  Here, the prefix is at the same time a domain 
SID, because it identifies the domain in which user 500 lives, and a 
domain SID that is part of a complete, larger SID is often called a 
"domain prefix."

An object of class sid encapsulates just such a SID and happily converts 
between NT-formatted SIDs, user/group/domain/… names, and the textual 
representation above, which is what you can see in the HKEY_USERS key of 
your registry, too.  It also provides a const PSID conversion operator so 
you can plug an sid into any place where you would normally use a const PSID.

<h4>A note on the validity of sid instances</h4>

A sid object may, at any time, be in an invalid state, or in a valid one. 
Without going into details, it becomes valid as soon as it has an sia 
(SID_IDENTIFIER_AUTHORITY) value and at least one RID. Using an invalid 
sid object anywhere is very likely to reward you with an exception, so 
make sure of your exception handling.

\author Simon Fell \<simon@zaks.demon.co.uk\>
\author Felix Kasza \<felixk@mvps.org\>
\author see http://mvps.org/win32/security/fksec.html
*/

	class sid;

	//! SidList is an alias for a vector of fksec::sid objects
	typedef std::vector<fksec::sid> SidList;

	class sid
	{
	public:
		//! The SidType enumeration, used by LookupSidType(), provides values which identify a SID as local or remote.
		enum SidType
		{
			/*! refers to SIDs which are always local and which do 
			not belong to any account domain. Examples are the SIDs for 
			Everyone, LocalSystem. */
			stWellKnown,
			/*! refers to SIDs residing in the local machine's accounts 
			database -- local users and local groups, mostly. */
			stLocal,
			/*! is used for accounts which reside in the domain 
			controller's accounts database, including domain users and global 
			groups. */
			stDomain,
			/*! is the tag for SIDs whose domain prefix does not match 
			the local prefixes, and for which no domain can be identified. */
			stForeign
		};

		// --- ctors/dtor ---

		//! construct *this as an empty sid object
		sid();

		//! construct *this as a copy of another sid object
		sid( const sid &s );

		//! Construct *this as a copy of a SID
		sid( const PSID s );

		//! Construct *this by interpreting a string SID or looking a name up in the accounts database
		sid( const TCHAR *name );

		//! construct *this from bits and pieces
		sid( SID_IDENTIFIER_AUTHORITY newsia, DWORD nSubAuths,
			DWORD subAuth0 = 0, DWORD subAuth1 = 0, DWORD subAuth2 = 0,
			DWORD subAuth3 = 0, DWORD subAuth4 = 0, DWORD subAuth5 = 0,
			DWORD subAuth6 = 0, DWORD subAuth7 = 0 );

		//! construct *this from different bits and pieces
		sid( unsigned __int64 newsia, DWORD nSubAuths,
			DWORD subAuth0 = 0, DWORD subAuth1 = 0, DWORD subAuth2 = 0,
			DWORD subAuth3 = 0, DWORD subAuth4 = 0, DWORD subAuth5 = 0,
			DWORD subAuth6 = 0, DWORD subAuth7 = 0 );

		//! clean up *this
		virtual ~sid();

		// --- assignment ---

		//! set *this to a copy of a sid, including the valid/invalid state
		const sid &operator=( const sid &s );

		//! set *this to a copy of a SID
		const sid &operator=( const PSID s );

		//! set *this to a SID derived from interpreting a string SID or looking a name up in the accounts database
		const sid &operator=( const TCHAR *name );

		// --- conversions ---

		//! return a pointer to an NT-formatted SID
		operator const PSID() const;

		// --- comparisons ---

		//! compares two sid objects for less-than
		bool operator<( const sid &r ) const;

		//! compares two sid objects for equality
		bool operator==( const sid &r ) const;

		//! compares two sid objects for inequality
		bool operator!=( const sid &r ) const;

		//! compares the prefixes of two sid objects for equality
		bool EqualPrefix( const sid &r ) const;


		// --- utilities ---

		//! computes the number of bytes needed to store *this as an NT SID
		DWORD GetLength() const;

		//! returns the SID_IDENTIFIER_AUTHORITY value as a 64-bit integer
		__int64 GetSidIdentifierAuthority() const;

		//! truncates *this by removing the last subauthority value
		void RemoveLastRid();

		//! appends a RID to the end of this sid
		void AppendSubAuthority( DWORD rid );

		//! sets a new value for an existing RID
		void SetSubAuthority( DWORD index, DWORD rid );

		//! returns a specified subauthority value
		DWORD GetSubAuthority( DWORD index ) const;

		//! returns the current subauthority count
		DWORD GetSubAuthorityCount() const;

		//! tests *this for validity
		bool IsValid() const;

		//! translates SID_NAME_USE to text description
		static const TCHAR *SnuToText( SID_NAME_USE snu );

		//! returns the string representation of *this
		fkstr ConvertToStringSid() const;

		//! stores a SID into a client-provided buffer
		void StoreSid( PSID ps, DWORD size ) const;

		//! sets *this to the SID represented by a stringified SID
		void ConvertFromStringSid( const TCHAR *stringsid );

		//! sets *this to the SID of an account looked up on a server
		void LookupName( const TCHAR *server, const TCHAR *name );

		//! retrieves the account name and domain for the sid
		void LookupSid( const TCHAR *server, fkstr &name,
			fkstr &domain, SID_NAME_USE &snu ) const;

		//! determines the server on which the SID resides
		SidType LookupSidType();

		//! retrieves the list of groups that this user is a member of
		SidList MemberOf( bool bIncludeGlobal, bool bIncludeLocal, bool bIncludeIndirect, const TCHAR *server = NULL );

		//! retrieves all the members of this group.
		SidList Members( const TCHAR *server = NULL );

		// --- inserters ---

		//! Inserts a textual representation, suitable for debugging, into an output stream
		friend fkostream &operator<<( fkostream &o, const sid &s );

	private:
		//! initializes all members of a sid object to zero and sets its state to invalid
		void Init();

		//! sets psid to NULL and havePSID to false
		void ClearPSID() const;

		//! releases psid memory, if any, and sets psid to NULL and havePSID to false
		void ReleasePSID() const;

		//! reads and converts a "-<uint64>" string
		bool CvsGetUInt64( const TCHAR *&str, unsigned __int64 &r );

		//! generates a PSID from *this
		PSID MakePSID() const;


		//! isValid remains false until a valid SID can be built.
		bool isValid;

		// SID components

		//! sia contains the sid's SID_IDENTIFIER_AUTHORITY value.
		/*! sia is mutable because ::InitializeSid() wants a non-const 
		pointer. Feh! */
		mutable SID_IDENTIFIER_AUTHORITY sia;

		//! subAuthCount gives the current number of subauthorities in *this.
		DWORD subAuthCount;

		//! subAuth[] contains the list of subauthorities.
		DWORD subAuth[SID_MAX_SUB_AUTHORITIES];

		//! havePSID indicates whether psid is valid and points to an NT-formatted SID reflecting the contents of *this.
		/*! If havePSID is false, psid is invalid, even if non-NULL. Do 
		not rely on whether psid is NULL or not!
		\sa MakePSID
		\sa ReleasePSID */
		mutable bool havePSID;

		//! psid points to a new()ed chunk of memory which holds an NT-formatted SID representing *this.
		/*! If havePSID is false, psid is not to be relied on! */
		mutable PSID psid;

	public:
		// constant, well-known SIDs

		//! \name constant SIDs outside NT AUTHORITY
		//@{
		//! S-1-0-0 null SID
		const static sid sidNull;
		//! S-1-1-0 World (Everyone)
		const static sid sidWorld;
		//! S 1-2-0 Local
		const static sid sidLocal;
		//! S-1-3-0 Creator Owner
		const static sid sidCreatorOwner;
		//! S-1-3-1 Creator Group
		const static sid sidCreatorGroup;
		//! S-1-3-2 Creator Owner Server
		const static sid sidCreatorOwnerServer;
		//! S-1-3-3 Creator Group Server
		const static sid sidCreatorGroupServer;
		//@}

		//! \name constant SIDs in the NT AUTHORITY domain
		//@{
		//! S-1-5- prefix for built-in accounts and groups
		const static sid sidNtAuthority;
		//! S-1-5-1 Dialup users
		const static sid sidDialup;
		//! S-1-5-2 Network logons
		const static sid sidNetwork;
		//! S-1-5-3 Batch logons
		const static sid sidBatch;
		//! S-1-5-4 Interactive logons
		const static sid sidInteractive;
		//! S-1-5-5- prefix for logon session SIDs, requires two more RIDs
		const static sid sidLogon;
		//! S-1-5-6 Service logons
		const static sid sidService;
		//! S-1-5-7 Anonymous (null session)
		const static sid sidAnonymousLogon;
		//! S-1-5-8 Logon by proxy
		const static sid sidProxy;
		//! S-1-5-9 DC account
		const static sid sidServerLogon;
		//! S-1-5-10 Self (current caller)
		const static sid sidSelf;
		//! S-1-5-11 Authenticated users (as opposed to World)
		const static sid sidAuthenticated;
		//! S-1-5-12 Indicates a restricted token
		const static sid sidRestricted;
		//! S-1-5-13 Token from Terminal Server
		const static sid sidTerminalServer;
		//! S-1-5-18 LocalSystem (NT AUTHORITY\SYSTEM)
		const static sid sidLocalSystem;
		//@}

		//! \name functions returning semi-constant SIDs in an account domain
		/*! \todo Add sid::GetDomainFooSid() functions to return domain-SID-dependent well-known SIDs. */
		//@{
		//! S-1-5-21- prefix for domains, domain accounts, etc.
		const static sid sidNonUnique;
		//@}

		//! \name constant SIDs in the built-in domain
		//@{
		//! S-1-5-32 built-in domain
		const static sid sidBuiltin;
		//! S-1-5-32-500 local admin account
		const static sid sidLocalAdministrator;
		//! S-1-5-32-501 local guest account
		const static sid sidLocalGuest;
		//! S-1-5-32-544 Administrators
		const static sid sidLocalAdministrators;
		//! S-1-5-32-545 Users
		const static sid sidLocalUsers;
		//! S-1-5-32-546 Guests
		const static sid sidLocalGuests;
		//! S-1-5-32-547 Power Users
		const static sid sidLocalPowerUsers;
		//! S-1-5-32-548 Account Operators
		const static sid sidLocalAccountOperators;
		//! S-1-5-32-549 System Operators
		const static sid sidLocalSystemOperators;
		//! S-1-5-32-550 Print Server Operators
		const static sid sidLocalPrintOperators;
		//! S-1-5-32-551 Backup Operators
		const static sid sidLocalBackupOperators;
		//! S-1-5-32-552 File replicator account
		const static sid sidLocalReplicator;
		//! S-1-5-32-553 Ras servers
		const static sid sidLocalRasServers;
		//! S-1-5-32-554 SID used to validate Net*() access from NT4 machines
		const static sid sidLocalPreW3KCompAccess;
		//@}
	};

	//! Inserts a textual representation, suitable for debugging, into an output stream
	fkostream &operator<<( fkostream &o, const sid &s );

} // namespace fksec

#endif // ! defined( AFX_SID_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
