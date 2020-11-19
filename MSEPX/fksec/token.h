//==============================================================================
// token.h: DO NOT include directly, #include fksec.h instead
//==============================================================================

#ifndef _TOKEN_H_
#define _TOKEN_H_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

namespace fksec {

// declare our own TOKEN_ALL_ACCESS
// constant to get around the PSDK quirks
#ifdef TOKEN_ALL_ACCESS
#undef TOKEN_ALL_ACCESS
#define TOKEN_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED  |\
                          TOKEN_ASSIGN_PRIMARY      |\
                          TOKEN_DUPLICATE           |\
                          TOKEN_IMPERSONATE         |\
                          TOKEN_QUERY               |\
                          TOKEN_QUERY_SOURCE        |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT )
#endif

   /** The token_group class represents an NT group object in an access token.

        One such group has two major features:
        <ul>
            <li>A group SID, identifying the group, which is stored here
              as a fksec::sid object.
            <li>A set of Attributes, or flags, that indicate how the
              group is used in the access token.
        </ul>
  
        This simple wrapper class allows you to view or change a given
        group's attributes.

        @author Tomas Restrepo \<tomasr@mvps.org\>
		@author see http://mvps.org/win32/security/fksec.html
   */
   class token_group
   {
   public:
      /** Construct *this out of a sid and some attributes

          @exceptions none
      */
      token_group ( const sid & newSid, DWORD attributes );
      /** Construct *this out of a SID_AND_ATTRIBUTES struct

          @exceptions none
      */
      token_group ( const SID_AND_ATTRIBUTES * group );
      /** Construct *this as a copy of another token_group object

          @exceptions none
      */
      token_group ( const token_group & g );
      /** Set *this to a copy of another token_group
         
          @returns a const reference to *this
          @exceptions none
      */
      const token_group & operator= ( const token_group & g );
      /** Compare this token_group to another object
         
          @returns 1 if both the group's sid and attributes are equal
          @exceptions none
      */
      int operator== ( const token_group & g ) const;
      /** Compare this token_group to another object
         
          @returns 1 if either the group's sid or attributes are different
          @exceptions none
      */
      int operator!= ( const token_group & g ) const;
      /** Compare this token_group to a group sid
         
          @returns 1 if the group's sid and s are equal
          @exceptions none
      */
      int operator== ( const sid & s ) const;
      /** Compare this token_group to a group sid
         
          @returns 1 if the group's sid and s are different
          @exceptions none
      */
      int operator!= ( const sid & s ) const;

      // -- accessors --
      /** Get this group's sid
         
          @returns a const reference to the group's sid
          @exceptions none
      */
      const sid & GetSid ( ) const;
      /** Get this group's attribute flags
         
          @returns a DWORD with the attribute flags
          @exceptions none
      */
      DWORD GetAttributes ( ) const;
      /** Set this group's attribute flags
         
          After changing the group's attributes
          you must make the change in the token by
          calling token::SetGroups()

          newAttr can be a combination of the following flags:

			- SE_GROUP_ENABLED
			- SE_GROUP_ENABLED_BY_DEFAULT
			- SE_GROUP_LOGON_ID
			- SE_GROUP_MANDATORY
			- SE_GROUP_OWNER
			- SE_GROUP_RESOURCE (W2k only)
			- SE_GROUP_USE_FOR_DENY_ONLY (W2k only)

          @exceptions none
      */
      void SetAttributes ( DWORD newAttr );
   private:
      /** The SID identifying this group
      */
      fksec::sid   groupSid;
      /** This group's attributes in the token
      */
      DWORD groupAttr;
   };
   typedef std::vector<token_group> group_list;
   typedef std::vector<priv> privilege_list;

   /** The token class represents an NT access token.

       An access token is a kernel objects that holds information regarding the
       security context a thread or process is running under. It holds information such
       as the user's sid, what privileges the user holds, what groups the user belongs to
       and what access permissions will be assigned by default to created objects.
  
       Every process in the system has an primary token associated with it. Most processes inherit
       their token from their parent process, except if they are created using CreateProcessAsUser(),
       which allows you to specify a different access token. For processes running on the interactive  
       workstation, their token can usually be traced back to the token created when the user logs on
       in behalf of WinLogon.exe (the local authority subsystem, lsass.exe, is the one that actually
       creates the token).

       Usually, thread´s have no token associated with them, unless one of three things happen:
       <ol>
       <li>The thread impersonates a client, as a result of a call to ImpersonateNamedPipeClient(),
          impersonateSecurityContext(), RpcImpersonateClient() or any such api. In this case, the thread get´s 
          assigned a token representing the given client, with certain limitations (see below).
          After a call to RevertToSelf(), or similar api, the thread
       <li>The thread calls ImpersonateSelf(), in which case the thread gets associated with an impersonation
          token created from the primary token its parent process has.
       <li>SetThreadToken() is called.
       </ol>

       There are four levels of Impersonation levels, which dictate what you can do with the impersonation 
       token assigned to a thread:
       <ol>
       <li>SecurityAnonymous: Not much useful, since you don´t know who the token represents, nor can you act 
          on their behalve.
       <li>SecurityIdentification: Somewhat more useful, since at least you can know who the token represents
          with a call to GetTokenInformation ( ..., TokenUser, ... );. You still can´t impersonate the client, though.
       <li>SecurityImpersonation: Like the last one, only you can really impersonate the client now, but only 
          on operations on the local system. You can use such a token in calls to AccessCheck() or PrivilegeCheck().
       <li>SecurityDelegation (W2K only): A delegation token allows you to impersonate the client against remote
          systems, too. 
       </ol>
  
       There are, however, times when the system will still check the primary process token, even if the current thread
       has an impersonation token:
       <ul>
       <li>When CreateProcess() is called, the primary token is always used, since an impersonation token can´t be
         assigned to a process. You can, however, provided you have the required privileges, turn an impersonation token
         into a primary token using DuplicateTokenEx(). 
       <li>If the api requires the SE_TCB_NAME privilege (Act as Part of the Operating System)
       <li>If the api requires the SE_AUDIT_NAME privilege.
       </ul>
  
       Windows 2000 also introduces the concept of "restricted tokens", which can be created from a 
       normal token using the CreateRestrictedToken() api. A restricted token allows you to
       restrict the access to objects granted by the normal token in one of two ways:
       <ol>
          <li>By removing privileges from it,
          <li>By marking sids or groups in the token as deny-only (SE_GROUP_USE_FOR_DENY_ONLY).
       </ol>
  
       Be careful when selecting which access to request to the token. Our own
       TOKEN_ALL_ACCESS definition is very NT4 friendly, but leaves out TOKEN_ADJUST_SESSIONID
       which is only valid on Win2000. Requesting this on NT4 will cause the token opening
       to fail.

       @author Tomas Restrepo \<tomasr@mvps.org&gt\>,
       @author see http://mvps.org/win32/security/fksec.html
   */
   class token
   {
   public:
      //-- construction/destruction --
      /** Construct *this as an empty token object

          The empty constructor is not very useful,
          as it forces us to do more checks...
          @exceptions none
      */
      token ( );
      /** Construct *this from an existing token handle

          Note that token takes ownership of the handle and 
          you should NOT close it.
          @exceptions errInvalidHandle
      */
      token ( HANDLE h );
      /** Construct *this as a copy of another token object

          @exceptions none
      */
      token ( const token & t );
      /** Clean up *this

          This releases internal buffers, destroyed the group, 
          restricted sids and privilege lists, and closes the
          token's handle

          @exceptions none
      */
      virtual ~token ( );

      /** Clean up *this

          This releases internal buffers, destroyed the group, 
          restricted sids and privilege lists, and closes the
          token's handle

          @exceptions none
      */
      void cleanup();

      /** Create a token object out a token assigned to a given process
          with a given access.

          You should, to get the most out of it, specify at least
          TOKEN_QUERY access.

          @returns a valid token object.
          @exceptions errOpenToken
      */
      static token OpenProcessToken ( HANDLE hProcess, DWORD access );
      /** Create a token object out this process' primary token

          By default, the token is opened for TOKEN_ALL_ACCESS.

          @returns a valid token object.
          @exceptions errOpenToken
      */
      static token OpenCurrentProcessToken ( DWORD access = TOKEN_ALL_ACCESS );
      /** Create a token object out a token assigned to a given thread

          You can specify if you want the access check performed against the
          current thread´s impersonation token (OpenAsSelf = false), or against
          the process'  primary token (OpenAsSelf = true).

          @returns a valid token object.
          @exceptions errOpenToken
      */
      static token OpenThreadToken ( HANDLE hThread, DWORD access, bool OpenAsSelf = false );
      /** Create a token object out this thread's impersonation token

          By default, the token is opened for TOKEN_ALL_ACCESS.

          @returns a valid token object.
          @exceptions errOpenToken
      */
      static token OpenCurrentThreadToken ( DWORD access = TOKEN_ALL_ACCESS );
      /** Create a token object out whatever token is available

          This one will open whatever token it can grab.
          First, try the current thread´s token with impersonation,
          then without, and finally the process´ token
          By default, the token is opened for TOKEN_ALL_ACCESS

          @returns a valid token object.
          @exceptions errOpenToken
      */
      static token OpenCurrentToken ( DWORD access = TOKEN_ALL_ACCESS );

      //-- accessors --
      //-- GetTokenInformation() wrappers --
      /** Get the owner's SID

          This is the sid that will be assigned by default
          as owner of object's created under this security 
          context, unless you explicitly 
          provide a valid security descriptor

          @returns the owner's SID as an fksec::sid object
          @exceptions errNoMemory, errQueryToken
      */
      sid GetOwner ( ) const;
      /** Set the owner's SID

          @exceptions errAdjustToken
      */
      void SetOwner ( const sid & newSid );
      /** Get the primary group

          This is the sid that will be assigned by default
          as primary group of object's created under this security 
          context, unless you explicitly 
          provide a valid security descriptor

          Not any sid can be an owner. There are two restrictions:
          <ol>
             <li>The sid <i>must</i> be already listed on the token's
             group list
             <li>The sid must be marked on the group list with the
             SE_GROUP_OWNER attribute
          </ol>

          @returns the group's SID as an fksec::sid object
          @exceptions errNoMemory, errQueryToken
      */
      sid GetPrimaryGroup ( ) const;
      /** Set the primary group's SID

          @exceptions errAdjustToken
      */
      void SetPrimaryGroup ( const sid & newGroup );
      /** Get the default DACL

          This is the DACL that will be assigned by default
          to objects created under this security 
          context, unless you explicitly 
          provide a valid security descriptor

          @returns the DACL as an fksec::acl object
          @exceptions errNoMemory, errQueryToken
      */
      acl GetDefaultDacl ( ) const;
      /** Set the default DACL

          @exceptions errAdjustToken
      */
      void SetDefaultDacl ( const acl & newDacl );

      /** Get the session's id 

          This value will be 0, unless the process/thread
          is running on a TS terminal (Terminal Services),
          in which case it identifies the user's session.

          Trying to call GetSessionId() on NT4 without
          Terminal Server will result in an exception

          @returns a DWORD with the value
          @exceptions errQueryToken
      */
      DWORD GetSessionId ( ) const;
      /** Set the session id 

          The token should be open with 
          TOKEN_ADJUST_SESSIONID access, and
          an enabled SeTcbPrivilege

          @exceptions errAdjustToken
      */
      void SetSessionId ( DWORD id );
      /** Get the token's Source

          The Source identifies who was responsible for
          creating this token. TOKEN_SOURCE has two fields:
          - SourceName: an 8-TCHAR string with the source name
              which, unfortunately, only has the '\0' at the last
              position, regardless of the real string length. Thus, 
              you might see some trailing garbage
          - The creator's LUID

          @exceptions errQueryToken
      */
      void GetSource ( TOKEN_SOURCE * source ) const;
      /** Get the SID of the user identified by this token

          @returns the user's SID as an fksec::sid object
          @exceptions errNoMemory, errQueryToken
      */
      sid GetUserSid ( ) const;

      /** Get token´s group list

          This is the list of groups the user belongs to
          (so this is an easy way to check for group 
          membership). 

          @returns std::vector containing token_group elements
          @exceptions none
      */
      group_list & GetGroups ( );
      /** Get token´s group list

          This is the list of groups the user belongs to
          (so this is an easy way to check for group 
          membership). 

          @returns std::vector containing token_group elements
          @exceptions none
      */
      const group_list & GetGroups ( ) const;
      /** Set the token's group list

          This is a simple wrapper around AdjustTokenGroups().
          Note that it's not really all that useful, since:
          a - You can´t add new groups to the token
          b - Can't delete groups from the token
          c - Can't disable groups marked with 
               SE_GROUP_MANDATORY, which is usually all
               of them. To do this, you´d need 
               CreateRestrictedToken()

          @exceptions errAdjustToken, errNoMemory
      */
      void SetGroups ( const group_list & groupList );
      /** Get the restricted sid list (W2K only)

          When Windows 2000 performs access checks 
          against a securable object, the system will 
          first check access against the user identified
          by the token and group list. If those have allowed
          access to the object, the system will then check those SIDs
          in the Restricted sids, by looking <i>only</i> at those ACE's
          in the object's DACL that are ACCESS_DENIED_ACE's, and will
          explicitly ignore ACCESS_ALLOWED_ACE's.

          @exceptions none
      */
      const group_list & GetRestrictedSids ( ) const;
      /** Get the token's privilege list

          @returns a reference to a vector of fksec::priv
          @exceptions none
      */
      privilege_list & GetPrivileges ( );
      /** Get the token's privilege list

          @returns a const reference to a vector of fksec::priv
          @exceptions none
      */
      const privilege_list & GetPrivileges ( ) const;
      /** Get a specified privilege in the token

          Very useful for doing things like:
          <code>
          token t = token::OpenCurrentToken ( );
          t.GetPriv ( SE_DEBUG_NAME ).Enable ( );
          </code>

          @returns a reference to the fksec::priv object
          @exceptions errQueryToken
      */
      priv & GetPriv ( const priv & p );

      //-- token statistics --
      /** Is the token an impersonation token?
         
          @returns true if it is an impersonation token
          @exceptions errQueryToken
      */
      bool IsImpersonationToken ( ) const;
      /** Is the token a primary token?
         
          @returns true if it is a primary token
          @exceptions errQueryToken
      */
      bool IsPrimaryToken ( ) const;
      /** What is the token's impersonation level?
         
          @returns one of the SECURITY_IMPERSONATION_LEVEL enumeration items
          @exceptions errQueryToken
      */
      SECURITY_IMPERSONATION_LEVEL GetImpersonationLevel ( ) const;

      /** Get the token ID
         
          The Token ID is a LUID
          identifies the token instance

          @returns a Locally Unique Identifier (LUID)
          @exceptions errQueryToken
      */
      LUID GetTokenId ( ) const;
      /** Get the token Authentication ID
         
          The Authentication ID is a LUID assigned 
          to the logon session the token belongs to

          @returns a Locally Unique Identifier (LUID)
          @exceptions errQueryToken
      */
      LUID GetAuthenticationId ( ) const;
      /** Get the token Modification ID
         
          The Modification ID is a LUID that
          changes each time the token is modified

          @returns a Locally Unique Identifier (LUID)
          @exceptions errQueryToken
      */
      LUID GetModifiedId ( ) const;
      /** Get the token's expiration time
         
          Returns the expiration time in 
          FILETIME structure in UTC.
          Token expiration times are not currently used

          @exceptions errQueryToken
      */
      void GetExpirationTime ( FILETIME & time ) const;
      /** Get the token's expiration time
         
          Returns the expiration time in 
          SYSTEMTIME structure in UTC.
          Token expiration times are not currently used

          @exceptions errQueryToken
      */
      void GetExpirationTime ( SYSTEMTIME & time ) const;
      /** Get the token's Dynamic Charge
         
          This is the amount, in bytes, of memory
          allocated for storing the token´s defaul dacl,
          the primary group and owner sids

          @exceptions errQueryToken
      */
      DWORD GetDynamicCharged ( ) const;
      /** Get the token's Dynamic Availability
         
          This is the amount, in bytes, of 
          free memory in the token's dynamic 
          charge
          
          @exceptions errQueryToken
      */
      DWORD GetDynamicAvailable ( ) const;
      /** Get the token's group count

          @returns the number of groups in the token
          @exceptions errQueryToken
      */
      DWORD GetGroupCount ( ) const;
      /** Get the token's privilege count
          
          @returns the number of privileges in the token
          @exceptions errQueryToken
      */
      DWORD GetPrivilegeCount ( ) const;

      //-- free accessors -- 
      /** Get the token's handle

          Gives access to the token handle
          DO NOT close it!

          @exceptions errQueryToken
      */
      HANDLE GetHandle ( ) const;
      /** Is this token instance valid?

          @returns true if the token handle is valid
          @exceptions none
      */
      bool IsValid ( ) const;

      //-- operators --
      /** Set *this to a copy of another token
         
          @returns a const reference to *this
          @exceptions errQueryToken, errInvalidHandle, errDupTokenHandle
      */
      const token & operator= ( const token & t );
      /** Set *this to a copy of another token's handle
         
          @returns a const reference to *this
          @exceptions errQueryToken, errInvalidHandle, errDupTokenHandle
      */
      const token & operator= ( HANDLE h );

   private:
      /** Retrieve the token's statistics
         
          This call populates token's internal structures

          @exceptions errInvalidHandle
      */
      void GetStatistics ( );
      /** Build the internal group list
         
          This call populates a std::vector of
          token_group objects with the token's 
          group list

          @exceptions errInvalidHandle, errNoMemory, errQueryToken
      */
      void BuildGroupList ( );
      /** Build the internal restricted sid list
         
          This call populates a std::vector of
          token_group objects with the token's 
          restricted sid list

          @exceptions errInvalidHandle, errNoMemory, errQueryToken
      */
      void BuildRSidList ( );
      /** Build the internal privilege list
         
          This call populates a std::vector of
          fksec::priv objects with the token's 
          privilege list

          @exceptions errInvalidHandle, errNoMemory, errQueryToken
      */
      void BuildPrivList ( );
      /** Retrieve some info from the token handle
         
          This internal method wraps GetTokenInformation()
          for those token information classes that
          require a variable length buffer.

          @returns a pointer to the allocated buffer with the info
          @exceptions errInvalidHandle, errNoMemory, errQueryToken
      */
      void * GetTokenInfo ( TOKEN_INFORMATION_CLASS info ) const;
      /** Free the memory allocated by GetTokenInfo()
         
          @exceptions none
      */
      void FreeTokenInfo ( void * p ) const;

   private:
      /** The token HANDLE
         
          The handle is mutable because windows has no notion
          of a const handle...
      */
      mutable HANDLE   hToken;
      /** Is token::stats valid?
      */
      bool             haveInternalData; 
      /** Some token statistics mantained by the system
      */
      TOKEN_STATISTICS stats;
      /** The internal group list
      */
      group_list       groups;
      /** The internal restricted sid list
      */
      group_list       rsids;
      /** The internal privilege list
      */
      privilege_list   privs;
   };
   //-- dumpers --
   fkostream & operator<< ( fkostream &o, const token & t );
   fkostream & operator<< ( fkostream &o, const token_group & g );

} // namespace fksec

#endif // _TOKEN_H_
