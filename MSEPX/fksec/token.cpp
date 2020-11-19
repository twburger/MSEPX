//==============================================================================
// token.cpp implementation of the token and token_group classes
//==============================================================================
#include "stdafx.h"
#define FKSEC_NO_AUTO_INCLUDES 1
#include "fksec.h"
#include "ex.h"
#include "priv.h"
#include "sid.h"
#include "ace.h"
#include "acl.h"
#include "token.h"

using namespace fksec;

//==============================================================================
// token_group members
//==============================================================================

token_group::token_group ( const sid & newSid, DWORD attributes )
{
   groupSid  = newSid;
   groupAttr = attributes;
}


token_group::token_group ( const SID_AND_ATTRIBUTES * group )
{
   groupSid  = sid(group->Sid);
   groupAttr = group->Attributes;
}


token_group::token_group ( const token_group & g )
{
   groupSid  = g.groupSid;
   groupAttr = g.groupAttr;
}


const token_group & token_group::operator= ( const token_group & g )
{
   if ( this != &g )
   {
      groupSid  = g.groupSid;
      groupAttr = g.groupAttr;
   }
   return *this;
}


// returns 1 if both the sid and attributes are equal
int token_group::operator== ( const token_group & g ) const
{
   return ((groupSid == g.groupSid) && (groupAttr == g.groupAttr));
}


int token_group::operator!= ( const token_group & g ) const
{
   return ((groupSid != g.groupSid) || (groupAttr != g.groupAttr));
}


// returns 1 if this is the group sid is equal
int token_group::operator== ( const sid & s ) const
{
   return (groupSid == s );
}


int token_group::operator!= ( const sid & s ) const
{
   return (groupSid != s );
}

// -- accessors --


const sid & token_group::GetSid ( ) const
{
   return groupSid;
}


DWORD token_group::GetAttributes ( ) const
{
   return groupAttr;
}


void token_group::SetAttributes ( DWORD newAttr )
{
   groupAttr = newAttr;
}


fkostream & fksec::operator<< ( fkostream &o, const token_group & g )
{
   o << g.GetSid ( ) << std::endl;
   const TCHAR * str;
   for ( DWORD i = 1; i != 0x0L; i <<= 1 )
   {
      switch ( g.GetAttributes ( ) & i )
      {
      case SE_GROUP_MANDATORY:            str = _T("SE_GROUP_MANDATORY");          break;
      case SE_GROUP_ENABLED_BY_DEFAULT:   str = _T("SE_GROUP_ENABLED_BY_DEFAULT"); break;
      case SE_GROUP_ENABLED:              str = _T("SE_GROUP_ENABLED");            break;
      case SE_GROUP_OWNER:                str = _T("SE_GROUP_OWNER");              break;
      case SE_GROUP_USE_FOR_DENY_ONLY:    str = _T("SE_GROUP_USE_FOR_DENY_ONLY");  break;
      case SE_GROUP_LOGON_ID:             str = _T("SE_GROUP_LOGON_ID");           break;
      case SE_GROUP_RESOURCE:             str = _T("SE_GROUP_RESOURCE");           break;
      default:                            continue;
      }
      o << _T("\t") << str << std::endl;
   }
   return o;
}

//==============================================================================
// token members
//==============================================================================
// --- construction / destruction ---

token token::OpenProcessToken ( HANDLE hProcess, DWORD access )
{
   HANDLE h;
   if ( !::OpenProcessToken ( hProcess, access, &h ) )
      throw NEWEX32(errOpenToken, "token::OpenProcessToken(): cannot open process token", GetLastError());
   return token ( h );
}


token token::OpenCurrentProcessToken ( DWORD access /* = TOKEN_ALL_ACCESS */ )
{
   return token::OpenProcessToken ( ::GetCurrentProcess ( ), access );
}


token token::OpenThreadToken ( HANDLE hThread, DWORD access, bool OpenAsSelf /* = false */ )
{
   HANDLE h;
   if ( !::OpenThreadToken ( hThread, access, OpenAsSelf, &h ) )
      throw NEWEX32(errOpenToken, "token::OpenThreadToken(): cannot open thread token", GetLastError());
   return token ( h );
}


token token::OpenCurrentThreadToken ( DWORD access /* = TOKEN_ALL_ACCESS */ )
{
   return token::OpenThreadToken ( ::GetCurrentThread ( ), access );
}


token token::OpenCurrentToken ( DWORD access /* = TOKEN_ALL_ACCESS */ )
{
   HANDLE ht = 0;
   DWORD rc = 0;
   const TCHAR *func = _T( "what?" );
   
   rc = 0;
   func = _T( "OpenThreadToken()" );
   if ( ! ::OpenThreadToken( GetCurrentThread(), access, FALSE, &ht ) )
      rc = GetLastError();
   
   // OTT() failed with something recoverable?
   if ( rc == ERROR_ACCESS_DENIED || rc == ERROR_NO_TOKEN || rc == ERROR_NO_IMPERSONATION_TOKEN )
   {
      rc = 0;
      func = _T( "OpenThreadToken() as self" );
      if ( ! ::OpenThreadToken( GetCurrentThread(), access, TRUE, &ht ) )
         rc = GetLastError();
      
      // OTT() failed again? try OPT()
      if ( rc == ERROR_ACCESS_DENIED || rc == ERROR_NO_TOKEN || rc == ERROR_NO_IMPERSONATION_TOKEN )
      {
         rc = 0;
         func = _T( "OpenProcessToken()" );
         if ( ! ::OpenProcessToken( GetCurrentProcess(), access, &ht ) )
            rc = GetLastError();
      }
   }
   
   if ( rc != 0 )
   {
      fkstr errstr = _T( "priv::openToken(): " ) + fkstr( func ) + _T( " failed, see ex::GetErrWin32()" );
      throw new ex( _T( __FILE__ ), __LINE__, errOpenToken, errstr.c_str(), rc );
   }
   // succeeded
   return token ( ht );
}


token::token ( )
   : hToken ( NULL ),
     haveInternalData ( false )
{
}


token::token ( HANDLE h )
   : hToken ( h ),
     haveInternalData ( false )
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::token(): Invalid Handle Value" );
   GetStatistics ( );    
}


token::~token ( ) 
{
	cleanup();
}


void token::cleanup()
{
	if ( IsValid ( ) )
		CloseHandle ( hToken );
	hToken = NULL;
	groups.clear();
	rsids.clear();
	privs.clear();
	haveInternalData = false;
}


// --- copy construction --

token::token ( const token & t )
{
   if ( ! t.IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::token(): Invalid Handle Value" );
   BOOL b = DuplicateHandle ( 
               ::GetCurrentProcess ( ), t.hToken,
               ::GetCurrentProcess ( ), &hToken,
               0, FALSE, DUPLICATE_SAME_ACCESS
            );
   if ( !b )
      throw NEWEX32 ( errDupTokenHandle, "token::token(): DuplicateHandle() failed", GetLastError ( ) );
   
   GetStatistics ( );
}

// --- Operators ---

const token & token::operator= ( const token & t )
{
	if ( &t == this )
		return *this;

   if ( hToken != t.hToken )
   {
      if ( ! t.IsValid ( ) )
         throw NEWEX ( errInvalidHandle, "token::operator=(): Invalid Handle Value" );

	  cleanup();

      BOOL b = DuplicateHandle ( 
                  ::GetCurrentProcess ( ), t.hToken,
                  ::GetCurrentProcess ( ), &hToken,
                  0, FALSE, DUPLICATE_SAME_ACCESS
               );
      if ( !b )
         throw NEWEX32 ( errDupTokenHandle, "token::operator=(): DuplicateHandle() failed", GetLastError ( ) );
      
      GetStatistics ( );
   }
   return *this;
}


const token & token::operator= ( HANDLE h )
{
   if ( (h == NULL) || (h == INVALID_HANDLE_VALUE) )
      throw NEWEX ( errInvalidHandle, "token::operator=(): Invalid Handle Value" );

   if ( hToken != h )
   {
	   cleanup();

      BOOL b = DuplicateHandle ( 
                  ::GetCurrentProcess ( ), h,
                  ::GetCurrentProcess ( ), &hToken,
                  0, FALSE, DUPLICATE_SAME_ACCESS
               );
      if ( !b )
         throw NEWEX32 ( errDupTokenHandle, "token::operator=(): DuplicateHandle() failed", GetLastError ( ) );
      
      GetStatistics ( );
   }
   return *this;
}



// --- GetTokenInformation() Wrappers ---


//
// token::GetOwner()
// token::SetOwner()
//
// Get/Set the owner used by default for new objects
//
sid token::GetOwner ( ) const
{
   try {
      TOKEN_OWNER * owner = (TOKEN_OWNER*)GetTokenInfo ( TokenUser );
      sid s ( owner->Owner );
      FreeTokenInfo ( owner );
      return s;
   }
   RETHROWEX ( "token::GetOwner(): GetTokenInfo() failed" );
}


void token::SetOwner ( const sid & newSid ) 
{
   if ( !newSid.IsValid ( ) )
      throw NEWEX ( errInvalidSid, "token::SetOwner(): Invalid Owner SID" );
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::SetOwner(): Invalid Handle Value" );
   
   TOKEN_OWNER owner;
   owner.Owner = (PSID)newSid;
   if ( !SetTokenInformation ( hToken, TokenOwner, (void*)&owner, sizeof owner ) )
      throw NEWEX32 ( errAdjustToken, "token::SetOwner(): SetTokenInformation() failed", GetLastError ( ) );
}


//
// token::GetPrimaryGroup()
// token::SetPrimary()
//
// Get/Set the primary group used by default for new objects
//
sid token::GetPrimaryGroup ( ) const
{
   try {
      TOKEN_PRIMARY_GROUP * group = (TOKEN_PRIMARY_GROUP*)GetTokenInfo ( TokenPrimaryGroup );
      sid s ( group->PrimaryGroup );
      FreeTokenInfo ( group );
      return s;
   }
   RETHROWEX ( "token::GetPrimaryGroup(): GetTokenInfo() failed" );
}


void token::SetPrimaryGroup ( const sid & newGroup )
{
   if ( !newGroup.IsValid ( ) )
      throw NEWEX ( errInvalidSid, "token::SetPrimaryGroup(): Invalid Group SID" );
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::SetPrimaryGroup(): Invalid Handle Value" );
   
   TOKEN_PRIMARY_GROUP group;
   group.PrimaryGroup = (PSID)newGroup;
   if ( !SetTokenInformation ( hToken, TokenPrimaryGroup, (void*)&group, sizeof group ) )
      throw NEWEX32 ( errAdjustToken, "token::SetPrimaryGroup(): SetTokenInformation() failed", GetLastError ( ) );
}


//
// token::GetDefaultDacl()
// token::SetDefaultDacl()
//
// Get/Set the default DACL used for new objects
//
acl token::GetDefaultDacl ( ) const
{
   try {
      TOKEN_DEFAULT_DACL * dacl = (TOKEN_DEFAULT_DACL*)GetTokenInfo ( TokenDefaultDacl );
      
      if ( dacl->DefaultDacl == NULL )
         throw NEWEX ( errInvalidAcl, "token::GetDefaultDacl(): Token has null DACL" );
      
      acl a ( dacl->DefaultDacl );
      FreeTokenInfo ( dacl );
      return a;
   }
   RETHROWEX ( "token::GetDefaultDacl(): GetTokenInfo() failed" );
}


void token::SetDefaultDacl ( const acl & newDacl )
{
   if ( !newDacl.IsValid ( ) )
      throw NEWEX ( errInvalidAcl, "token::SetDefaultDacl(): Invalid ACL" );
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::SetDefaultDacl(): Invalid Handle Value" );
   
   TOKEN_DEFAULT_DACL dacl;
   dacl.DefaultDacl = (PACL)newDacl;
   if ( !SetTokenInformation ( hToken, TokenDefaultDacl, (void*)&dacl, sizeof dacl ) )
      throw NEWEX32 ( errAdjustToken, "token::SetDefaultDacl(): SetTokenInformation() failed", GetLastError ( ) );
}


//
// token::GetSessionId()
//
// Get the terminal services session ID
//
DWORD token::GetSessionId ( ) const
{
   DWORD id, len;
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::operator=(): Invalid Handle Value" );
   
   if ( !GetTokenInformation ( hToken, TokenSessionId, (void*)&id, sizeof id, &len ) )
      throw NEWEX32 ( errQueryToken, "token::GetSessionId(): GetTokenInformation() failed", GetLastError ( ) );
   return id;
}

void token::SetSessionId ( DWORD id )
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::SetSessionId(): Invalid Handle Value" );
   
   if ( !SetTokenInformation ( hToken, TokenSessionId, (void*)&id, sizeof DWORD ) )
      throw NEWEX32 ( errAdjustToken, "token::SetSessionId(): SetTokenInformation() failed", GetLastError ( ) );
}

//
// token::GetSource()
//
// Get the token´s source (who created it?)
//
void token::GetSource ( TOKEN_SOURCE * source ) const
{
   DWORD len;
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::operator=(): Invalid Handle Value" );
   
   if ( !GetTokenInformation ( hToken, TokenSource, (void*)source, sizeof TOKEN_SOURCE, &len ) )
      throw NEWEX32 ( errQueryToken, "token::GetSource(): GetTokenInformation() failed", GetLastError ( ) );
}


//
// token::GetUserSid()
//
//  Get the SID of the user identified by this token
//
sid token::GetUserSid ( ) const
{
   try {
      TOKEN_USER * user = (TOKEN_USER*)GetTokenInfo ( TokenUser );
      sid s ( user->User.Sid );
      FreeTokenInfo ( user );
      return s;
   }
   RETHROWEX ( "token::GetUserSid(): GetTokenInfo() failed" );
}


//
// token::GetImpersonationLevel()
//
// Get the impersonation level of the token.
// It´s only meaningful if token::IsImpersonationToken()
// returns true
//
SECURITY_IMPERSONATION_LEVEL token::GetImpersonationLevel ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetImpersonationLevel(): invalid access" );
   return stats.ImpersonationLevel;
}



// --- token statistics ---

bool token::IsImpersonationToken ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::IsImpersonationToken(): invalid access" );
   return (stats.TokenType == TokenImpersonation);
}


bool token::IsPrimaryToken ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::IsPrimaryToken(): invalid access" );
   return (stats.TokenType == TokenPrimary);
} 


LUID token::GetTokenId ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetTokenId(): invalid access" );
   return stats.TokenId;
}


LUID token::GetAuthenticationId ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetAuthenticationId(): invalid access" );
   return stats.AuthenticationId;
}


LUID token::GetModifiedId ( ) const
{
   // the modified ID can change, so 
   // get it each time fresh
   TOKEN_STATISTICS stats;
   DWORD len;

   if ( !GetTokenInformation ( hToken, TokenStatistics, (void*)&stats, sizeof stats, &len ) )
      throw NEWEX32 ( errQueryToken, "token::GetModifiedId(): GetTokenInformation() failed", GetLastError ( ) );
   return stats.ModifiedId;
}


void token::GetExpirationTime ( FILETIME & time ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetExpirationTime(): invalid access" );
    
      time.dwHighDateTime = stats.ExpirationTime.HighPart;
      time.dwLowDateTime  = stats.ExpirationTime.LowPart;
}


void token::GetExpirationTime ( SYSTEMTIME & time ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetExpirationTime(): invalid access" );
   
   FILETIME utc = { 
      stats.ExpirationTime.HighPart,
      stats.ExpirationTime.LowPart
   };
   
   FileTimeToSystemTime ( &utc, &time );
}


DWORD token::GetDynamicCharged ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetDynamicCharged(): invalid access" );
   return stats.DynamicCharged;
}


DWORD token::GetDynamicAvailable ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetDynamicAvailable(): invalid access" );
   return stats.DynamicAvailable;
}


DWORD token::GetGroupCount ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetGroupCount(): invalid access" );
   return stats.GroupCount;
}


DWORD token::GetPrivilegeCount ( ) const
{
   if ( !haveInternalData )
      throw NEWEX ( errQueryToken, "token::GetPrivilegeCount(): invalid access" );
   return stats.PrivilegeCount;
}


//
// token::GetHandle()
// Get this token´s handle
//
HANDLE token::GetHandle ( ) const
{
   return hToken;
}


//
// token::IsValid()
// Is this token valid?
//
bool token::IsValid ( ) const
{
   return ((hToken != NULL) && (hToken != INVALID_HANDLE_VALUE));
}


//
// token::GetGroups()
// token::GetRestrictedSids()
// token::GetPrivileges()
// token::GetPriv()
//
// Provide list of this objects
// You can also set the group and privilege list
//
group_list & token::GetGroups ( )
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::GetGroups(): Invalid Handle Value" );
   return groups;
}


const group_list & token::GetGroups ( ) const
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::GetGroups(): Invalid Handle Value" );
   return groups;
}


void token::SetGroups ( const group_list & groupList )
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::SetGroups(): Invalid Handle Value" );
   
   // build a TOKEN_GROUPS list with the groups
   TOKEN_GROUPS * g = 0;
   int numgroups = groupList.size ( );
   int size = sizeof(TOKEN_GROUPS) + (numgroups-1)*sizeof(SID_AND_ATTRIBUTES);
   
   g = (TOKEN_GROUPS*)new BYTE[size];
   if ( g == 0 ) throw NEWEX ( errNoMemory, "token::SetGroups(): failed to allocate memory for group list" );
   
   g->GroupCount = numgroups;
   for ( int i = 0; i < numgroups; i++ )
   {
      g->Groups[i].Sid = (PSID)groupList[i].GetSid ( );
      g->Groups[i].Attributes = groupList[i].GetAttributes ( );
   }
   
   // adjust the group list on the token, and then 
   // rebuild our group list
   BOOL b = AdjustTokenGroups ( hToken, FALSE, g, 0, NULL, NULL );
   delete[] g;
   
   if ( !b )
      throw NEWEX32 ( errAdjustToken, "token::SetGroups(): AdjustTokenGroups() failed", GetLastError ( ) );
   
   BuildGroupList ( );
   // update group count
   stats.GroupCount = groups.size ( );
}


const group_list & token::GetRestrictedSids ( ) const
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::GetRestrictedSids(): Invalid Handle Value" );
   
   return rsids;
}


privilege_list & token::GetPrivileges ( ) 
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::GetPrivileges(): Invalid Handle Value" );
   return privs;
}


const privilege_list & token::GetPrivileges ( ) const 
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::GetPrivileges(): Invalid Handle Value" );
   return privs;
}


#pragma warning( disable: 4172 )
priv & token::GetPriv ( const priv & p )
{
   for ( privilege_list::iterator it = privs.begin ( ); 
   it != privs.end ( ); it++ )
   {
      if ( (*it) == p )
         return *it;
   }
   // not found
   throw NEWEX ( errQueryToken, "token::GetPriv(): privilege not found" );
   // needed to keep VC++ 5.0 quiet...
   return priv();
}
#pragma warning( default: 4172 )


//
// token::GetStatistics()
// token::BuildGroupList()
// token::BuildRSidList()
// token::BuildPrivList()
//
// Private methods used to retrieve the token´s info
//
void token::GetStatistics ( ) 
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::GetStatistics(): Invalid Handle Value" );
   
   DWORD len;
   haveInternalData = true; // assume success
   if ( !GetTokenInformation ( hToken, TokenStatistics, (void*)&stats, sizeof stats, &len ) )
   {
      // we probably don´t have TOKEN_QUERY access
      haveInternalData = false;
   }
   
   try
   {
      // get group information
      BuildGroupList ( );
      // get restricted sids info
      BuildRSidList ( );
      // get privilege list
      BuildPrivList ( );
   }
   catch ( ex * e )
   {
      // we can live with empty lists...
      // dismiss
      e->shoo ( );
   }
}


void token::BuildGroupList ( ) 
{
   TOKEN_GROUPS * g;
   try {
      g = (TOKEN_GROUPS*)GetTokenInfo ( TokenGroups );
   }
   RETHROWEX ( "token::BuildGroupList(): GetTokenInfo() failed" );
   
   groups.clear ( );
   for ( DWORD i = 0; i < g->GroupCount; i++ )
      groups.push_back ( token_group(&g->Groups[i]) );
   FreeTokenInfo ( g );
}


void token::BuildRSidList ( )
{
	TOKEN_GROUPS * g = 0;

   rsids.clear();

   try {
      g = (TOKEN_GROUPS*) GetTokenInfo ( TokenRestrictedSids );
   }
   catch ( ex *e )
   {
	   e->FKSECADDHOP( "BuilsRSidList(): GTI() failed" );
	   if ( e->GetErrWin32() != ERROR_INVALID_PARAMETER )
		   throw;
	   // on err 87, we assume that we run on NT4 -- no restricted SIDs
	   g = 0;
   }

   if ( g != 0 )
   {
	   for ( DWORD i = 0; i < g->GroupCount; i++ )
		  rsids.push_back ( token_group(&g->Groups[i]) );
   
	   FreeTokenInfo ( g );
   }
}


void token::BuildPrivList ( )
{
   TOKEN_PRIVILEGES * p;
   try {
      p = (TOKEN_PRIVILEGES*)GetTokenInfo ( TokenPrivileges );
   }
   RETHROWEX ( "token::BuildPrivList(): GetTokenInfo() failed" );
   
   privs.clear ( );
   for ( DWORD i = 0; i < p->PrivilegeCount; i++ )
   {
      try {
         priv v( p->Privileges[i].Luid );
         v.SetHandle ( hToken );
         privs.push_back ( v );
      }
      RETHROWEX ( "token::BuildPrivList(): failed to create privilege" );
   }
   FreeTokenInfo ( p );
}


void * token::GetTokenInfo ( TOKEN_INFORMATION_CLASS info ) const
{
   if ( !IsValid ( ) )
      throw NEWEX ( errInvalidHandle, "token::operator=(): Invalid Handle Value" );
 
   DWORD len = 0;
   // get required buffer size, and then request the real info
   if ( ! GetTokenInformation ( hToken, info, NULL, 0, &len ) )
   {
		if ( GetLastError() != ERROR_INSUFFICIENT_BUFFER )
			throw NEWEX32( errQueryToken,
				"token::GetTokenInfo() 1: GetTokenInformation() failed", GetLastError ( ) );
   }
   
   void * p = new BYTE[len];
   if ( p == 0 )
	   throw NEWEX ( errNoMemory, "token::GetTokenInfo(): failed to allocate memory" );
   
   if ( !GetTokenInformation ( hToken, info, p, len, &len ) )
      throw NEWEX32 ( errQueryToken, "token::GetTokenInfo() 2: GetTokenInformation() failed", GetLastError ( ) );
   
   return p;
}


void token::FreeTokenInfo ( void * p ) const
{
   delete [] p;
}



// --- dumpers ---

fkostream & fksec::operator<< ( fkostream &o, const token & t )
{
   try {
      sid user = t.GetUserSid ( );
      if ( t.IsPrimaryToken ( ) )
         o << _T("Token [primary]: ") << user << std::endl;
      else
         o << _T("Token [impersonation]: ") << user << std::endl;
      
      if ( t.IsImpersonationToken ( ) )
      {
         const TCHAR * str;
         switch ( t.GetImpersonationLevel ( ) )
         {
         case SecurityAnonymous:         str = _T("Anonymous");      break;
         case SecurityIdentification:    str = _T("Identification"); break;
         case SecurityImpersonation:     str = _T("Impersonation");  break;
         case SecurityDelegation:        str = _T("Delegation");     break;
         default:                        str = _T("-none-");         break;
         }
         o << _T("Impersonation Level: ") << str << std::endl;
      }
   }
   catch ( ex * e )
   { 
      // no TOKEN_QUERY access
      e->shoo ( );
   }
   
   // token source
   try {
      TOKEN_SOURCE source;
      t.GetSource ( &source );
      o << _T("Source: ") << source.SourceName << _T(" - ID ") << std::hex 
         << source.SourceIdentifier.HighPart << _T("-") << source.SourceIdentifier.LowPart << std::endl;
   }
   catch ( ex * e )
   { 
      // no TOKEN_QUERY_SOURCE access
      e->shoo ( );
   }
   
   try {
      LUID l;
      l = t.GetTokenId ( );
      o << _T("Statistics:") << std::endl;
      o << _T("    ID: ") << std::hex << l.HighPart << _T("-") << l.LowPart << std::endl;
      l = t.GetAuthenticationId ( );
      o << _T("    AuthID: ") << std::hex << l.HighPart << _T("-") << l.LowPart << std::endl;
      l = t.GetModifiedId ( );
      o << _T("    Modified ID: ") << std::hex << l.HighPart << _T("-") << l.LowPart << std::endl;
      o << _T("    Dynamic Charge: ") << t.GetDynamicCharged ( ) << _T(" bytes") 
         << _T(" - ") << t.GetDynamicAvailable ( ) << _T(" bytes free") << std::endl;
      DWORD id = t.GetSessionId ( );
      o << _T("    Session Id: ") << std::hex << id << std::endl;
   }
   catch ( ex * e )
   { 
      // no TOKEN_QUERY access
      e->shoo ( );
   }
   
   
   /*
   * remove for now, since no windows uses the expiration
   * time right now, and we´d print garbage
   SYSTEMTIME time;
   t.GetExpirationTime ( time );
   int size = GetDateFormat ( LOCALE_USER_DEFAULT, DATE_LONGDATE, &time, NULL, NULL, 0 );
   TCHAR * date = new TCHAR[size];
   if ( date == 0 ) throw NEWEX ( errNoMemory, _T("operator<<(token): failed to allocate memory for date") );
   GetDateFormat ( LOCALE_USER_DEFAULT, DATE_LONGDATE, &time, NULL, date, size );
   o << _T("Expiration Time: ") << date << std::endl;
   delete[] date;
   */
   
   // default object access
   try {
      o << _T("Owner: ") << t.GetOwner ( ) << std::endl;
      o << _T("Primary Group: ") << t.GetPrimaryGroup ( ) << std::endl;
      o << t.GetDefaultDacl ( ) << std::endl;
      group_list groups = t.GetGroups ( );
      o << _T("    Groups in token [") << t.GetGroupCount ( ) << _T("]:") << std::endl;
      for ( group_list::iterator git = groups.begin ( );
            git != groups.end ( ); git++ )
      {
         o << _T("    ") << *git;
      }
      group_list rsids = t.GetRestrictedSids ( );
      o << std::endl << _T("Restricted SIDs:") << std::endl;
      for ( group_list::iterator rit = rsids.begin ( );
            rit != rsids.end ( ); rit++ )
      {
         o << _T("    ") << *rit;
      }
      
      privilege_list privs = t.GetPrivileges ( );
      o << std::endl << _T("Token Privileges:") << std::endl;
      for ( privilege_list::iterator pit = privs.begin ( );
            pit != privs.end ( ); pit++ )
      {
         o << *pit << std::endl;
      }
   }
   catch ( ex * e )
   { 
      // no TOKEN_QUERY access
      e->shoo ( );
   }
   
   return o;
}

