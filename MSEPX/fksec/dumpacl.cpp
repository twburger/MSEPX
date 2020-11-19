#include "stdafx.h"
#include <accctrl.h>
#include "dumpacl.h"

#pragma warning(disable : 4995)
#pragma warning(disable : 4996) // turn off warning C4995/C4996: '_sntprintf': name was marked as #pragma deprecated

#define lenof(a) (sizeof(a) / sizeof((a)[0]) )


const TCHAR *sidToText( PSID psid )
{
	// S-rev- + SIA + subauthlen*maxsubauth + terminator
	static TCHAR buf[15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1];
	TCHAR *p = &buf[0];
	PSID_IDENTIFIER_AUTHORITY psia;
	DWORD numSubAuths, i;

	// Validate the binary SID.

	if ( ! IsValidSid( psid ) )
		return FALSE;

	psia = GetSidIdentifierAuthority( psid );

	p = buf;
	p += _sntprintf( p, &buf[sizeof buf] - p, _T( "S-%lu-" ), 0x0f & *( (byte *) psid ) );

	if ( ( psia->Value[0] != 0 ) || ( psia->Value[1] != 0 ) )
		p += _sntprintf( p, &buf[sizeof buf] - p, _T( "0x%02hx%02hx%02hx%02hx%02hx%02hx" ),
			(USHORT) psia->Value[0], (USHORT) psia->Value[1],
			(USHORT) psia->Value[2], (USHORT) psia->Value[3],
			(USHORT) psia->Value[4], (USHORT) psia->Value[5] );
	else
		p += _sntprintf( p, &buf[sizeof buf] - p, _T( "%lu" ), (ULONG) ( psia->Value[5] ) +
			(ULONG) ( psia->Value[4] << 8 ) + (ULONG) ( psia->Value[3] << 16 ) +
			(ULONG) ( psia->Value[2] << 24 ) );

	// Add SID subauthorities to the string.

	numSubAuths = *GetSidSubAuthorityCount( psid );
	for ( i = 0; i < numSubAuths; ++ i )
		p += _sntprintf( p, &buf[sizeof buf] - p, _T( "-%lu" ), *GetSidSubAuthority( psid, i ) );

	return buf;
}



bool getSecurityPriv( void )
{
	HANDLE hToken;
	LUID privValue;
	TOKEN_PRIVILEGES tkp;
	DWORD rc = 0;

	if ( OpenProcessToken( GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
	{
		if ( LookupPrivilegeValue( NULL, SE_SECURITY_NAME, &privValue ) )
		{
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Luid = privValue;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if ( ! AdjustTokenPrivileges( hToken, FALSE, &tkp, sizeof tkp, NULL, NULL ) )
				rc = GetLastError();
		}
		else
			rc = GetLastError();
	}
	else
	{
		rc = GetLastError();
		hToken = INVALID_HANDLE_VALUE;
	}

	if ( hToken != INVALID_HANDLE_VALUE )
		CloseHandle( hToken );

	if ( rc )
		SetLastError( rc );

	return rc == 0;
}



static const TCHAR *indent( int nBlanks )
{
	static const int maxBlanks = 80;
	static TCHAR blanks[maxBlanks + 1] = _T( "" );

	if ( blanks[0] == _T( '\0' ) )
	{
		for ( int i = 0; i < maxBlanks; ++ i )
			blanks[i] = _T( ' ' );
		blanks[maxBlanks] = _T( '\0' );
	}

	if ( nBlanks > maxBlanks )
		nBlanks = maxBlanks;
	if ( nBlanks < 0 )
		nBlanks = 0;

	return &blanks[maxBlanks - nBlanks];
}



void printSid( PSID psid )
{
	TCHAR name[256], domain[256];
	TCHAR *type;
	DWORD cbname = sizeof name, cbdomain = sizeof domain, rc;
	SID_NAME_USE sidUse;

	//!! next line has hardcoded server name !!
	// NULL server name is usually appropriate, though.
	if ( LookupAccountSid( NULL, psid, name, &cbname, domain, &cbdomain, &sidUse ) )
	{
		switch ( sidUse )
		{
			case SidTypeUser:			type = _T( "user" ); break;
			case SidTypeGroup:			type = _T( "group" ); break;
			case SidTypeDomain:			type = _T( "domain" ); break;
			case SidTypeAlias:			type = _T( "alias" ); break;
			case SidTypeWellKnownGroup:	type = _T( "well-known group" ); break;
			case SidTypeDeletedAccount:	type = _T( "deleted account" ); break;
			case SidTypeInvalid:		type = _T( "invalid type" ); break;
			case SidTypeUnknown:		type = _T( "unknown type" ); break;
			default:					type = _T( "bad sidUse value" ); break;
		}
		_tprintf( _T( "%s%s%s (%s)\n" ), domain, ( domain == 0 || *domain == '\0' )? _T( "" ): _T( "\\" ), name, type );
	}
	else
	{
		rc = GetLastError();
		_tprintf( _T( "[%s] *** error %lu\n" ), sidToText( psid ), rc );
	}
}



void printAce( int ind, bool isSacl, int index, PACL acl )
{
	ACE_HEADER *ace;
	TCHAR *type;
	int i;
	bool first;
	DWORD j;
	PSID psid;

	static struct {
		DWORD flag;
		TCHAR *txt;
	} inheritflags[] = {
		{ CONTAINER_INHERIT_ACE, _T( "CONTAINER_INHERIT_ACE" ) },
		{ INHERIT_ONLY_ACE, _T( "INHERIT_ONLY_ACE" ) },
		{ NO_PROPAGATE_INHERIT_ACE, _T( "NO_PROPAGATE_INHERIT_ACE" ) },
		{ OBJECT_INHERIT_ACE, _T( "OBJECT_INHERIT_ACE" ) },
		{ SUB_CONTAINERS_ONLY_INHERIT, _T( "SUB_CONTAINERS_ONLY_INHERIT" ) },
		{ SUB_OBJECTS_ONLY_INHERIT, _T( "SUB_OBJECTS_ONLY_INHERIT" ) },
		{ SUB_CONTAINERS_AND_OBJECTS_INHERIT, _T( "SUB_CONTAINERS_AND_OBJECTS_INHERIT" ) },
		{ FAILED_ACCESS_ACE_FLAG, _T( "FAILED_ACCESS_ACE_FLAG" ) },
		{ SUCCESSFUL_ACCESS_ACE_FLAG, _T( "SUCCESSFUL_ACCESS_ACE_FLAG" ) },
		{ INHERITED_ACE, _T( "INHERITED_ACE" ) }
	};
	static struct {
		DWORD flag;
		TCHAR *txt;
	} permflags[] = {
		{ /* 0x00000001 */ FILE_READ_DATA, _T( "file: FILE_READ_DATA, dir: FILE_LIST_DIRECTORY" ) },
		{ /* 0x00000002 */ FILE_WRITE_DATA, _T( "file: FILE_WRITE_DATA, dir: FILE_ADD_FILE" ) },
		{ /* 0x00000004 */ FILE_APPEND_DATA, _T( "file: FILE_APPEND_DATA, dir: FILE_ADD_SUBDIRECTORY" ) },
		{ /* 0x00000008 */ FILE_READ_EA, _T( "FILE_READ_EA" ) },
		{ /* 0x00000010 */ FILE_WRITE_EA, _T( "FILE_WRITE_EA" ) },
		{ /* 0x00000020 */ FILE_EXECUTE, _T( "file: FILE_EXECUTE, dir: FILE_TRAVERSE" ) },
		{ /* 0x00000040 */ FILE_DELETE_CHILD, _T( "FILE_DELETE_CHILD" ) },
		{ /* 0x00000080 */ FILE_READ_ATTRIBUTES, _T( "FILE_READ_ATTRIBUTES" ) },
		{ /* 0x00000100 */ FILE_WRITE_ATTRIBUTES, _T( "FILE_WRITE_ATTRIBUTES" ) },
		{ /* 0x00000200 */ 0x00000200, _T( "unknown" ) },
		{ /* 0x00000400 */ 0x00000400, _T( "unknown" ) },
		{ /* 0x00000800 */ 0x00000800, _T( "unknown" ) },
		{ /* 0x00001000 */ 0x00001000, _T( "unknown" ) },
		{ /* 0x00002000 */ 0x00002000, _T( "unknown" ) },
		{ /* 0x00004000 */ 0x00004000, _T( "unknown" ) },
		{ /* 0x00008000 */ 0x00008000, _T( "unknown" ) },
		{ /* 0x001f01ff */ FILE_ALL_ACCESS, _T( "FILE_ALL_ACCESS" ) },
		{ /*            */ FILE_GENERIC_READ, _T( "FILE_GENERIC_READ" ) },
		{ /*            */ FILE_GENERIC_WRITE, _T( "FILE_GENERIC_WRITE" ) },
		{ /*            */ FILE_GENERIC_EXECUTE, _T( "FILE_GENERIC_EXECUTE" ) },
		{ /* 0x00010000 */ DELETE, _T( "DELETE" ) },
		{ /* 0x00020000 */ READ_CONTROL, _T( "READ_CONTROL" ) },
		{ /* 0x00040000 */ WRITE_DAC, _T( "WRITE_DAC" ) },
		{ /* 0x00080000 */ WRITE_OWNER, _T( "WRITE_OWNER" ) },
		{ /* 0x00100000 */ SYNCHRONIZE, _T( "SYNCHRONIZE" ) },
		{ /* 0x00200000 */ 0x00200000, _T( "unknown" ) },
		{ /* 0x00400000 */ 0x00400000, _T( "unknown" ) },
		{ /* 0x00800000 */ 0x00800000, _T( "unknown" ) },
		{ /* 0x01000000 */ ACCESS_SYSTEM_SECURITY, _T( "ACCESS_SYSTEM_SECURITY" ) },
		{ /* 0x02000000 */ MAXIMUM_ALLOWED, _T( "MAXIMUM_ALLOWED" ) },
		{ /* 0x04000000 */ 0x04000000, _T( "unknown" ) },
		{ /* 0x08000000 */ 0x08000000, _T( "unknown" ) },
		{ /* 0x10000000 */ GENERIC_ALL, _T( "GENERIC_ALL" ) },
		{ /* 0x20000000 */ GENERIC_EXECUTE, _T( "GENERIC_EXECUTE" ) },
		{ /* 0x40000000 */ GENERIC_WRITE, _T( "GENERIC_WRITE" ) },
		{ /* 0x80000000 */ GENERIC_READ, _T( "GENERIC_READ" ) },
		{ /* 0x0000ffff */ SPECIFIC_RIGHTS_ALL, _T( "SPECIFIC_RIGHTS_ALL" ) },
		{ /* 0x000f0000 */ STANDARD_RIGHTS_REQUIRED, _T( "STANDARD_RIGHTS_REQUIRED" ) },
		{ /* 0x001f0000 */ STANDARD_RIGHTS_ALL, _T( "STANDARD_RIGHTS_ALL" ) }
	};

	if ( ! GetAce( acl, index, (void **) &ace ) )
	{
		_tprintf( _T( "%s%cACL, entry %d: GetAce() failed, gle == %lu\n" ),
			indent( ind ), isSacl? 'S': 'D', index, GetLastError() );
		return;
	}

	switch ( ace->AceType )
	{
		case ACCESS_ALLOWED_ACE_TYPE:
			type = _T( "ACCESS_ALLOWED_ACE_TYPE" );
			psid = &( (ACCESS_ALLOWED_ACE *) ace )->SidStart;
			break;
		case ACCESS_DENIED_ACE_TYPE:
			type = _T( "ACCESS_DENIED_ACE_TYPE" );
			psid = &( (ACCESS_DENIED_ACE *) ace )->SidStart;
			break;
		case SYSTEM_AUDIT_ACE_TYPE:
			type = _T( "SYSTEM_AUDIT_ACE_TYPE" );
			psid = &( (SYSTEM_AUDIT_ACE *) ace )->SidStart;
			break;
		case SYSTEM_ALARM_ACE_TYPE:
			type = _T( "SYSTEM_ALARM_ACE_TYPE" );
			psid = &( (SYSTEM_ALARM_ACE *) ace )->SidStart;
			break;
#if 0
		case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
			type = _T( "ACCESS_ALLOWED_COMPOUND_ACE_TYPE" );
			psid = &( (ACCESS_ALLOWED_COMPOUND_ACE *) ace )->SidStart;
			break;
#endif
		case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
			type = _T( "ACCESS_ALLOWED_OBJECT_ACE_TYPE" );
			psid = &( (ACCESS_ALLOWED_OBJECT_ACE *) ace )->SidStart;
			break;
		case ACCESS_DENIED_OBJECT_ACE_TYPE:
			type = _T( "ACCESS_DENIED_OBJECT_ACE_TYPE" );
			psid = &( (ACCESS_DENIED_OBJECT_ACE *) ace )->SidStart;
			break;
		case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
			type = _T( "SYSTEM_AUDIT_OBJECT_ACE_TYPE" );
			psid = &( (SYSTEM_AUDIT_OBJECT_ACE *) ace )->SidStart;
			break;
		case SYSTEM_ALARM_OBJECT_ACE_TYPE:
			type = _T( "SYSTEM_ALARM_OBJECT_ACE_TYPE" );
			psid = &( (SYSTEM_ALARM_OBJECT_ACE *) ace )->SidStart;
			break;
		default:
			type = _T( "invalid-ACE-type" );
			psid = &( (ACCESS_ALLOWED_ACE *) ace )->SidStart;
			break;
	}
	_tprintf( _T( "%s%cACL entry %d\n" ), indent( ind ), isSacl? 'S': 'D', index );

	_tprintf( _T( "%sACE type: %s (%lu)\n" ), indent( ind + 2 ), type, (DWORD) ace->AceType );

	_tprintf( _T( "%sTrustee: " ), indent( ind + 2 ) );
	printSid( psid );

	_tprintf( _T( "%sInheritance/auditing:  " ), indent( ind + 2 ) );
	for ( j = ace->AceFlags, i = 0; i < 8; i ++ )
	{
		if ( i != 0 && i % 4 == 0 )
			putchar( ' ' );
		putchar( ( j & 0x80 )? '1': '0' );
		j <<= 1;
	}
	putchar( '\n' );
	for ( i = 0, first = true; i < lenof( inheritflags ); i ++ )
	{
		if ( inheritflags[i].flag == ( inheritflags[i].flag & ace->AceFlags ) )
		{
			_tprintf( _T( "%s%s\n" ), indent( ind + 4 ), inheritflags[i].txt );
			first = false;
		}
	}
	if ( first )
	{
		_tprintf( _T( "%sNO_INHERITANCE\n" ), indent( ind + 4 ) );
	}

	_tprintf( _T( "%sPermissions:  " ), indent( ind + 2 ) );
	for ( j = ( (ACCESS_ALLOWED_ACE *) ace )->Mask, i = 0; i < 32; i ++ )
	{
		if ( i != 0 && i % 4 == 0 )
			putchar( ' ' );
		if ( i != 0 && i % 16 == 0 )
			putchar( '-' );
		if ( i != 0 && i % 8 == 0 )
			putchar( ' ' );
		putchar( ( j & 0x80000000 )? '1': '0' );
		j <<= 1;
	}
	putchar( '\n' );
	j = ( (ACCESS_ALLOWED_ACE *) ace )->Mask;
	for ( i = 0, first = true; i < lenof( permflags ); i ++ )
	{
		if ( permflags[i].flag == ( permflags[i].flag & j ) )
		{
			_tprintf( _T( "%s%08lXh %s\n" ), indent( ind + 4 ), permflags[i].flag, permflags[i].txt );
			first = false;
		}
	}
	if ( first )
	{
		indent( ind + 4 );
		_tprintf( _T( "%s(none)\n" ), indent( ind + 4 ) );
	}
}



void printAcl( int ind, bool isSacl, PACL acl )
{
	DWORD i;
	ACL_SIZE_INFORMATION aci;

	if ( acl == 0 )
		return;

	if ( ! GetAclInformation( acl, &aci, sizeof aci, AclSizeInformation ) )
	{
		_tprintf( _T( "%sGAI(): gle == %lu\n" ), indent( ind ), GetLastError() );
		return;
	}

	_tprintf( _T( "%s%cACL header: %lu ACEs, %lu bytes used, %lu bytes free\n" ),
		indent( ind ), isSacl? 'S': 'D', aci.AceCount, aci.AclBytesInUse, aci.AclBytesFree );

	for ( i = 0; i < aci.AceCount; ++ i )
		printAce( ind + 2, isSacl, i, acl );

}



void printSD( int ind, SECURITY_DESCRIPTOR *psd )
{
	SECURITY_DESCRIPTOR_CONTROL sdc;
	DWORD rev;
	PSID psidOwner, psidGroup;
	int ownerDefaulted, groupDefaulted;
	PACL dacl, sacl;
	int daclPresent, daclDefaulted;
	int saclPresent, saclDefaulted;
	int i;
	bool first;
	WORD j;

	static struct {
		WORD flag;
		TCHAR *txt;
	} ctlflags[] = {
		{ /* 0x0001 */ SE_OWNER_DEFAULTED, _T( "SE_OWNER_DEFAULTED" ) },
		{ /* 0x0002 */ SE_GROUP_DEFAULTED, _T( "SE_GROUP_DEFAULTED" ) },
		{ /* 0x0004 */ SE_DACL_PRESENT, _T( "SE_DACL_PRESENT" ) },
		{ /* 0x0008 */ SE_DACL_DEFAULTED, _T( "SE_DACL_DEFAULTED" ) },
		{ /* 0x0010 */ SE_SACL_PRESENT, _T( "SE_SACL_PRESENT" ) },
		{ /* 0x0020 */ SE_SACL_DEFAULTED, _T( "SE_SACL_DEFAULTED" ) },
		{ /* 0x0040 */ 0x0040, _T( "unknown" ) },
		{ /* 0x0080 */ 0x0080, _T( "unknown" ) },
		{ /* 0x0100 */ SE_DACL_AUTO_INHERIT_REQ, _T( "SE_DACL_AUTO_INHERIT_REQ" ) },
		{ /* 0x0200 */ SE_SACL_AUTO_INHERIT_REQ, _T( "SE_SACL_AUTO_INHERIT_REQ" ) },
		{ /* 0x0400 */ SE_DACL_AUTO_INHERITED, _T( "SE_DACL_AUTO_INHERITED" ) },
		{ /* 0x0800 */ SE_SACL_AUTO_INHERITED, _T( "SE_SACL_AUTO_INHERITED" ) },
		{ /* 0x1000 */ SE_DACL_PROTECTED, _T( "SE_DACL_PROTECTED" ) },
		{ /* 0x2000 */ SE_SACL_PROTECTED, _T( "SE_SACL_PROTECTED" ) },
		{ /* 0x4000 */ 0x4000, _T( "unknown" ) },
		{ /* 0x8000 */ SE_SELF_RELATIVE, _T( "SE_SELF_RELATIVE" ) },
	};

	if ( ! GetSecurityDescriptorControl( psd, &sdc, &rev ) )
	{
		_tprintf( _T( "%sSECURITY_DESCRIPTOR: *** GSDC() failed, gle = %lu\n" ),
			indent( ind ), GetLastError() );
		return;
	}

	_tprintf( _T( "%sSECURITY_DESCRIPTOR: rev = %lu, length = %lu bytes\n" ),
		indent( ind ), rev, GetSecurityDescriptorLength( psd ) );

	_tprintf( _T( "%sSD control:  " ), indent( ind + 2 ) );
	for ( j = sdc, i = 0; i < 8 * sizeof WORD; ++ i )
	{
		if ( i != 0 && i % 4 == 0 )
			putchar( ' ' );
		if ( i != 0 && i % 16 == 0 )
			putchar( '-' );
		if ( i != 0 && i % 8 == 0 )
			putchar( ' ' );
		putchar( ( j & 0x8000 )? '1': '0' );
		j <<= 1;
	}
	putchar( '\n' );
	j = sdc;
	for ( i = 0, first = true; i < lenof( ctlflags ); i ++ )
	{
		if ( ctlflags[i].flag == ( ctlflags[i].flag & j ) )
		{
			_tprintf( _T( "%s%04hXh %s\n" ), indent( ind + 4 ), ctlflags[i].flag, ctlflags[i].txt );
			first = false;
		}
	}
	if ( first )
	{
		indent( ind + 4 );
		_tprintf( _T( "%s(none)\n" ), indent( ind + 4 ) );
	}

	ind += 2;

	if ( ! GetSecurityDescriptorOwner( psd, &psidOwner, &ownerDefaulted ) )
	{
		_tprintf( _T( "%sOwner: *** GSDO() failed, gle == %lu\n" ), indent( ind ), GetLastError() );
	}
	else
	{
		_tprintf( _T( "%sOwner: %s" ), indent( ind ), ownerDefaulted? _T( "[def] " ): _T( "" ) );
		printSid( psidOwner );
	}

	if ( ! GetSecurityDescriptorGroup( psd, &psidGroup, &groupDefaulted ) )
	{
		_tprintf( _T( "%sGroup: *** GSDG() failed, gle == %lu" ), indent( ind ), GetLastError() );
	}
	else
	{
		_tprintf( _T( "%sGroup: %s" ), indent( ind ), groupDefaulted? _T( "[def] " ): _T( "" ) );
		printSid( psidGroup );
	}

	dacl = 0;
	if ( ! GetSecurityDescriptorDacl( psd, &daclPresent, &dacl, &daclDefaulted ) )
	{
		_tprintf( _T( "%sDACL: *** GSDD() failed, gle == %lu" ), indent( ind ), GetLastError() );
	}
	else
	{
		_tprintf( _T( "%sDACL: %s%s%s\n" ), indent( ind ), daclPresent? _T( "[present]" ): _T( "[absent]" ),
			daclDefaulted? _T( "[defaulted]" ): _T( "[specified]" ), dacl == 0? _T( "[NULL DACL]" ): _T( "" ) );
		if ( dacl != 0 )
			printAcl( ind + 2, false, dacl );
	}

	sacl = 0;
	if ( ! GetSecurityDescriptorSacl( psd, &saclPresent, &sacl, &saclDefaulted ) )
	{
		_tprintf( _T( "%sSACL: *** GSDD() failed, gle == %lu" ), indent( ind ), GetLastError() );
	}
	else
	{
		_tprintf( _T( "%sSACL: %s%s%s\n" ), indent( ind ), saclPresent? _T( "[present]" ): _T( "[absent]" ),
			saclDefaulted? _T( "[defaulted]" ): _T( "[specified]" ), sacl == 0? _T( "[NULL SACL]" ): _T( "" ) );
		if ( sacl != 0 )
			printAcl( ind + 2, true, sacl );
	}
}
