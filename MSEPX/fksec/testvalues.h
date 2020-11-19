// testvalues.h: defines that need to be adapted to your environment
// I recommend that you keep your own version of this file around


#define TEST_SD 1
#define TEST_ACL 1
#define TEST_ACE 1
#define TEST_PRIV 1
#define TEST_SID 1
#define TEST_REG 1
#define TEST_TYPICAL 1
#define TEST_ADS 1

#define	BACK	_T( "\\" )

// change these according to your setup
#define LOOKUP_SRV	_T( "\\\\BAR" )		// a DC if you are in a domain; else the local machine
#define DOMAIN		_T( "BAR" )			// a valid domain name (your domain, or the machine name if none)
#define GOODGUY		_T( "felixk" )		// a valid user account in that domain
#define BADGUY		_T( "bogus user" )	// a user account that does not exist
#define LOCAL_GROUP	_T( "foo" )			// an existing local group
// an AdsPath to a AD object you want to mess with the SD on 
#define ADS_SOME_OBJECT _T( "OU=test2,OU=test1,DC=nt,DC=mvps,DC=org" )

// change these according to the language version of NT that you use
#define ADMINISTRATORS	_T( "Administrators" )
// DO NOT DEFINE DOMAIN_ADMINS if your machine is not a member of a domain
//#define DOMAIN_ADMINS	_T( "Domain Admins" )
#define EVERYONE		_T( "Everyone" )
#define GUEST			_T( "Guest" )
#define GUESTS			_T( "Guests" )
