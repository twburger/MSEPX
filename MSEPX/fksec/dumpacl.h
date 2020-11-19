

// returns the address of a !!static!!, non-thread-local, buffer with
// the text representation of the SID that was passed in
const TCHAR *sidToText( PSID psid );

// getSecurityPriv() may be used by the caller to enable SE_SECURITY_NAME.
// if this is not done, don't ask for SYSTEM_SECURITY_INFORMATION!
bool getSecurityPriv( void );

// Translates a SID and terminates it with a linefeed. No provision is
// made to dump the SID in textual form if LookupAccountSid() fails.
void printSid( PSID psid );

// Displays the index-th (0-based) ACE from ACL with an indent of _ind_
// spaces; isSacl, if true, causes interpretation as an SACL, else DACL
void printAce( int ind, int isSacl, int index, PACL acl );

// Dumps an entire ACL with an indent of _ind_ spaces; isSacl decides
// whether it will be labeled "SACL" or "DACL"
void printAcl( int ind, bool isSacl, PACL acl );

// printSD() displays an entire SECURITY_DESCRIPTOR with the usual indent.
void printSD( int ind, SECURITY_DESCRIPTOR *psd );
