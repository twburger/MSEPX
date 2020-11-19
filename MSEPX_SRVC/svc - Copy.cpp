#include "../MSEPX_SRVC/svc.h"
#include "../MSEPX_SRVC/RegValSvc.h"
//
// Purpose: 
//   Entry point for the process
//
// Parameters:
//   None
// 
// Return value:
//   None
//

BOOL ProcessCommand( DWORD dwArgc, LPWSTR * lpszArgv );
DWORD WINAPI PipeThread(LPVOID); 
DWORD WINAPI InstanceThread(LPVOID); 
VOID ProcessRequest(LPWSTR, LPWSTR, DWORD &);

//void SetNullSessionPipes(WCHAR * PipeName, BOOL Remove = FALSE);
//LONG RegInsertToMultiString( HKEY hKey, const WCHAR* valueName, const WCHAR* str );
//LONG RegRemoveFromMultiString( HKEY hKey, const WCHAR* valueName, const WCHAR* str );
//BOOL FindEntryInMultiString( const WCHAR* data, const WCHAR* entry, DWORD* offset );

#define MAX_SVC_MSSG_SZ 1024

WCHAR mssg[MAX_SVC_MSSG_SZ];

SERVICE_STATUS          gSvcStatus; 
SERVICE_STATUS_HANDLE   gSvcStatusHandle; 
HANDLE                  ghSvcStopEvent = NULL;


void __cdecl _tmain(int argc, WCHAR *argv[]) 
{ 
	// If command-line parameter is "install", install the service. 
	// Otherwise, the service is probably being started by the SCM.

	if( argc == 2 && lstrcmpi( argv[1], TEXT("install")) == 0 )
	{
		SvcInstall();
		return;
	}

	// TO_DO: Add any additional services for the process to this table.
	SERVICE_TABLE_ENTRY DispatchTable[] = 
	{ 
		{ SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain }, 
		{ NULL, NULL } 
	}; 

	// Connects the main thread of a service process to the service control manager, 
	// which causes the thread to be the service control dispatcher thread for the calling process.
	// This call returns when the service has stopped. 
	// The process should simply terminate when the call returns.
	// The dispatcher thread loops, waiting for incoming control requests for the services specified 
	// in the dispatch table. This thread returns when there is an error or when all of the services 
	// in the process have terminated. When all services in the process have terminated, the SCM 
	// sends a control request to the dispatcher thread telling it to exit. 
	// This thread then returns from the StartServiceCtrlDispatcher call 
	// and the process can terminate.
	if (!StartServiceCtrlDispatcher( DispatchTable )) 
	{ 
		//printf("Service terminated\n"); 
		SvcReportEvent(TEXT("StartServiceCtrlDispatcher")); 
	} 
} 

//
// Purpose: 
//   Installs a service in the SCM database
//
// Parameters:
//   None
// 
// Return value:
//   None
//
VOID SvcInstall()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	WCHAR szPath[MAX_PATH];

	if( !GetModuleFileName( NULL, szPath, MAX_PATH ) )
	{
		//printf("Cannot install service (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager( 
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager) 
	{
		//printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Create the service

	schService = CreateService(
		schSCManager,              // SCM database 
		SVCNAME,                   // name of service 
		SVCNAME,                   // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_DEMAND_START,      // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		szPath,                    // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // NULL means run as LocalSystem account 
		NULL);                     // no password 

	if (schService == NULL) 
	{
		//printf("CreateService failed (%d)\n", GetLastError()); 
		CloseServiceHandle(schSCManager);
		return;
	}
	else //printf("Service installed successfully\n"); 

		CloseServiceHandle(schService); 
	CloseServiceHandle(schSCManager);
}

//
// Purpose: 
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None.
//
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
	// Register the handler function for the service

	gSvcStatusHandle = RegisterServiceCtrlHandler( 
		SVCNAME, 
		SvcCtrlHandler);

	if( !gSvcStatusHandle )
	{ 
		SvcReportEvent(TEXT("RegisterServiceCtrlHandler - Could not register a service control handler")); 
		//printf("Could not register a service control handler");
		return; 
	} 

	// These SERVICE_STATUS members remain as set here

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
	gSvcStatus.dwServiceSpecificExitCode = 0;    

	//   Be sure to periodically call ReportSvcStatus() with 
	//   SERVICE_START_PENDING. If initialization fails, call
	//   ReportSvcStatus with SERVICE_STOPPED.

	// Report initial status to the SCM

	ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );

	// Perform service-specific initialization and work.

	//SvcReportEvent(TEXT("Service STARTS")); 

	ServiceRun( dwArgc, lpszArgv );
}

//
// Purpose: 
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None
//


// Opening a named pipe from service is restricted for local users (users that are not administrators) since Windows NT version 3.5 or later. 
// If a service running in the Local System account attempts to open a named pipe on a computer running Windows NT version 3.5 or later, 
// the operation may fail with an Access Denied error (error 5). This can happen even if the pipe was created with a NULL DACL. 
// To resolve it, you will need to add your pipe name to NullSessionPipes in the registry.
// \HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes
// For detail information, please see KB article: http://support.microsoft.com/kb/126645

VOID ServiceRun( DWORD dwArgc, LPTSTR *lpszArgv)
{
	// Initialize
	BOOL IsReady = FALSE;
	WCHAR PipeName[MAX_PATH_LEN];

	_ThreadArgs ThreadArgs = {NULL,NULL};

	// Create a stop event handle. The control handler function, SvcCtrlHandler,
	// uses SetEvent to signal this event when it receives the stop control code.

	ghSvcStopEvent = CreateEvent(
		NULL,    // default security attributes
		TRUE,    // manual reset event
		FALSE,   // not in signaled state right now
		NULL);   // no name

	if ( ghSvcStopEvent == NULL)
	{
		ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
		return;
	}

	// there should be command line arguments that provide the pipe name
	// there will be two arguments - the first is the name of the service itself: RegValSvc
	if( 2 == dwArgc )
	{
		StringCchCopy(PipeName, MAX_PATH_LEN, lpszArgv[1] );

		// add the pipe to the REG_MULTI_SZ value in NullSessionPipes 
		//SetNullSessionPipes(PipeName);

		DWORD  dwThreadId = 0; 
		HANDLE hThread = NULL;

		// Create an event that signals the thread that will handle pipe events.
		ThreadArgs.QuitEvent = CreateEvent( 
			NULL,    // default security attribute 
			TRUE,    // manual-reset event 
			FALSE,    // initial state = not signaled 
			NULL);   // unnamed event object

		// set the thread arguments with the pipe name
		ThreadArgs.PipeName = PipeName;

		// Start an infinite loop that stops when a quit event is detected
		while (TRUE) 
		{
			//   Be sure to periodically call ReportSvcStatus() with 
			//   SERVICE_RUNNING.
			ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

			// Create a thread for a client request that listens for a pipe write
			if(! hThread )
			{
				hThread = CreateThread( 
					NULL,              // no security attribute 
					0,                 // default stack size 
					PipeThread,    // thread proc
					(LPVOID) &ThreadArgs,//  hReadWritePipe,    // thread parameter 
					0,                 // not suspended 
					&dwThreadId);      // returns thread ID 
			}

			if(hThread == NULL) 
			{
				SvcReportEvent(TEXT("Creation of PipeThread failed."));
			}
			// wait for the thread to indicate it is done by flagging the quit event
			// this allows for the service loop to look for the service stop event while 
			// processing client requests
			else
			{
				if( WAIT_OBJECT_0 == WaitForSingleObject(ThreadArgs.QuitEvent, 200) )
				{
					// Closing a thread handle does not terminate the associated thread or remove the thread object
					CloseHandle(hThread);
					hThread = NULL;
					ResetEvent(ThreadArgs.QuitEvent);
				}
			}

			// Look for a stop service 
			if( WAIT_OBJECT_0 == WaitForSingleObject(ghSvcStopEvent, 200 )) //INFINITE) )
			{
				// need code here to make the thread terminate by opening the pipe
				// and sending a null message
				SendMessage2RegValSvc( _T("") );
				CloseHandle(hThread);
				hThread = NULL;

				// remove the pipe to the REG_MULTI_SZ value in NullSessionPipes 
				//SetNullSessionPipes(PipeName, TRUE);

				// finally tell the service manager we are stopped
				ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );

				break;
			}
		} // while(1)
	}
	else 
	{	
		StringCchPrintf(mssg, MAX_SVC_MSSG_SZ, _T("Wrong arg count: %d. Service Name: %s"), dwArgc, lpszArgv[0] );
		SvcReportEvent(mssg);
	}

	//////////////////////////////////////////////////
	// The work loop has ended for some reason - probably an error
	// Wait forever for a stop service
	while(1)
	{
		// Check whether to stop the service.
		WaitForSingleObject(ghSvcStopEvent, INFINITE);

		// remove the pipe to the REG_MULTI_SZ value in NullSessionPipes 
		//SetNullSessionPipes(PipeName, TRUE);

		// finally tell the service manager we are stopped probably due to bad args
		ReportSvcStatus( SERVICE_STOPPED, ERROR_BAD_ARGUMENTS, 0 );

		break;
	}

	return;
}

DWORD WINAPI PipeThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{ 
	DWORD rv = -1;
	LPCWSTR PipeName = NULL;
	HANDLE QuitEvent = NULL;
	HANDLE hReadWritePipe = INVALID_HANDLE_VALUE;

	// Do some extra error checking since the app will keep running even if this
	// thread fails.

	if (lpvParam == NULL)
	{
		SetEvent(QuitEvent);
		return (DWORD)-1;
	}

	// The thread's parameter is a handle to a structure with the pipe name and 
	// quit event
	PipeName = ((_ThreadArgs *)lpvParam)->PipeName;
	QuitEvent = ((_ThreadArgs *)lpvParam)->QuitEvent;

	hReadWritePipe = CreateNamedPipe( 
		PipeName,   // pipe name 
		/*FILE_FLAG_OVERLAPPED | */PIPE_ACCESS_DUPLEX, // pipe open mode
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // PIPE_NOWAIT , // pipe mode
		PIPE_UNLIMITED_INSTANCES,              // instances of this pipe
		BUFSIZE,			// output buffer size
		BUFSIZE,			// input buffer size
		0,				// default client timeout
		NULL			// default security attributes
		);

	// Break if the pipe handle is valid. 
	if (hReadWritePipe != INVALID_HANDLE_VALUE)
	{
		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero and GetLastError returns ERROR_PIPE_CONNECTED then it's OK to 
		// process the message.
		BOOL IsReady = ConnectNamedPipe(hReadWritePipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		if( IsReady )
		{
			DWORD  dwThreadId = 0; 

			// If the server is to be serving multiple clients the code in a new thread is created
			// to handle the client request read and writes.
			HANDLE hThread = CreateThread( 
				NULL,              // no security attribute 
				0,                 // default stack size 
				InstanceThread,    // thread proc
				(LPVOID) hReadWritePipe,    // thread parameter 
				0,                 // not suspended 
				&dwThreadId );		// returns the thread's ID

			if(hThread == NULL) 
			{
				SvcReportEvent(TEXT("Creation of InstanceThread failed"));
			}
			// wait for the thread to indicate it is done by flagging the quit event
			// this allows for the service loop to look for the service stop event while 
			// processing client requests
			else
			{
				// Closing a thread handle does not terminate the associated thread or remove the thread object
				CloseHandle(hThread);
				hThread = NULL;
				// the pipe is closed by the thread so don't close it again 
				hReadWritePipe = INVALID_HANDLE_VALUE;
				// all went well
				rv = 1;
			}
		}
		else
		{
			SvcReportEvent(TEXT("Connection to client failed"));
		}
	}

	if (hReadWritePipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hReadWritePipe); 
		hReadWritePipe = INVALID_HANDLE_VALUE;
	}

	// signal the thread has connected to the client through the pipe and is over
	SetEvent(QuitEvent);

	return rv;
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
{
	HANDLE hHeap      = GetProcessHeap();
	WCHAR* pchRequest = (WCHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(WCHAR));
	WCHAR* pchReply   = (WCHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(WCHAR));
	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0; 
	BOOL fSuccess = FALSE;
	DWORD rv = -1;


	if (lpvParam == NULL)
	{
		return (DWORD)-1;
	}

	if (pchRequest == NULL)
	{
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		return (DWORD)-1;
	}

	if (pchReply == NULL)
	{
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	HANDLE hReadWritePipe = (HANDLE)lpvParam;

	while(TRUE)
	{
		// Read client requests from the pipe. This simplistic code only allows messages
		// up to BUFSIZE characters in length.
		fSuccess = ReadFile( 
			hReadWritePipe,        // handle to pipe 
			pchRequest,    // buffer to receive data 
			BUFSIZE*sizeof(WCHAR), // size of buffer 
			&cbBytesRead, // number of bytes read 
			NULL);        // not overlapped I/O 

		// when there is no longer anything to read the return is 0 with 0 bytes read and the last error is 0 or
		// ERROR_BROKEN_PIPE if the client read all it needs from the server and has closed its end
		if (!fSuccess || cbBytesRead == 0)
		{   
			DWORD err = GetLastError();
			if ( ERROR_BROKEN_PIPE == err || 0 == err )
			{
				// no more to read
#if(_DEBUG)
				if ( ERROR_BROKEN_PIPE == err )
					SvcReportEvent(TEXT("InstanceThread: client disconnected."));
#endif
				rv = 1;
			}
			else
			{
				SvcReportEvent(TEXT("InstanceThread ReadFile failed."));
			}

			break;
		}

#if(_DEBUG)
		StringCchPrintf(mssg, MAX_SVC_MSSG_SZ, _T("*** Read the client message: '%s' ***"), pchRequest );
		SvcReportEvent(mssg);
#endif
		// Process the incoming message.
		cbReplyBytes = BUFSIZE*sizeof(WCHAR); // provide the reply buffer size
		ProcessRequest(pchRequest, pchReply, cbReplyBytes); 

		// Write the reply to the pipe. 
		fSuccess = WriteFile( 
			hReadWritePipe,        // handle to pipe 
			pchReply,     // buffer to write from 
			cbReplyBytes, // number of bytes to write 
			&cbWritten,   // number of bytes written 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbReplyBytes != cbWritten)
		{   
			SvcReportEvent(TEXT("InstanceThread WriteFile failed."));
			break;
		}
	}

	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 

	FlushFileBuffers(hReadWritePipe); 
	DisconnectNamedPipe(hReadWritePipe); 
	CloseHandle(hReadWritePipe); 

	HeapFree(hHeap, 0, pchRequest);
	HeapFree(hHeap, 0, pchReply);

	return rv;
}

// Process the client request message into a command to be processed.
// pchReply should contain the result code and a space followed by a possible message
// the reply must be double null terminated

#define REQ_PARAM_SEP '^'

VOID ProcessRequest( LPWSTR pchRequest, LPWSTR pchReply, DWORD & chReplyBytes )
{
	BOOL AOK = FALSE;
	int paramcount=0;
	LPWSTR *params = NULL;

	assert(pchRequest && pchReply && chReplyBytes && chReplyBytes > 0);

	// zero out the reply
	//memset( (void*) pchReply, 0, chReplyBytes * sizeof(WCHAR) );

	if( pchRequest && *pchRequest)
	{
		// the request is a command followed by a set of paramters
		// we will use the carat (^) as the field separator
		int c = 0;
		LPWSTR p =  pchRequest;
		// count the separators
		while(*p)
		{
			if( REQ_PARAM_SEP == *p )
			{
				c++;
			}
			p++;
		}
		// set the count to one based
		c++;

		// if there is a command and at least 1 argument
		if( c >= 2 )
		{
			paramcount=c;
			params = new LPWSTR[paramcount];
			c = 0;
			p =  pchRequest;
			params[c] = p;
			while(*p && c < paramcount)
			{
				if( REQ_PARAM_SEP == *p )
				{
					*p = 0;
					p++;
					c++;
					params[c] = p;
				}
				p++;
			}

			AOK = TRUE;
		}
	}

	// if the command was not parsed return an error
	// An extra final null is placed on the end of the reply
	if(!AOK)
	{
		StringCchCopy( pchReply, BUFSIZE, TEXT("1 The request was not valid. Possibly not enough arguments.0"));
	}
	else
	{
		AOK = ProcessCommand( paramcount, params );
		if( AOK )
			StringCchCopy( pchReply, BUFSIZE, TEXT("0"));  // send ERROR_SUCCESS back
		else
			StringCchCopy( pchReply, BUFSIZE, TEXT("1 The request was not valid. It was not processed."));
	}

	// count the terminating null
	chReplyBytes = (lstrlen(pchReply)+1)*sizeof(WCHAR);

	if( params )
		delete params;

	return;
}

enum REG_CMD {
	NO_CMD,
	ADD_CMD,
	DEL_CMD
};

BOOL ProcessCommand( DWORD dwArgc, LPWSTR * lpszArgv )
{
	REG_CMD cmd=NO_CMD;
	BOOL bRV = FALSE;

	// This code will create a registry key value or remove it.
	// The idea is that the service runs under system so any registry value can be changed by the SYSTEM user
	// unlike a program run by a user that may or may not have permisssion to write and delete values for that key.
	// A command and argument was recieved
	// lpszArgv[0] - command
	// lpszArgv[1] - registry key - one of HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS
	// lpszArgv[2] - registry sub key path
	// lpszArgv[3] - value name
	// lpszArgv[4] - value type
	// lpszArgv[5] - value

	// The only commands we need to support is add and delete
	// Make sure the argument count is correct
	if( ADD_COMMAND == (WCHAR) *lpszArgv[0] && 6 == dwArgc )
	{
		cmd = ADD_CMD;
		bRV = TRUE;
	}
	else if( DEL_COMMAND == (WCHAR) *lpszArgv[0] && 4 == dwArgc )
	{
		cmd = DEL_CMD;
		bRV = TRUE;
	}
	else
	{
		SvcReportEvent(TEXT("Registry command or arguments are incorrect."));
	}

	if( bRV)
	{
		bRV = FALSE;

		HKEY hSubKey = GetRegSubKey(lpszArgv[1],lpszArgv[2]);

		if( hSubKey )
		{
			if( ADD_CMD == cmd )
			{
				try {
					DWORD size = 0;
					DWORD dwType = GetRegValType(lpszArgv[4]);
					const byte * data = GetRegData(dwType, lpszArgv[5], size);
					if( dwType && data && size )
					{
						DWORD rv = RegSetValueEx( hSubKey, lpszArgv[3], 0, REG_DWORD, data, size);
						bRV = TRUE;
					}
				} catch( ... )
				{
					SvcReportEvent(TEXT("Registry value creation failed."));
				}
			}
			else if( DEL_CMD == cmd )
			{
				// try to delete the key value
				try {
					DWORD rv = RegDeleteValue( hSubKey, lpszArgv[3]);
					bRV = TRUE;
				} catch( ... )
				{
					SvcReportEvent(TEXT("Registry value deletion failed."));
				}
			}
			RegFlushKey(hSubKey); //immediately write the changes
			RegCloseKey(hSubKey);
		}
		else
		{
			StringCchPrintf(mssg, 
				MAX_SVC_MSSG_SZ, 
				_T("Registry key value was not found: %s%s"), 
				lpszArgv[1],lpszArgv[2] );
			SvcReportEvent(mssg);
		}
	}

	return bRV;
}

HKEY GetRegistrationKey(LPTSTR keyname)
{
	HKEY hKey = NULL;

	if( !lstrcmpi( keyname, TEXT("HKEY_CLASSES_ROOT")))
		hKey = HKEY_CLASSES_ROOT;
	else if( !lstrcmpi(keyname, TEXT("HKEY_CURRENT_USER")))
		hKey = HKEY_CURRENT_USER;
	else if( !lstrcmpi( keyname, TEXT("HKEY_LOCAL_MACHINE")))
		hKey = HKEY_LOCAL_MACHINE;
	else if( !lstrcmpi( keyname, TEXT("HKEY_USERS")))
		hKey = HKEY_USERS;

	return hKey;
}


HKEY GetRegSubKey( LPTSTR keyname, LPTSTR subkeyname )
{
	HKEY hSubKey = NULL;
	HKEY hKey = GetRegistrationKey(keyname); // do not need to call RegCloseKey(hKey) on a defined key
	DWORD rv = 0;
	if( hKey )
	{
		rv = RegOpenKeyExW( hKey, subkeyname,0, KEY_WRITE, &hSubKey);
	}
	//RegCloseKey(hKey); // do not need to call RegCloseKey(hKey) on a defined key
	return hSubKey;
}

// only handle REG_SZ and REG_DWORD for now
DWORD GetRegValType(LPTSTR RegValueType)
{
	DWORD regtype = REG_NONE;

	if( !lstrcmpi( RegValueType, TEXT("REG_SZ")))
		regtype = REG_SZ;
	else if( !lstrcmpi( RegValueType, TEXT("REG_DWORD")))
		regtype = REG_DWORD;

	return regtype;
}

static DWORD RegDataValue = 0;

byte* GetRegData(DWORD RegValueType, LPTSTR value, DWORD & size)
{
	byte * ptr = NULL;
	size = 0;

	switch(RegValueType)
	{
	case REG_SZ:
		ptr = (byte *)value;
		size = (DWORD) lstrlen(value)+1;
		break;
	case REG_DWORD:
		RegDataValue =  _wtol(value);
		ptr = (byte *)&RegDataValue;
		size = sizeof(DWORD);
		break;
	}

	return ptr;
}

//
// Purpose: 
//   Sets the current service status and reports it to the SCM.
//
// Parameters:
//   dwCurrentState - The current state (see SERVICE_STATUS)
//   dwWin32ExitCode - The system error code
//   dwWaitHint - Estimated time for pending operation, 
//     in milliseconds
// 
// Return value:
//   None
//
VOID ReportSvcStatus( DWORD dwCurrentState,
					 DWORD dwWin32ExitCode,
					 DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ( (dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED) )
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the SCM.
	SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}

//
// Purpose: 
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
// 
// Return value:
//   None
//
VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{
	// Handle the requested control code. 

	switch(dwCtrl) 
	{  
	case SERVICE_CONTROL_STOP: 
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

		// Signal the service to stop.

		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);

		return;

	case SERVICE_CONTROL_INTERROGATE: 
		break; 

	default: 
		break;
	} 

}

//
// Purpose: 
//   Logs messages to the event log
//
// Parameters:
//   szFunction - name of function that failed
// 
// Return value:
//   None
//
// Remarks:
//   The service must have an entry in the Application event log.
//
//#define SVC_ERROR 0

VOID SvcReportEvent(LPTSTR szFunction) 
{ 
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];
	WCHAR Buffer[80];

	hEventSource = RegisterEventSource(NULL, SVCNAME);

	if( NULL != hEventSource )
	{
		StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

		lpszStrings[0] = SVCNAME;
		lpszStrings[1] = Buffer;

		ReportEvent(hEventSource,        // event log handle
			EVENTLOG_ERROR_TYPE, // event type
			0,                   // event category
			SVC_ERROR,           // event identifier
			NULL,                // no security identifier
			2,                   // size of lpszStrings array
			0,                   // no binary data
			lpszStrings,         // array of strings
			NULL);               // no binary data

		DeregisterEventSource(hEventSource);
	}
}

/*
void SetNullSessionPipes(WCHAR * PipeName, BOOL Remove )
{
	HKEY hKey = NULL;
	DWORD rv = RegOpenKeyExW( HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"),
		0, KEY_READ | KEY_WRITE, &hKey);
	if( ERROR_SUCCESS == rv && hKey )
	{
		if( Remove )
			rv = RegRemoveFromMultiString(hKey, _T("NullSessionPipes"), PipeName );
		else
			rv = RegInsertToMultiString( hKey, _T("NullSessionPipes"), PipeName );
	}
	if(hKey)
		RegCloseKey(hKey);
}

*/

/** Inserts a string to a MULTI_SZ value. If the string is already present, nothing will be added. This
avoids duplicated strings.
Input parameters: hKey: handle to open key, 
valueName: name of the multistring value to which the str value will be appended, 
str: string to append
<-- ERROR_SUCCESS 
  | any error code returned by RegQueryValueEx and RegSetValueEx */ 

/*
LONG RegInsertToMultiString( HKEY hKey, const WCHAR* valueName, const WCHAR* str )
{
    LONG status; 
    BYTE* data;
    DWORD newSize, oldSize, strSize;

    // Obtains the current data size
    status = RegQueryValueEx( hKey, 
                              valueName, 
                              NULL, 
                              NULL, 
                              NULL, 
                              &oldSize );

    if( status != ERROR_SUCCESS )
    {
        return status;
    }

    // Allocates memory to hold all the data
    strSize = (wcslen(str) + 1) * sizeof(WCHAR);
    newSize = oldSize + strSize;
    data = (BYTE*)HeapAlloc( GetProcessHeap(), 0 , newSize );
    if( data == NULL )
    {
        return ERROR_OUTOFMEMORY;
    }

    // Obtains the current data
    status = RegQueryValueEx( hKey, 
                              valueName, 
                              NULL, 
                              NULL, 
                              data, 
                              &oldSize );
    if( status != ERROR_SUCCESS )
    {
        HeapFree( GetProcessHeap(), 0 , data );
        return status;
    }

    // Looks if the data is already there
    if( FindEntryInMultiString( (WCHAR*)data, str, NULL ) )
    {
        HeapFree( GetProcessHeap(), 0 , data );
        return ERROR_SUCCESS;
    }        

    // Appends our entry
    CopyMemory( data+oldSize-2, str, strSize );

    // Append another NULL terminator
    data[newSize-2] = 0;
    data[newSize-1] = 0;

    // Sets the new data
    status = RegSetValueEx( hKey, 
                            valueName, 
                            0, 
                            REG_MULTI_SZ, 
                            data, 
                            newSize );

    HeapFree( GetProcessHeap(), 0 , data );

    return status;
}
*/

/** Removes a string from a MULTI_SZ value.
Input parameters: hKey: handle to open key,
valueName: name of the multistring value to which the str value will be appended,
str: string to append
<-- ERROR_SUCCESS 
  | ERROR_INVALID_NAME: str was not found 
  | any error code returned by RegQueryValueEx and RegSetValueEx */ 
/*
LONG RegRemoveFromMultiString( HKEY hKey, const WCHAR* valueName, const WCHAR* str )
{
    LONG status; 
    BYTE* data;
    DWORD size, offset, strSize;
    BYTE* p;
    BOOL  found = FALSE;

    // Obtains the current data size
    status = RegQueryValueEx( hKey, 
                              valueName, 
                              NULL, 
                              NULL, 
                              NULL, 
                              &size );
    if( status != ERROR_SUCCESS )
    {
        return status;
    }

    // Allocates memory to hold all the data
    strSize = (wcslen(str) + 1) * sizeof(WCHAR);
    data = (BYTE*)HeapAlloc( GetProcessHeap(), 0 , size );
    if( data == NULL )
    {
        return ERROR_OUTOFMEMORY;
    }

    // Obtains the current data
    status = RegQueryValueEx( hKey, 
                              valueName, 
                              NULL, 
                              NULL, 
                              data, 
                              &size );
    if( status != ERROR_SUCCESS )
    {
        HeapFree( GetProcessHeap(), 0 , data );
        return status;
    }

    // Searches the entry to be removed
    found = FindEntryInMultiString( (WCHAR*)data, str, &offset );
    if( !found )
    {
        HeapFree( GetProcessHeap(), 0 , data );
        return ERROR_INVALID_NAME;
    }

    // Writes over the entry, and then puts it back in the registry
    p = data + offset;

    CopyMemory( p, p + strSize, size - strSize - offset );

    status = RegSetValueEx( hKey, 
                            valueName, 
                            0, 
                            REG_MULTI_SZ, 
                            data, 
                            size - strSize );

    HeapFree( GetProcessHeap(), 0 , data );

    return status;
}
*/
/** Input parameters: data: multi string in which the entry is to be found,
entry: to find
offset: if not NULL holds the number of bytes from the beginning of data where entry starts
Output parameters: TRUE: found entry
  | FALSE: did not find entry */ 
/*
BOOL FindEntryInMultiString( const WCHAR* data, const WCHAR* entry, DWORD* offset )
{
    BYTE* p;
    DWORD read, tmp;
    BOOL  found = FALSE;

    p = (BYTE*)data;
    read = 0;
    while( !( (*p == 0 ) && ((*(p+1)) == 0 ) )  )
    {
        if( wcscmp( (WCHAR*)p, entry ) == 0 )
        {
            found = TRUE;
            break;
        }

        tmp = (wcslen( (WCHAR*)p ) + 1) * sizeof(WCHAR);
        read += tmp ;
        p += tmp;
    }

    if( offset )
    {
        if( found )
        {
            *offset = read;
        }
        else
        {
            *offset = 0;
        }
    }
    return found;
}
*/
