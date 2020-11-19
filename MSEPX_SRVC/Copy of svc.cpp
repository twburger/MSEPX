#include "svc.h"
#include "RegValSvc.h"
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

BOOL ProcessCommand( TCHAR*);
DWORD WINAPI InstanceThread(LPVOID); 
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD); 

TCHAR mssg[1024];

void __cdecl _tmain(int argc, TCHAR *argv[]) 
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
	TCHAR szPath[MAX_PATH];

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

	// Report initial status to the SCM

	ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );

	// Perform service-specific initialization and work.

	SvcReportEvent(TEXT("Service STARTS")); 

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
#define MAX_PATH_LEN 255

WCHAR PipeName[MAX_PATH_LEN];
HANDLE hReadWritePipe = INVALID_HANDLE_VALUE;

// Openning a named pipe from service is restricted since Windows NT version 3.5 or later. 
// To resolve it, you will need to add your pipe name to NullSessionPipes in the registry.
// For detail information, please see KB article: http://support.microsoft.com/kb/126645

BOOL bQuitSent = FALSE;

VOID ServiceRun( DWORD dwArgc, LPTSTR *lpszArgv)
{
	//   Be sure to periodically call ReportSvcStatus() with 
	//   SERVICE_START_PENDING. If initialization fails, call
	//   ReportSvcStatus with SERVICE_STOPPED.

	// Initialize
	BOOL IsReady = FALSE;
	bQuitSent = FALSE;

	_ThreadArgs ThreadArgs = {NULL,NULL};

	// create an event that signals the service to stop when the client sends "QUIT"
	ThreadArgs.QuitEvent = CreateEvent( 
         NULL,    // default security attribute 
         TRUE,    // manual-reset event 
         FALSE,    // initial state = not signaled 
         NULL);   // unnamed event object 

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

	hReadWritePipe = INVALID_HANDLE_VALUE;

	//wsprintf(mssg,_T("Arg count: %d. Pipe Name: %s"), dwArgc, lpszArgv[1] );
	//SvcReportEvent(mssg);

	// there should be command line arguments that provide the pipe name
	// there will b tow arguments - the first is the name of the service itself: RegValSvc
	if( 2 == dwArgc )
	{

		//wsprintf(mssg,_T("Attempting to open/create pipe Name: %s"), lpszArgv[1] );
		//SvcReportEvent(mssg);

		lstrcpy( PipeName, lpszArgv[1] );

		// open the pipe
		while (!bQuitSent) 
		{
			if( INVALID_HANDLE_VALUE == hReadWritePipe )
				hReadWritePipe = CreateNamedPipe( 
					PipeName,   // pipe name 
					/*FILE_FLAG_OVERLAPPED | */PIPE_ACCESS_DUPLEX, // pipe open mode
					PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT, // | PIPE_WAIT, // pipe mode
					PIPE_UNLIMITED_INSTANCES,              // instances of this pipe
					BUFSIZE,			// output buffer size
					BUFSIZE,			// input buffer size
					0,				// default client timeout
					NULL			// default security attributes
					);

			// Break if the pipe handle is valid. 
			if (hReadWritePipe != INVALID_HANDLE_VALUE)
			{
				//wsprintf(mssg,_T("Open SUCCESS. Waiting for client to connect pipe Name: %s"), lpszArgv[1] );
				//SvcReportEvent(mssg);

				// Wait for the client to connect; if it succeeds, 
				// the function returns a nonzero value. If the function
				// returns zero and GetLastError returns ERROR_PIPE_CONNECTED then it's OK to 
				// process the message.
				DWORD dwStartTickCount = GetTickCount();
				while( !IsReady )
				{
					IsReady = ConnectNamedPipe(hReadWritePipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
					if( IsReady )
						break;

					Sleep(10);
					if(GetTickCount()-dwStartTickCount > 1000)
						break;
				}

				//wsprintf(mssg,_T("ConnectNamedPipe status: %d."), GetLastError() );
				//SvcReportEvent(mssg);

				//if(!IsReady)					SvcReportEvent(TEXT("The service setup of the pipe did not work.")); 
			}

			if(IsReady)
			{
				DWORD  dwThreadId = 0; 
				HANDLE hThread = NULL;

				//wsprintf(mssg,_T("Open SUCCESS. Attempting to read pipe. Name: %s"), lpszArgv[1] );
				//SvcReportEvent(mssg);

				ThreadArgs.hReadWritePipe = hReadWritePipe;

				// Create a thread for this client request
				hThread = CreateThread( 
					NULL,              // no security attribute 
					0,                 // default stack size 
					InstanceThread,    // thread proc
					(LPVOID) &ThreadArgs,//  hReadWritePipe,    // thread parameter 
					0,                 // not suspended 
					&dwThreadId);      // returns thread ID 

				if(hThread == NULL) 
				{
					wsprintf(mssg,TEXT("CreateThread failed, GLE=%d."), GetLastError());
					SvcReportEvent(mssg);
				}
				else
				{
					CloseHandle(hThread);
					hReadWritePipe = INVALID_HANDLE_VALUE;
				}
			}
			/*
			else
			{
				if (hReadWritePipe != INVALID_HANDLE_VALUE)
				{
					CloseHandle(hReadWritePipe); 
					hReadWritePipe = INVALID_HANDLE_VALUE;
				}
			}
			*/

			//SvcReportEvent(_T("Looking for the service stop event"));

			// close the service
			//wsprintf(mssg,_T("bQuitSent: %d"), bQuitSent );
			//SvcReportEvent(mssg);

			if( bQuitSent )
			{
				SvcReportEvent(_T("Detected the QUIT sent"));
				break;
			}

			if( WAIT_OBJECT_0 == WaitForSingleObject(ThreadArgs.QuitEvent, 200) )
			{
				SvcReportEvent(_T("Detected the QUIT EVENT"));
				bQuitSent = TRUE;
				break;
			}

			if( WAIT_OBJECT_0 == WaitForSingleObject(ghSvcStopEvent, 200 )) //INFINITE) )
			{
			ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
			SvcReportEvent(_T("Reporting SERVICE_STOPPED, NO_ERROR"));
			SvcReportEvent(_T("Detected the service stop event - ghSvcStopEvent"));
			break;
			}

			ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );
			//SvcReportEvent(_T("Reporting SERVICE_RUNNING, NO_ERROR"));

			// reset the pipe ready
			IsReady = FALSE;
		} // while(1)
	}
	else 
	{	
		wsprintf(mssg,_T("Wrong arg count: %d. Service Name: %s"), dwArgc, lpszArgv[0] );
		SvcReportEvent(mssg);
	}

	if (hReadWritePipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hReadWritePipe); 
		hReadWritePipe = INVALID_HANDLE_VALUE;
	}

	if( bQuitSent)
	{
		ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
		SvcReportEvent(_T("QUIT EVENT - Reporting SERVICE_STOPPED, NO_ERROR"));
	}
	else
	{
		//////////////////////////////////////////////////
		// the work loop has ended for some reason - probably the QUIT command sent or an error
		while(1)
		{
			// Check whether to stop the service.
			SvcReportEvent(_T("OUT OF WORK LOOP, WAITING FOREVER FOR SERVICE TO BE STOPPED"));

			if (hReadWritePipe != INVALID_HANDLE_VALUE)
				CloseHandle(hReadWritePipe); 

			WaitForSingleObject(ghSvcStopEvent, INFINITE);

			ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );

			SvcReportEvent(_T("Reporting SERVICE_STOPPED, NO_ERROR"));

			break;
		}
	}

	return;
}

BOOL ProcessCommand( TCHAR * chBuf )
{
	return TRUE;

	// This code will create a registry key value or remove it.
	// The idea is that the service runs under system so any registry value can be changed by the SYSTEM user
	// unlike a program run by a user that may or may not have permisssion to write and delete values for that key.
	// If a command and argument was recieved
	// argv[0] - the program path
	// argv[1] - command
	// argv[2] - registry key - HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS
	// argv[3] - registry sub key path
	// argv[4] - value name
	// argv[5] - value type
	// argv[6] - value
	/*
	if( dwArgc == 7 ) 
	{
	if( lstrcmpi( lpszArgv[1], TEXT("c")) == 0 || lstrcmpi( lpszArgv[1], TEXT("create")) == 0 )
	{
	// try to write a value to the registry key provided
	// try to delete the key value
	try {
	DWORD dwType = GetRegValType(lpszArgv[5]);
	DWORD size = 0;
	const byte * data = GetRegData(dwType, lpszArgv[6], &size);
	if( dwType && data && size )
	{
	HKEY hSubKey = GetRegSubKey(lpszArgv[2],lpszArgv[3]);
	if( hSubKey )
	{
	DWORD rv = RegSetValueEx( hSubKey, lpszArgv[4], 0, REG_DWORD, data, size);
	RegCloseKey(hSubKey);	
	}
	}
	} catch( ... )
	{
	}
	}
	}
	else if( dwArgc == 5 )
	{
	if( lstrcmpi( lpszArgv[1], TEXT("d")) == 0 || lstrcmpi( lpszArgv[1], TEXT("delete")) == 0 )
	{
	// try to delete the key value
	try {
	HKEY hSubKey = GetRegSubKey(lpszArgv[2],lpszArgv[3]);
	if( hSubKey )
	{
	DWORD rv = RegDeleteValue( hSubKey, lpszArgv[4]);
	RegCloseKey(hSubKey);	
	}
	} catch( ... )
	{
	}
	}
	}

	return TRUE;

	*/
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
	HKEY hKey = GetRegistrationKey(keyname);
	if( hKey )
	{
		DWORD rv = RegOpenKeyExW( hKey, subkeyname,0, KEY_WRITE, &hSubKey);
	}
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

byte* GetRegData(DWORD RegValueType, LPTSTR value, DWORD * size)
{
	byte * ptr = NULL;
	size = 0;

	switch(RegValueType)
	{
	case REG_SZ:
		ptr = (byte *)value;
		*size = (DWORD) lstrlen(value)+1;
		break;
	case REG_DWORD:
		RegDataValue =  _wtol(value);
		ptr = (byte *)&RegDataValue;
		*size = sizeof(DWORD);
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
	TCHAR Buffer[80];

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

DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{ 
	HANDLE hHeap      = GetProcessHeap();
	TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(TCHAR));
	TCHAR* pchReply   = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(TCHAR));

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0; 
	BOOL fSuccess = FALSE;
	HANDLE hPipe  = NULL;

	// Do some extra error checking since the app will keep running even if this
	// thread fails.

	if (lpvParam == NULL)
	{
		//printf( "\nERROR - Pipe Server Failure:\n");
		//printf( "   InstanceThread got an unexpected NULL value in lpvParam.\n");
		//printf( "   InstanceThread exitting.\n");
		return (DWORD)-1;
	}

	if (pchRequest == NULL)
	{
		//printf( "\nERROR - Pipe Server Failure:\n");
		//printf( "   InstanceThread got an unexpected NULL heap allocation.\n");
		//printf( "   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		return (DWORD)-1;
	}

	if (pchReply == NULL)
	{
		//printf( "\nERROR - Pipe Server Failure:\n");
		//printf( "   InstanceThread got an unexpected NULL heap allocation.\n");
		//printf( "   InstanceThread exitting.\n");
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	// Print verbose messages. In production code, this should be for debugging only.
	//printf("InstanceThread created, receiving and processing messages.\n");

	// The thread's parameter is a handle to a pipe object instance. 

	//hPipe = (HANDLE) lpvParam;
	hPipe = ((_ThreadArgs *)lpvParam)->hReadWritePipe;
	HANDLE QuitEvent = ((_ThreadArgs *)lpvParam)->QuitEvent;

	// Loop until done reading
	while (hPipe && QuitEvent) 
	{ 
		// Read client requests from the pipe. This simplistic code only allows messages
		// up to BUFSIZE characters in length.
		fSuccess = ReadFile( 
			hPipe,        // handle to pipe 
			pchRequest,    // buffer to receive data 
			BUFSIZE*sizeof(TCHAR), // size of buffer 
			&cbBytesRead, // number of bytes read 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{   
			if (GetLastError() == ERROR_BROKEN_PIPE)
			{
				_tprintf(TEXT("InstanceThread: client disconnected.\n"), GetLastError()); 
			}
			else
			{
				_tprintf(TEXT("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError()); 
			}
			break;
		}

		// look for the quit signal
		if( 0 == lstrcmpW(_T("QUIT"), pchRequest ) )
		{
			wsprintf(mssg,_T("******* GOT THE QUIT MESSAGE: '%s'"), pchRequest );
			SvcReportEvent(mssg);
			bQuitSent = TRUE;

			SetEvent(QuitEvent);
		}

		wsprintf(mssg,_T("*** Read the client message: '%s'"), pchRequest );
		SvcReportEvent(mssg);

		// Process the incoming message.
		GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes); 

		// Write the reply to the pipe. 
		fSuccess = WriteFile( 
			hPipe,        // handle to pipe 
			pchReply,     // buffer to write from 
			cbReplyBytes, // number of bytes to write 
			&cbWritten,   // number of bytes written 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbReplyBytes != cbWritten)
		{   
			_tprintf(TEXT("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError()); 
			break;
		}
	}

	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 

	FlushFileBuffers(hPipe); 
	DisconnectNamedPipe(hPipe); 
	CloseHandle(hPipe); 

	HeapFree(hHeap, 0, pchRequest);
	HeapFree(hHeap, 0, pchReply);

	//printf("InstanceThread exitting.\n");
	return 1;
}

VOID GetAnswerToRequest( LPTSTR pchRequest, 
						LPTSTR pchReply, 
						LPDWORD pchBytes )
						// This routine is a simple function to print the client request to the console
						// and populate the reply buffer with a default data string. This is where you
						// would put the actual client request processing code that runs in the context
						// of an instance thread. Keep in mind the main thread will continue to wait for
						// and receive other client connections while the instance thread is working.
{
	_tprintf( TEXT("Client Request String:\"%s\"\n"), pchRequest );

	// Check the outgoing message to make sure it's not too long for the buffer.
	if (FAILED(StringCchCopy( pchReply, BUFSIZE, TEXT("default answer from server") )))
	{
		*pchBytes = 0;
		pchReply[0] = 0;
		//printf("StringCchCopy failed, no outgoing message.\n");
		return;
	}
	*pchBytes = (lstrlen(pchReply)+1)*sizeof(TCHAR);
}

