#include "stdafx.h"
#include "svc.h"
#include "MSEPX.h"

DWORD ProcessServiceResult( LPWSTR ResultBuffer, DWORD & SvcRetVal, 
	DWORD szMssg, LPWSTR DetailsBuffer, DWORD szDetailsBuffer );

DWORD SendMessage2RegValSvc( LPCWSTR  lpvMessage )
{
	BOOL bRV = FALSE;
	DWORD rv = UNKNOWN_ERROR;
	DWORD cbWritten = 0;
	HANDLE hReadWritePipe = INVALID_HANDLE_VALUE;
	DWORD  cbRead = 0;
	DWORD cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(TCHAR);
	WCHAR  * ResultBuffer = new WCHAR[BUFSIZE];
	LPWSTR ErrorMessageBuffer = CUtility::GetErrorMessageBuffer();

	do
	{ 
		// create the client end of the pipe to talk to the server service
		hReadWritePipe = CreateFile(
			PIPE_NAME,   // pipe name
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE, 
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

		// Break if the pipe handle is valid or a bad error
		// Exit if an error other than ERROR_PIPE_BUSY occurs. 
		if (hReadWritePipe != INVALID_HANDLE_VALUE) 
			break; 

		rv = GetLastError();

		if( ! ( ERROR_PIPE_BUSY == rv || ERROR_FILE_NOT_FOUND == rv) )
		{
			break;
		}
		
		// All pipe instances are busy, so wait n000 milliseconds. 
		// If an instance of the pipe is available before the time-out interval elapses, 
		// the return value is nonzero.
		// If an instance of the pipe is not available before the time-out interval elapses, 
		// the return value is zero. To get extended error information, call GetLastError.

		if ( ! WaitNamedPipe(PIPE_NAME, 1000)) 
		{ 
			rv = GetLastError();
			// if the wait failed stop trying to open the pipe
			if( ! ( ERROR_PIPE_BUSY == rv || ERROR_FILE_NOT_FOUND == rv) )
				break;
		}

	} while( INVALID_HANDLE_VALUE == hReadWritePipe && (
		ERROR_PIPE_BUSY == rv || ERROR_FILE_NOT_FOUND == rv ) ); 
	// ERROR_PIPE_BUSY = 231
	// ERROR_FILE_NOT_FOUND = 2

	
	if(hReadWritePipe != INVALID_HANDLE_VALUE) 
	{
		// set the pipe up 
		// Sets the read mode and the blocking mode of the specified named pipe
		//DWORD dwMode = PIPE_READMODE_MESSAGE | PIPE_WAIT; 
		DWORD dwMode = PIPE_READMODE_MESSAGE; 
		BOOL fSuccess = SetNamedPipeHandleState( 
			hReadWritePipe,    // pipe handle 
			&dwMode,  // new pipe mode 
			NULL,     // don't set maximum bytes 
			NULL);    // don't set maximum time 

		// send a command down the pipe
		bRV = WriteFile(
			hReadWritePipe,                  // pipe handle
			lpvMessage,             // message
			cbToWrite,              // message length
			&cbWritten,             // bytes written
			NULL);                  // not overlapped

		//if( ! bRV )			ErrorMessage(_T("Write Failed"));

		// read the server response

		if( bRV )
		{
			DWORD BytesRead = 0;
			do
			{
				// Read from the pipe. 
				bRV = ReadFile( 
				hReadWritePipe,    // pipe handle 
				ResultBuffer,    // buffer to receive reply 
				BUFSIZE*sizeof(TCHAR),  // size of buffer 
				&cbRead,  // number of bytes read 
				NULL);    // not overlapped 

				if ( ! bRV && GetLastError() != ERROR_MORE_DATA ) // repeat loop if ERROR_MORE_DATA 
				{
					fSuccess = TRUE;
					break;
				}

				BytesRead += cbRead;
			} while ( ! bRV);  // repeat loop if ERROR_MORE_DATA 

			// if it all worked there should be a return value of zero (ERROR_SUCCESS)
			// from the service or an error code and possible message
			if( fSuccess )
			{
				// process the return message into a return code of DWORD and 
				// a message if the return code is not zero
				// adjust the message size to wide characters
				BytesRead /= sizeof(WCHAR);
				if( ERROR_SUCCESS != ProcessServiceResult( ResultBuffer, rv, BytesRead, 
					CUtility::GetErrorMessageBuffer(), CUtility::MaxMssgBuffSz ) )
				{
					// the service returned a value but it could not be processed
					rv = ERR_SERVICE_RETVAL;
				}
			}
			else
			{
				rv = GetLastError();
				// if no system error is availablejust use a general error reporting 
				// that this did not work
				if( 0 == rv )
					rv = ERR_SERVICE;
			}
		}
	}
	else
	{
		rv = GetLastError();
	}

	if (hReadWritePipe != INVALID_HANDLE_VALUE)
		CloseHandle(hReadWritePipe);

	delete ResultBuffer;
	delete ErrorMessageBuffer;

	return rv;
}

// A message from the registry editing service can be just a number or it could be a number
// followed by a text message to explain an error or provide another detail.
// 
#define ASPACE ' '

DWORD ProcessServiceResult( LPWSTR ResultBuffer, DWORD & SvcRetVal, 
						   DWORD szMssg, LPWSTR DetailsBuffer, DWORD szDetailsBuffer )
{
	DWORD rv = ERROR_SUCCESS; //UNKNOWN_ERROR;

	// parse the service message into a number and a possible message

	// isolate the number
	WCHAR *n = ResultBuffer;
	WCHAR *e = ResultBuffer;
	while(  *e && ASPACE != *e ) e++;
	*e = 0;
	
	SvcRetVal = _wtoi(n);
	
	// there may be a message even if the return value is zero
	n=e+1;
	// if there is a message return it
	if( (DWORD)(n-ResultBuffer) < szMssg)
		StringCchCopy(DetailsBuffer,szDetailsBuffer,n);

	return rv;
}
