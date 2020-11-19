// MSEPX.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "MSEPX.h"
#include "DragDrop.h"


#define MAX_VALUE_NAME	MAX_PATH
#define MAX_MSSG		512

#define MAX_LOADSTRING 100
#define PIPE_TIMEOUT 5000

//#define MS_ESS_REG_XP _T("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Processes")
#define MS_ESS_REG_XP _T("Software\\Microsoft\\Microsoft Antimalware\\Exclusions\\Processes")

STARTUPINFO si;
SECURITY_ATTRIBUTES sa;
SECURITY_DESCRIPTOR sd;               //security information for pipes
PROCESS_INFORMATION pi;

BOOL bServiceRunning = FALSE;
BOOL bExclusionListSelectionState = TRUE;
BOOL bProcessListSelectionState = TRUE;
BOOL bDoNotShowExcludedProcesses = FALSE;

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name
HWND hMainDialog = NULL;
HWND hInitDlg = NULL;
CDragDropMgr * pDD;

// Prototype for the message processing callback for the modeless dialog showing inititialization 
BOOL CALLBACK InitDlgProc(HWND hwnd, 
						  UINT message, 
						  WPARAM wParam, 
						  LPARAM lParam);

bool CallStartService();

// The dialog procedure is just like Windows procedure, except that it returns 
// TRUE when it processes a message and FALSE when it doesn't. 
BOOL CALLBACK MainDialogProc (HWND hwnd, 
							  UINT message, 
							  WPARAM wParam, 
							  LPARAM lParam)
{
	BOOL bRV = FALSE; // return value set to command not processed

	switch (message)
	{
	case WM_INITDIALOG:
		{
			// center the dialog window
			CenterDialogInWindow( NULL, hwnd );

			HCURSOR waitcursor = LoadCursor(NULL, IDC_APPSTARTING);
			HCURSOR oldcursor = GetCursor();
			SetCursor(waitcursor);

			// Put up a "...loading registry" editor service messagebox
			hInitDlg = CreateDialogW(GetModuleHandle(NULL), 
				MAKEINTRESOURCE(IDD_INIT),hwnd, InitDlgProc);

			SetWindowText(hInitDlg, _T("Initializing MSEPX...") );
			//SetDlgItemText(hInitDlg, IDC_INIT_MSSG, _T("..."));
			CenterDialogInWindow( hwnd, hInitDlg, TRUE );

			// Put up a "loading processes..." messagebox
			SetDlgItemText(hInitDlg, IDC_INIT_MSSG, _T("Loading processes...") );

			// the lists are loaded so quickly that the message is not seen with a small delay
			Sleep(400);

			// Set the list of excluded processes (actually the executable's path and file name)
			SetExcludedList(GetDlgItem(hwnd, IDC_LIST_EXCLUDED));

			// Set the running processes list (actually the executable's path and file name)
			SetProcessList( GetDlgItem(hwnd,IDC_LIST_PROCESSES),
				GetDlgItem(hwnd,IDC_LIST_EXCLUDED),
				bDoNotShowExcludedProcesses );

			SetDlgItemText(hInitDlg, IDC_INIT_MSSG, _T("Starting registry edit service..."));

			bServiceRunning = StartRegService();

			// Display "Service loading failed - using internal registry editing.
			// User requires permission to change HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Processes"
			if( !bServiceRunning )
				MessageBox(hwnd, 
				_T("User requires permission to change \nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\\nMicrosoft Antimalware\\Exclusions\\Processes"),
				_T("Service loading failed - \nusing internal registry editing."), 
				MB_ICONERROR|MB_OK);

			// remove the initialization messages and reset the cursor icon.
			DestroyWindow(hInitDlg);

			// must be set to NULL to ensure proper message processing
			hInitDlg = NULL;

			SetCursor(oldcursor);

			// create the drag and drop object
			pDD = new CDragDropMgr();
			static DRAGDROPWND MyDragDropWindows[] = {
				//{ IDC_LIST_PROCESSES, DDW_SOURCE | DDW_TARGET},
				//{ IDC_LIST_EXCLUDED, DDW_SOURCE | DDW_TARGET },
				{ IDC_LIST_PROCESSES, DDW_SOURCE },
				{ IDC_LIST_EXCLUDED, DDW_TARGET },
				{ 0, 0 },
			};
			pDD->Install(hwnd, MyDragDropWindows);

			bRV = TRUE;
		}
		break;

	case WM_COMMAND:
		
		switch( LOWORD(wParam) )
		{
		case IDC_LIST_PROCESSES:
			if( HIWORD (wParam) == LBN_DBLCLK)
			{
				OnLbnDblclkListProcesses(hwnd);
				bRV = TRUE;
			}
			break;

		case IDC_LIST_EXCLUDED:
			if( HIWORD (wParam) == LBN_DBLCLK)
			{
				OnLbnDblclkListExcluded(hwnd);
				bRV = TRUE;
			}
			break;

		case IDM_EXIT:
			StopRegService();
			PostQuitMessage(0);
			bRV = TRUE;
			break;

		case IDM_ABOUT:
			{
				HWND HelpDialog = CreateDialogW( NULL, MAKEINTRESOURCE(IDD_ABOUTBOX), hwnd, About );
				ShowWindow(HelpDialog,SW_SHOW);
				bRV = TRUE;
			}
			break;

		case IDC_BUTTON_REFRESH:
			{
				HCURSOR waitcursor = LoadCursor(NULL, IDC_WAIT);
				HCURSOR oldcursor = GetCursor();
				SetCursor(waitcursor);

				OnBnClickedButtonRefresh(hwnd);
				bRV = TRUE;

				SetCursor(oldcursor);
			}
			break;

		case IDC_BUTTON_MSEX_RMV:
			{
				HCURSOR waitcursor = LoadCursor(NULL, IDC_WAIT);
				HCURSOR oldcursor = GetCursor();
				SetCursor(waitcursor);

				OnBnClickedButtonRemoveMS_Exclusion(hwnd);
				bRV = TRUE;

				SetCursor(oldcursor);
			}
			break;

		case IDC_CHECK_DONOT_SHOW_EXCLUDED:
			{
				HCURSOR waitcursor = LoadCursor(NULL, IDC_WAIT);
				HCURSOR oldcursor = GetCursor();
				SetCursor(waitcursor);

				OnBnClickedCheckDoNotShowExcluded(hwnd);
				bRV = TRUE;

				SetCursor(oldcursor);
			}
			break;

		case IDC_BUTTON_MSEX:
			{
				HCURSOR waitcursor = LoadCursor(NULL, IDC_WAIT);
				HCURSOR oldcursor = GetCursor();
				SetCursor(waitcursor);

				OnBnClickedButtonAddMS_Exclusion(hwnd);
				bRV = TRUE;

				SetCursor(oldcursor);
			}
			break;

		case WM_DESTROY:
			// stop the registry before quiting the dialog otherwise it will still run 
			// and use resources
			StopRegService();

			delete pDD;

			PostQuitMessage(0);
			bRV = TRUE;
			break;

		case WM_CLOSE:
			DestroyWindow (hwnd);
			bRV = TRUE;
			break;
		}
		break;

	case WM_DD_DRAGENTER: 
		bRV = TRUE;
		OnDragEnter( wParam,  lParam);
		break;

	case WM_DD_DRAGDROP:
		OnDragDrop( wParam,  lParam);
		bRV = TRUE;
		break;

	case WM_DD_DRAGABORT:
		OnDragAbort( wParam,  lParam);
		bRV = TRUE;
		break;

	}

	return bRV;
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
					   HINSTANCE hPrevInstance,
					   LPTSTR    lpCmdLine,
					   int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	MSG msg;
	HACCEL hAccelTable = NULL;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_MSEPX, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MSEPX));

	// Main dialog 
	hMainDialog = CreateDialog (hInst, 
		MAKEINTRESOURCE (IDD_DLG_MAIN), 
		0, 
		MainDialogProc);

	// Main message loop:
	// Note the changes that allow the accelerators in the dialog to work 
	// like it is the main window
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if( !IsWindow(hInitDlg) || !IsDialogMessage(hInitDlg, &msg))
		{
			if (!TranslateAccelerator(hMainDialog, hAccelTable, &msg))
			//if (!IsDialogMessage(hMainDialog, & msg))
			{
				if( !pDD->PreTranslateMessage(&msg) )
				{
					if (!IsDialogMessage(hMainDialog, & msg))
					//if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
					{
							TranslateMessage(&msg);
							DispatchMessage(&msg);
					}
				}
			}
		}
	}

	return (int) msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MSEPX));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_MSEPX);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	return TRUE;

	HWND hWnd;

	hInst = hInstance; // Store instance handle in our global variable

	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

	if (!hWnd)
	{
		return FALSE;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code here...
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

// start the windows service that will change the registry for the user
BOOL StartRegService()
{
	BOOL bRV = FALSE;

	bRV = CallStartService();
	if( !bRV )
	{
		if (IsWinNT())        //initialize security descriptor (Windows NT)
		{
			InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&sd, true, NULL, false);
			sa.lpSecurityDescriptor = &sd;
		}
		else
		{
			sa.lpSecurityDescriptor = NULL;
			sa.nLength = sizeof(SECURITY_ATTRIBUTES);
			sa.bInheritHandle = true;         //allow inheritable handles
		}

		/*
		The dwFlags member tells CreateProcess how to make the process.
		STARTF_USESTDHANDLES validates the hStd* members. STARTF_USESHOWWINDOW
		validates the wShowWindow member.
		*/
		//GetStartupInfo(&si);      //set startupinfo for the spawned process
		ZeroMemory( &si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory( &pi, sizeof(pi));

		//WCHAR app_spawn[] = _T("D:\\My Documents\\Visual Studio 2008\\Projects\\MSEPX\\Debug\\MSEPXSVC.exe install");
	#if(_DEBUG)
		WCHAR app_spawn[] = _T("MSEPXSVC.exe install");
		//WCHAR app_spawn[] = _T("..\\debug\\MSEPXSVC.exe install");
	#else
		//WCHAR app_spawn[] = _T(".\\MSEPXSVC.exe install");
		WCHAR app_spawn[] = _T("MSEPXSVC.exe install");
	#endif

		WCHAR curr_dir[MAX_DIR_LEN+1];
		GetCurrentDirectory(MAX_DIR_LEN, curr_dir);

		// Install the service
		if ( 
			/*		CreateProcessWithLogonW(
			_T("administrator"),
			_T("P4253NWDT2GB"),
			_T("w2wd"),
			0,

			NULL,				// application - If the executable module is a 16-bit application, lpApplicationName should be NULL
			app_spawn,			// arguments
			NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, // DWORD dwCreationFlags
			NULL,				// optional - LPVOID lpEnvironment
			curr_dir,				// optional - LPCTSTR lpCurrentDirectory
			&si,				// LPSTARTUPINFO lpStartupInfo
			&pi					// LPPROCESS_INFORMATION lpProcessInformation
			)
			*/
			CreateProcess(
				NULL,				// application - If the executable module is a 16-bit application, lpApplicationName should be NULL
				app_spawn,			// arguments
				NULL,				// optional - LPSECURITY_ATTRIBUTES lpProcessAttributes
				NULL,				// optional - LPSECURITY_ATTRIBUTES lpThreadAttributes
				TRUE,				// BOOL bInheritHandles
				NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, // DWORD dwCreationFlags
				NULL,				// optional - LPVOID lpEnvironment
				curr_dir,				// optional - LPCTSTR lpCurrentDirectory
				&si,				// LPSTARTUPINFO lpStartupInfo
				&pi					// LPPROCESS_INFORMATION lpProcessInformation
				)
			)
		{
			// wait for the service to self install - this must be done or starting the service does not work
			//Sleep(4000);
			 DWORD dw = WaitForSingleObject(pi.hProcess, 4000); //INFINITE);

			 bRV = CallStartService();
		}
		else 
		{	
			ErrorMessage(_T("Create Process"));
		}
	}

	return bRV;
}

bool CallStartService()
{
	bool bRV = FALSE;

	// This sends arguments to the service SvcMain function which 
	// is designed to loop until the service is closed
	LPCWSTR args[1] = {PIPE_NAME};
	if( ERROR_SUCCESS == DoStartSvc( SVCNAME, 1, args ) )
	{
		// wait for the service to start - this usually takes about 5 seconds or so
		Sleep(10000);

		// run a test to see if the service is going
		if( ERROR_SUCCESS == DoQuerySvc(SVCNAME))
			bRV = TRUE;
		else
			ErrorMessage(_T("Query Service"));
	}
	else
	{
		ErrorMessage(_T("Start Service"));
	}

	return bRV;
}

void SetProcessList(HWND hListBox, HWND hListBoxExclusions, BOOL bFilter )
{
	HANDLE hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	PROCESSENTRY32* processInfo=new PROCESSENTRY32;
	processInfo->dwSize=sizeof(PROCESSENTRY32);

	SendMessage( hListBox, LB_RESETCONTENT, 0, 0 ); //clear the list

	wchar_t filepath[MAX_PATH] = {0};
	int iExt = 0;  // for determining the horizontal extent required for the list box 
	while(hSnapShot && Process32Next(hSnapShot,processInfo)!=FALSE)
	{
		/*
		Windows Server 2003 and Windows XP/2000:  
		The size of the PROCESS_ALL_ACCESS flag increased on Windows Server 2008 and Windows Vista. 
		If an application compiled for Windows Server 2008 and Windows Vista is run on 
		Windows Server 2003 or Windows XP/2000, the PROCESS_ALL_ACCESS flag is too large and 
		the function specifying this flag fails with ERROR_ACCESS_DENIED. 
		To avoid this problem, specify the minimum set of access rights required for the operation. 
		If PROCESS_ALL_ACCESS must be used, set _WIN32_WINNT to the minimum operating system 
		targeted by your application (for example, 
		#define _WIN32_WINNT _WIN32_WINNT_WINXP).
		*/

		//PROCESS_ALL_ACCESS works in the debugger but not when run by the user because
		// the Visual environment runs the process as SYSTEM and not as the user. We could gain complete
		// control of any process by hacking the permission of the process like this program
		// hacks registry permissions, but instead the basic query and read permissions are used which will work for any user.

		//DWORD RequiredAccess = PROCESS_ALL_ACCESS;
		DWORD RequiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

		// Get a process handle
		HANDLE hProcess=OpenProcess( RequiredAccess, TRUE, processInfo->th32ProcessID);
		if( hProcess )
		{
			// The PSAPI.LIB (Process Status API) library is required for GetModuleFileNameEx
			// or load PSAPI.DLL dynamically
			GetModuleFileNameEx(hProcess, NULL, filepath, MAX_PATH );
			if( *filepath )
			{
				// Some of the file paths start with 
				// \??\ (like csrs.exe and winlogon) or \SystemRoot\ (like smss.exe)
				// so trim or translate the value
				if( !_tcsncmp(filepath, _T("\\??\\"), 4 ) )
				{
					wchar_t *s = filepath+4;
					wchar_t *t = filepath;
					while( *s ) *t++ = *s++;
					++*t = _T('\0');
				}
				else if( !_tcsnicmp(filepath, _T("\\systemroot\\"), 12 ) )
				{
					wchar_t rootpath[MAX_PATH] = {0};
					char * root = new char[MAX_PATH];
					size_t sz = MAX_PATH;
					_dupenv_s(&root, &sz,"systemroot");
					if(*root)
					{
						MultiByteToWideChar(CP_ACP,MB_COMPOSITE,
							root, strlen(root), 
							rootpath, sizeof(rootpath));
						wchar_t path[MAX_PATH] = {0};
						wcscpy_s(path,MAX_PATH,rootpath );
						wcscat_s(path,MAX_PATH,filepath+11 );
						wcscpy_s(filepath,MAX_PATH,path );
					}
					delete root;
				}
				// if filtering existing entries in the MSE process exclusion list
				BOOL bSkip = FALSE;
				if( bFilter )
				{
					// See if the path is already in the exclusion list
					// A -1 (LB_ERR) return from FindStringExact means it is not found
					bSkip = ( LB_ERR != SendMessage(hListBoxExclusions, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)(LPCSTR) filepath ) );
				}

				// Do not add duplicates like the service process
				if( !bSkip && ( LB_ERR == SendMessage(hListBox, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)(LPCSTR) filepath )) )
				{
					SendMessageW(hListBox, LB_ADDSTRING, -1, (LPARAM)(LPCSTR)filepath);
					int ilen = GetTextLen( hMainDialog, filepath);
					if( iExt < ilen ) 
						iExt = ilen;
				}
			}
			CloseHandle( hProcess );
		}
	}

	CloseHandle(hSnapShot);
	delete processInfo;

	// Reset the horizontal extent of the list box
	SendMessage(hListBox, LB_SETHORIZONTALEXTENT, iExt, 0);
}

// Set the list of excluded processes
void SetExcludedList(HWND hListBox )
{
	int iExt = 0;  // for determining the horizontal extent required for the list box 
	//TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	//DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys=0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	_FILETIME ftLastWriteTime;      // last write time 
	DWORD i, retCode; 
	TCHAR  achValue[MAX_VALUE_NAME]; 
	DWORD cchValue = MAX_VALUE_NAME; 

	SendMessage(hListBox, LB_RESETCONTENT, 0, 0 );

	// Read the path entries
	HKEY hKey;
	if( ERROR_SUCCESS == RegOpenKeyExW( HKEY_LOCAL_MACHINE, MS_ESS_REG_XP,0, KEY_READ, &hKey) )
	{
		// Get the class name and the value count. 
		retCode = RegQueryInfoKey(
			hKey,                    // key handle 
			achClass,                // buffer for class name 
			&cchClassName,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			&cbMaxSubKey,            // longest subkey size 
			&cchMaxClass,            // longest class string 
			&cValues,                // number of values for this key 
			&cchMaxValue,            // longest value name 
			&cbMaxValueData,         // longest value data 
			&cbSecurityDescriptor,   // security descriptor 
			&ftLastWriteTime);       // last write time 

		// Enumerate the subkeys, until RegEnumKeyEx fails.

		// There are no subkeys just values so this code is not required
		/*
		if (cSubKeys)
		{
		//printf( "\nNumber of subkeys: %d\n", cSubKeys);

		for (i=0; i<cSubKeys; i++) 
		{ 
		cbName = MAX_KEY_LENGTH;
		retCode = RegEnumKeyEx(hKey, i,
		achKey, 
		&cbName, 
		NULL, 
		NULL, 
		NULL, 
		&ftLastWriteTime); 
		if (retCode == ERROR_SUCCESS) 
		{
		_tprintf(TEXT("(%d) %s\n"), i+1, achKey);
		}
		}
		}
		*/

		// Enumerate the key values. 
		if (cValues) 
		{
			//printf( "\nNumber of values: %d\n", cValues);

			for(i=0, retCode = ERROR_SUCCESS ; retCode == ERROR_SUCCESS && i < cValues; i++) 
			{ 
				cchValue = MAX_VALUE_NAME; 
				achValue[0] = '\0'; 
				retCode = RegEnumValue(hKey, i, 
					achValue, 
					&cchValue, 
					NULL, 
					NULL,
					NULL,
					NULL);

				if (retCode == ERROR_SUCCESS ) 
				{ 
					SendMessage(hListBox, LB_ADDSTRING, -1, (LPARAM)(LPCSTR)achValue);
					int ilen = GetTextLen(hMainDialog,achValue);
					if( iExt < ilen ) iExt = ilen;
				} 
			}
		}
	} 
	// Reset the horizontal extent of the list box
	SendMessage(hListBox, LB_SETHORIZONTALEXTENT, iExt, 0);
}

// Add the selected process paths from the registry and the exclusions list
void OnBnClickedButtonAddMS_Exclusion( HWND hMainDialog )
{
	HWND hProcList = GetDlgItem(hMainDialog, IDC_LIST_PROCESSES);
	HWND hExcList = GetDlgItem(hMainDialog, IDC_LIST_EXCLUDED);
	int *aryListBoxSel = NULL;

	// Get the indexes of all the selected items.
	int nCount = SendMessage(hProcList, LB_GETSELCOUNT, 0, 0 );
	if( LB_ERR != nCount )
	{
		aryListBoxSel = new int[nCount];
		SendMessage( hProcList, LB_GETSELITEMS, nCount, (LPARAM)aryListBoxSel );
		wchar_t filepath[MAX_PATH] = {0};
		for( int i = 0; i < nCount; i++ )
		{
			int idx = aryListBoxSel[i];
			// avoid a buffer overflow even if it means dropping values
			ASSERT( SendMessage(hProcList, LB_GETTEXTLEN, idx, 0 ) < MAX_PATH );
			if( SendMessage(hProcList, LB_GETTEXTLEN, idx, 0 ) < MAX_PATH )
			{
				SendMessage(hProcList, LB_GETTEXT, idx, (LPARAM)filepath );
				// make sure this is not adding a duplicate to the exclusions
				int iExists = SendMessage(hExcList, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)(LPCSTR) filepath );
				if( iExists < 0 )
				{
					// Update the Registry by adding an exclusion on the selected process
					// use the service if it is running
					DWORD rv = -1;
					if( bServiceRunning )
					{
						rv = AddExToRegUsingService(filepath);
					}
					else
					{
						rv = AddExclusionToRegistry(filepath);
					}
					if( ERROR_SUCCESS == rv )
					{
						// add the string
						SendMessage(hExcList, LB_ADDSTRING, -1, (LPARAM)(LPCSTR)filepath);
					}
				}
			}
		}
	}

	// if the processes shown are to be filtered by those already selected
	// then remove the selections
	if( bDoNotShowExcludedProcesses )
	{
		for( int i = nCount-1; i >= 0; i-- )
		{
			SendMessage( hProcList, LB_DELETESTRING, aryListBoxSel[i], 0);
		}
	}

	if( aryListBoxSel )
		delete aryListBoxSel;

	// clear the process selections
	SendMessage( hProcList, LB_SETSEL, FALSE, -1);
	return;
}

// Remove the selected process paths from the registry and the exclusions list
void OnBnClickedButtonRemoveMS_Exclusion( HWND hMainDialog)
{
	HWND hExcList = GetDlgItem(hMainDialog, IDC_LIST_EXCLUDED);

	// Get the indexes of all the selected items.
	int nCount = SendMessage(hExcList, LB_GETSELCOUNT, 0, 0);
	if( LB_ERR != nCount )
	{
		int* aryListBoxSel = new int[nCount];
		SendMessage(hExcList, LB_GETSELITEMS, nCount, (LPARAM) aryListBoxSel);
		wchar_t filepath[MAX_PATH] = {0};
		DWORD rv = -1;
		// The program can't remove an entry in without resetting the index. So, because
		// the index changes after each deletion only the first will be 
		// removed correctly if removed in ascending inex order. 
		// The solution is to remove listbox items starting with the highest index number.
		// This assumes the listbox GetSelItems function always returns the selected values in
		// index order and not a random or selected order.
		for( int i = nCount-1; i >= 0; i-- )
		{
			// Avoid several calls to the array
			int idx = aryListBoxSel[i];
			// avoid a buffer overflow even if it means dropping values
			ASSERT( SendMessage(hExcList, LB_GETTEXTLEN, idx, 0 ) < MAX_PATH );
			if( SendMessage(hExcList, LB_GETTEXTLEN, idx, 0 ) < MAX_PATH )
			{
				*filepath = 0;
				SendMessage(hExcList, LB_GETTEXT, idx, (LPARAM) filepath );
				// Update the Registry by removing the exclusion on the selected process
				if( bServiceRunning )
				{
					rv = RemoveExFromRegUsingService(filepath);
				}
				else
				{
					rv = RemoveExclusionFromRegistry(filepath);
				}
				if( ERROR_SUCCESS == rv )
				{
					// remove the string
					SendMessage(hExcList, LB_DELETESTRING, idx, 0 );
				}
				else
					break;
			}
		}
		delete aryListBoxSel;
	}

	// clear the process selections if any left after an error
	SendMessage(hExcList, LB_SETSEL, false, -1 );

	// Reset the running processes list to include the now removed processes
	// if they are running and if bDoNotShowExcludedProcesses is set
	if( bDoNotShowExcludedProcesses )
		SetProcessList( GetDlgItem(hMainDialog,IDC_LIST_PROCESSES),
		GetDlgItem(hMainDialog,IDC_LIST_EXCLUDED),
		bDoNotShowExcludedProcesses );
	return;
}

// Calculate the required width in pixels to reset the CListbox with
// pListBox->SetHorizontalExtent(iExt). This overcomes the bug of not 
// automatically recalculating the required size

int GetTextLen(HWND hMainDialog, LPCTSTR lpszText)
{
	SIZE size;
	size.cx = 0;
	size.cy = 0;

	HDC hDC = GetDC(hMainDialog);
	ASSERT(hDC);

	if( hDC )
	{
		GetTextExtentPoint32(hDC, lpszText, (int) _tcslen(lpszText), &size );
		size.cx += 3;
		ReleaseDC(hMainDialog, hDC);
	}

	return size.cx;
}


// Switch to change running process display
void OnBnClickedCheckDoNotShowExcluded(HWND hMainDialog)
{
	// Toggle the show settings
	// if an accelerator was used the check is not set so use the last state
	if( bDoNotShowExcludedProcesses )
	{
		bDoNotShowExcludedProcesses = FALSE;
		CheckDlgButton( hMainDialog, IDC_CHECK_DONOT_SHOW_EXCLUDED, BST_UNCHECKED );
	}
	else
	{
		bDoNotShowExcludedProcesses = TRUE;
		CheckDlgButton( hMainDialog, IDC_CHECK_DONOT_SHOW_EXCLUDED, BST_CHECKED );
	}

	/*
	if( IsDlgButtonChecked(hMainDialog, IDC_CHECK_DONOT_SHOW_EXCLUDED ))
	{
		bDoNotShowExcludedProcesses = TRUE;
	else
		bDoNotShowExcludedProcesses = FALSE;
	*/

	// Reset the running processes list
	SetProcessList( GetDlgItem(hMainDialog,IDC_LIST_PROCESSES),
		GetDlgItem(hMainDialog,IDC_LIST_EXCLUDED),
		bDoNotShowExcludedProcesses );
}

// Refresh the running processes so to include those started after this program began
// and the eclusions changed through MSE itself or manual edits.
// It may be a good idea to create a timer event in the message loop to call this every 
// thirty seconds or so. 
// Looks like adding a setup dialog and save code may be needed.
void OnBnClickedButtonRefresh(HWND hMainDialog)
{
	// refresh the lists in case processes were added or edits made to MSE exclusions

	// read the registry value entries in 
	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Processes
	SetExcludedList(GetDlgItem(hMainDialog, IDC_LIST_EXCLUDED));
	// Set the running processes list
	SetProcessList( GetDlgItem(hMainDialog,IDC_LIST_PROCESSES),
		GetDlgItem(hMainDialog,IDC_LIST_EXCLUDED),
		bDoNotShowExcludedProcesses );
}

void OnLbnDblclkListProcesses(HWND hMainDialog)
{
	// Select or deselect everything based on the last state
	HWND lb = GetDlgItem(hMainDialog, IDC_LIST_PROCESSES);
	SendMessage( lb, LB_SETSEL, bProcessListSelectionState, -1);
	bProcessListSelectionState = !bProcessListSelectionState;
}

// handle double click 
void OnLbnDblclkListExcluded(HWND hMainDialog)
{
	// Select or deselect everything based on the last state
	HWND lb = GetDlgItem(hMainDialog, IDC_LIST_EXCLUDED);
	SendMessage( lb, LB_SETSEL, bExclusionListSelectionState, -1);
	bExclusionListSelectionState = !bExclusionListSelectionState;
}

// like is says
bool IsWinNT()  //check if we're running NT
{
	OSVERSIONINFO osv;
	osv.dwOSVersionInfoSize = sizeof(osv);
	GetVersionEx(&osv);
	return (osv.dwPlatformId == VER_PLATFORM_WIN32_NT);
}

// like is says
void ErrorMessage(LPTSTR str)  //display detailed error info
{
	LPVOID msg;
	DWORD err = GetLastError();
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &msg,
		0,
		NULL
		);
	//MessageBox( hMainDialog, sprintf("%s: %s\n",str,msg),_T("Error"), MB_ICONERROR|MB_OK);
	LocalFree(msg);
}

// like is says
void CenterDialogInWindow( HWND hWindow, HWND hDialog, BOOL Show )
{
	RECT WinRect;
	RECT DlgRect;
	int x,y,width,height;

	if( !hWindow)
		hWindow = GetDesktopWindow();
	GetWindowRect( hDialog, &DlgRect );

	assert( hDialog && hWindow );

	if( hDialog && hWindow )
	{
		GetWindowRect( hWindow, &WinRect );
		GetWindowRect( hDialog, &DlgRect );

		// all rectangle values are relative to the system window top left of 0,0

		// dialogs are top,left to bottom,right 
		// the system window always starts at 0,0
		// newly created dialogs and windows also begin at 0,0  

		width = DlgRect.right-DlgRect.left;
		height = DlgRect.bottom-DlgRect.top;
		
		// get the parent center point
		int parent_center_x = WinRect.left+((WinRect.right-WinRect.left)/2);
		int parent_center_y = WinRect.top+((WinRect.bottom-WinRect.top)/2);

		// now offset the centre point to the new top left start point of the dialog 
		x = parent_center_x - (width/2);
		y = parent_center_y - (height/2);

		assert(width > 0 && height > 0 && x > 0 && y > 0 );

		// now the dialog's right and bottom values distances from the parent center 
		// should be exactly equal to the dialog's left and top values distances 
		// from the parent center

		// do not move the dialog if it has unusable results which can happen if the dialog is 
		// bigger than the parent window
		if(width > 0 && height > 0 && x > 0 && y > 0 )
			MoveWindow(hDialog, x, y, width, height, TRUE);

		if( Show)
			ShowWindow(hDialog, SW_SHOW);
	}

	return;
}

// Stop and remove the service completely
void StopRegService()
{
	if( bServiceRunning )
	{
		DoStopSvc(SVCNAME);
		//DoDeleteSvc(SVCNAME); // do not call this in Windows 7 or Vista
		bServiceRunning = FALSE;
	}
}

// Add a process exclusion to the Registry
// This is the built in version used if the registry editor service fails to load and run
DWORD AddExclusionToRegistry(LPCTSTR filepath)
{
	DWORD rv = -1;
	try {
		// set the access to allow writes

		// Add the path entries from the entries in
		// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Processes
		HKEY hKey = NULL;
		rv = RegOpenKeyExW( HKEY_LOCAL_MACHINE, MS_ESS_REG_XP, 0, KEY_WRITE, &hKey);
		if( ERROR_SUCCESS == rv && hKey	)
		{
			DWORD data = 0;
			rv = RegSetValueEx( hKey, filepath, 0, REG_DWORD, (const byte *) &data, sizeof(data));
		}

		if( hKey )
			RegCloseKey(hKey);	

		if( ERROR_SUCCESS != rv	)
		{
			throw(filepath );
		}

	} catch( LPCTSTR details ) {
		// Show an error
		LPWSTR mssg = new WCHAR[MAX_MSSG];
		StringCchCopy( mssg, MAX_MSSG, details);
		StringCchCopy( mssg, MAX_MSSG, _T("\n"));
		StringCchCopy( mssg, MAX_MSSG, _T("Failure to add a security scan exclusion to the registry") );
		CUtility::ShowRegistryError( hMainDialog, rv, mssg );
		delete mssg;
	}

	return rv;
}

// Rmove a process exclusion to the Registry
// This is the built in version used if the registry editor service fails to load and run
DWORD RemoveExclusionFromRegistry(LPCWSTR filepath)
{
	DWORD rv = -1;
	try {
		// set the access to allow deletes

		// Remove the path entries from the entries in
		// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Processes
		HKEY hKey = NULL;
		rv = RegOpenKeyExW( HKEY_LOCAL_MACHINE, MS_ESS_REG_XP,0, KEY_WRITE, &hKey);
		if( ERROR_SUCCESS ==  rv && hKey )
		{
			DWORD data = 0;
			rv = RegDeleteValue( hKey, filepath);
		}

		if( hKey )
			RegCloseKey(hKey);	

		if( ERROR_SUCCESS != rv	)
		{
			throw( filepath );
		}
	} catch( LPCWSTR details )
	{
		// show an error message
		LPWSTR mssg = new WCHAR[MAX_MSSG];
		StringCchCopy( mssg, MAX_MSSG, details);
		StringCchCopy( mssg, MAX_MSSG, _T("\n"));
		StringCchCopy( mssg, MAX_MSSG, _T("Failure to remove a security scan exclusion from the registry") );
		CUtility::ShowRegistryError( hMainDialog, rv, mssg );
		delete mssg;
	}

	return rv;
}

#define REQ_PARAM_SEP _T("^")

// Call service to add a process exclusion to the Registry using the service
DWORD AddExToRegUsingService(LPCWSTR filepath)
{
	DWORD rv = -1;
	LPWSTR lpvMessage = new WCHAR[BUFSIZE];

	*lpvMessage = ADD_COMMAND;
	*(lpvMessage+1) = 0;
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, _T("HKEY_LOCAL_MACHINE") );
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, MS_ESS_REG_XP );
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, filepath );
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, _T("REG_DWORD") );
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, _T("0") );

	rv = SendMessage2RegValSvc(lpvMessage);

	delete lpvMessage;

	return rv;
}

// Call service to remove a process exclusion from the Registry using the service
DWORD RemoveExFromRegUsingService(LPCTSTR filepath)
{
	DWORD rv = -1;
	LPWSTR lpvMessage = new WCHAR[BUFSIZE];

	*lpvMessage = DEL_COMMAND;
	*(lpvMessage+1) = 0;
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, _T("HKEY_LOCAL_MACHINE") );
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, MS_ESS_REG_XP );
	StringCchCat( lpvMessage, BUFSIZE, REQ_PARAM_SEP );

	StringCchCat( lpvMessage, BUFSIZE, filepath );

	rv = SendMessage2RegValSvc(lpvMessage);

	delete lpvMessage;

	return rv;
}

// message processing callback for the modeless dialog showing inititialization
BOOL CALLBACK InitDlgProc(HWND hwnd, 
						  UINT message, 
						  WPARAM wParam, 
						  LPARAM lParam)
{
	BOOL bRV = FALSE; // did not process the message

	switch (message) 
	{ 
	case WM_INITDIALOG: 
		SetDlgItemText(hwnd, IDC_INIT_MSSG, _T("..."));
		bRV = TRUE; 
		break;

	case WM_DESTROY:
		hInitDlg = NULL; 
		bRV = TRUE; 
		break;

	case WM_COMMAND: 
		switch (LOWORD(wParam)) 
		{ 
		case IDCANCEL: 
			DestroyWindow(hwnd); 
			bRV = TRUE; 
			break;
		}
	case WM_CTLCOLORSTATIC:
		// Set the colour of the text for our URL
		if ((HWND)lParam == GetDlgItem(hwnd, IDC_INIT_MSSG)) 
		{
			// we're about to draw the static
			// set the text colour in (HDC)lParam
			SetBkMode((HDC)wParam,TRANSPARENT);
			SetTextColor((HDC)wParam, RGB(255,25,10));
			return (BOOL)CreateSolidBrush (GetSysColor(COLOR_MENU));
		}
		break;
	} 

	return bRV;
}

//////////////////
// DRAG and DROP related code Starts
//////////////////

//////////////////
// Begin dragging: create new text data from list item under point.
//
LRESULT OnDragEnter(WPARAM wp, LPARAM lp)
{
    DRAGDROPINFO& ddi = *(DRAGDROPINFO*)lp;
	HWND hLB = GetDlgItem(hMainDialog, (int)wp);
	assert(hLB!=NULL);

	// remove any list box selections that have been made so to remind the user only the current item is being moved
	SendMessage(hLB, LB_SETSEL, FALSE, -1);

	// get index of item under point
    int item = GetLBItemUnderPt(hLB, ddi.pt);
	// if the index is out of range abort
	// this is very important, if garbage is written to the registry it will be corrupted
    if (item>=0) {
        LPWSTR text = new WCHAR[MAX_PATH];
        
		SendMessage(hLB, LB_GETTEXT, item, (LPARAM)text );
        ddi.data = new CDragDropText(text);

		delete text;

		pDD->m_bDrag = TRUE; // do drag/drop

        return TRUE; 
    }
    return FALSE; // no item under mouse: nothing to drag
}

//////////////////
// User let go of the mouse: drop data into child control.
//
LRESULT OnDragDrop(WPARAM wp, LPARAM lp)
{
    //TRACE(_T("CMSEPX_MFCDlg::OnDragDrop\n"));

	DRAGDROPINFO& ddi = *(DRAGDROPINFO*)lp;
    LPCTSTR text = (LPCTSTR)ddi.data->OnGetData();
	HWND hLB = GetDlgItem(hMainDialog, (int)wp);
    assert(hLB!=NULL);
	if( hLB )
	{
		// Get the index of an existing entry
		int iNew = 0; //GetLBItemUnderPt(plb, ddi.pt); // get current position if inserting

		// FindString() would find a substring
		// FindStringExact() finds only an exact match but is case insensitive 
		int iExists = SendMessage(hLB, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)(LPCSTR) text );
		// If the path is not already there add it
		if(iExists < 0 )
		{
			// Update the Registry by adding an exclusion on the selected process
			// as a REG_DWORD value of 0x00000000 named with the path
			DWORD rv = -2;

			if( bServiceRunning )
				rv = AddExToRegUsingService(text);
			else
				rv = AddExclusionToRegistry(text);

			if( ERROR_SUCCESS == rv )
			{
				// add the string
				iNew = SendMessage(hLB, LB_ADDSTRING, (WPARAM)-1, (LPARAM)(LPCSTR) text );
				// highlight the new path
				//plb->SetSel(iNew,TRUE);
			}
		}
	}

	// Reseet the running processes list to include the now removed processes
	// if they are running and if bDoNotShowExcludedProcesses is set
	if( bDoNotShowExcludedProcesses )
	{
		SetProcessList( GetDlgItem(hMainDialog,IDC_LIST_PROCESSES),
			GetDlgItem(hMainDialog,IDC_LIST_EXCLUDED),
			bDoNotShowExcludedProcesses );
	}
	else
	{
		// redraw the source list box to eliminate the move box artifact shadow
		RedrawWindow(ddi.hwndSource,NULL,NULL, RDW_INVALIDATE);
	}

    return 0;
}

//////////////////
// Drag aborted (for example, user pressed Esc).
//
LRESULT OnDragAbort(WPARAM wp, LPARAM lp)
{
    //TRACE(_T("CMyDlg::OnDragAbort\n"));

	// refresh the source list selection to eliminate the move box artifact shadow
	HWND hLB = GetDlgItem(hMainDialog, (int)wp);
	RECT Rect;
	GetWindowRect( hLB, &Rect );
	//RedrawWindow(hLB,&Rect,NULL, RDW_INTERNALPAINT); //repaint the listbox
	RedrawWindow(hLB,NULL,NULL, RDW_INVALIDATE);
	//SendMessage( hLB, LB_SETSEL, FALSE, -1);
    return 0;
}

//////////////////
// Helper to get the listbox item under the mouse.
// This may not be the selected item when dropping.
//
int GetLBItemUnderPt(HWND hLB, POINT pt)
{
	// get the current item count of the list box and set to index of last item
	UINT c = SendMessage(hLB, LB_GETCOUNT, 0, 0) - 1;
	// get index of item under point
	UINT item = SendMessage(hLB, LB_ITEMFROMPOINT, 0, MAKELPARAM(pt.x,pt.y));
	// if the index is out of range abort
	// this is very important, if the index is not a valid list box item index the value will return garbage
    if (item < 0 || item > c) {
		item = -1;
	}

	return item;
}

//////////////////
// DRAG and DROP related code ends
//////////////////

