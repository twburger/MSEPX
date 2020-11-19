SetProcessList(HWND hListBox, HWND hListBoxExclusions, BOOL bFilter )
{
	HANDLE hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	PROCESSENTRY32* processInfo=new PROCESSENTRY32;
	processInfo->dwSize=sizeof(PROCESSENTRY32);

	pListBox->ResetContent(); //clear the list

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
		// the Visual environment runs the process as SYSTEM not the user. We could gain complete
		// control of any process by hacking the permission of the process like this program
		// hacks registry permissions.

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
					char root[MAX_PATH] = {0};
					char * p = getenv("systemroot");
					if(*p)
					{
						strcpy( root, p );
						MultiByteToWideChar(CP_ACP,MB_COMPOSITE,
							root, strlen(root), 
							rootpath, sizeof(rootpath));
						wchar_t path[MAX_PATH] = {0};
						_tcscpy(path,rootpath );
						_tcscat(path, filepath+11 );
						_tcscpy(filepath, path );
					}
				}
				// if filtering existing entries in the MSE process exclusion list
				BOOL bSkip = FALSE;
				if( bFilter )
				{
					// see if the path is already in the exclsion list
					// -1 return from FindStringExact means it is not found
					bSkip = ( 0 <= SendMessage(hListBoxExclusions, LB_FINDSTRINGEXACT, filepath, -1) );
				}

				// Do not add duplicates like the service process
				if( !bSkip && ( 0 > pListBox->FindStringExact(-1,filepath)) )
				{
					SendMessage(hListBox, LB_ADDSTRING, 0, filepath);
					int ilen = GetTextLen(filepath);
					if( iExt < ilen ) 
						iExt = ilen;
				}
			}
			CloseHandle( hProcess );
		}
	}

	CloseHandle(hSnapShot);
	delete processInfo;

	// Reset the horizontal extent of the list box if required
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

	pListBox->ResetContent();

	// Read the path entries from the entries in
	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Processes
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
					SendMessage(hListBox, LB_ADDSTRING, 0, achValue);
					int ilen = GetTextLen(achValue);
					if( iExt < ilen ) iExt = ilen;
				} 
			}
		}
    } 
	// Reset the horizontal extent of the list box if required
	SendMessage(hListBox, LB_SETHORIZONTALEXTENT, iExt, 0);
}

// Add the selected process paths from the registry and the exclusions list
void OnBnClickedButtonAddMS_Exclusion( HWND hMainDialog )
{
	HWND hProcList = GetDlgItem(hMainDialog, IDC_LIST_PROCESSES);
	HWND hExcList = GetDlgItem(hMainDialog, IDC_LIST_EXCLUDED);

	// Get the indexes of all the selected items.
	int nCount = SendMessage(hListBox, LB_GETCOUNT, 0, 0 );
	if( LB_ERR != nCount )
	{
		CArray<int,int> aryListBoxSel;
		aryListBoxSel.SetSize(nCount);
		ProcList->GetSelItems(nCount, aryListBoxSel.GetData());
		wchar_t filepath[MAX_PATH] = {0};
		for( int i = 0; i < nCount; i++ )
		{
			// avoid a buffer overflow even if it means dropping values
			ASSERT( SendMessage(hProcList, LB_GETTEXTLEN, aryListBoxSel[i], 0 ) < MAX_PATH );
			if( SendMessage(hProcList, LB_GETTEXTLEN, aryListBoxSel[i], 0 ) < MAX_PATH )
			{
				SendMessage(hProcList, LB_GETTEXT, aryListBoxSel[i], filepath );
				// make sure this is not adding a duplicate to the exclusions
				int iExists = SendMessage(hExcList, LB_FINDSTRINGEXACT, filepath, -1);
				if( iExists < 0 )
				{
					// Update the Registry by adding an exclusion on the selected process
					if( ERROR_SUCCESS == AddExclusionToRegistry(filepath))
					{
						// add the string
						SendMessage(hExcList, LB_ADDSTRING, filepath, 0);
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
			ProcList->DeleteString(i);
		}
	}

	// clear the process selections
	ProcList->SetSel(-1, FALSE);

	return;
}

// Remove the selected process paths from the registry and the exclusions list
void OnBnClickedButtonRemoveMS_Exclusion( HWND hMainDialog)
{
	HWND ExcList = GetDlgItem(hMainDialog, IDC_LIST_EXCLUDED);

	// Get the indexes of all the selected items.
	int nCount = SendMessage(hExcList, LB_GETSELCOUNT, filepath, 0);
	if( LB_ERR != nCount )
	{
		int* ListBoxSelections = new int[nCount];
		SendMessage(hExcList, LB_GETSELITEMS, nCount, &ListBoxSelections);
		wchar_t filepath[MAX_PATH] = {0};
		DWORD rv = -1;
		// The program can't remove an entry in without resetting the index. So, because
		// the index changes after each deletion only the first will be 
		// removed correctly if removed in ascending inex order. 
		// The solution is to remove listbox items starting with the highest index number.
		// This assumes the listbox GetSelItems function always returns the selected values in
		// index order and not a random or selected order.
		#ifdef _DEBUG
			int lastidx = nCount-1;
		#endif
		for( int i = nCount-1; i >= 0; i-- )
		{
			// Avoid several calls to the array
			int idx = aryListBoxSel[i];
			// avoid a buffer overflow even if it means dropping values
			ASSERT( SendMessage(hExcList, LB_GETTEXTLEN, idx, 0 ) < MAX_PATH );
			if( SendMessage(hExcList, LB_GETTEXTLEN, idx, 0 ) < MAX_PATH )
			{
				SendMessage(hExcList, LB_GETTEXT, idx, filepath );
				rv = RemoveExclusionFromRegistry(filepath);
				// Update the Registry by removing the exclusion on the selected process
				if( ERROR_SUCCESS == rv )
				{
				// remove the string
				#ifdef _DEBUG
					// make sure the code goes down an ordered list
					ASSERT( idx <= lastidx );
					lastidx = idx;
				#endif
				SendMessage(hExcList, LB_DELETESTRING, idx, 0 );
				}
				else
					break;
			}
		}
	}

	// clear the process selections if any left after an error
	SendMessage(hExcList, hExcList, false, -1 );

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

int GetTextLen(LPCTSTR lpszText)
{
  ASSERT(AfxIsValidString(lpszText));

  CDC *pDC = GetDC();
  ASSERT(pDC);

  CSize size;
  CFont* pOldFont = pDC->SelectObject(GetFont());
  if ((GetStyle() & LBS_USETABSTOPS) == 0)
  {
    size = pDC->GetTextExtent(lpszText, (int) _tcslen(lpszText));
    size.cx += 3;
  }
  else
  {
    // Expand tabs as well
    size = pDC->GetTabbedTextExtent(lpszText, (int)
          _tcslen(lpszText), 0, NULL);
    size.cx += 2;
  }
  pDC->SelectObject(pOldFont);
  ReleaseDC(pDC);

  return size.cx;
}


// Switch to change running process display
void OnBnClickedCheckDoNotShowExcluded()
{
	// Toggle the show settings
	 CButton* cb = (CButton*)this->GetDlgItem(IDC_CHECK_DONOT_SHOW_EXCLUDED);
	 if( BST_CHECKED == cb->GetCheck() )
		bDoNotShowExcludedProcesses = TRUE;
	 else
		bDoNotShowExcludedProcesses = FALSE;

	 // Reset the running processes list
	SetProcessList((CListBox*)this->GetDlgItem(IDC_LIST_PROCESSES),
		(CListBox*)this->GetDlgItem(IDC_LIST_EXCLUDED),
		bDoNotShowExcludedProcesses );
}

// Refresh the running processes so to include those started after this program began
void OnBnClickedButtonRefresh()
{
	// Set the running processes list
	SetProcessList((CListBox*)this->GetDlgItem(IDC_LIST_PROCESSES),
		(CListBox*)this->GetDlgItem(IDC_LIST_EXCLUDED),
		bDoNotShowExcludedProcesses );
}

void OnLbnDblclkListProcesses()
{
	// Select or deselect everything based on the last state
	CListBox* lb = (CListBox*)this->GetDlgItem(IDC_LIST_PROCESSES);
	lb->SetSel( -1, bProcessListSelectionState );
	bProcessListSelectionState = !bProcessListSelectionState;
}

void OnLbnDblclkListExcluded()
{
	// Select or deselect everything based on the last state
	CListBox* lb = (CListBox*)this->GetDlgItem(IDC_LIST_EXCLUDED);
	lb->SetSel( -1, bExclusionListSelectionState );
	bExclusionListSelectionState = !bExclusionListSelectionState;
}
