/// msepx.h

#pragma once

#include "stdafx.h"
#include "resource.h"
#include "Utility.h"
#include <Tlhelp32.h>
#include <Psapi.h>
#include "common.h"

#define PIPE_NAME	TEXT("\\\\.\\pipe\\MSEPX")

BOOL CALLBACK MainDialogProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD RemoveExclusionFromRegistry(LPCWSTR filepath);
DWORD AddExclusionToRegistry(LPCTSTR filepath);
DWORD AddExToRegUsingService(LPCTSTR filepath);
DWORD RemoveExFromRegUsingService(LPCTSTR filepath);
void OnLbnDblclkListExcluded(HWND hMainDialog);
void OnLbnDblclkListProcesses(HWND hMainDialog);
void OnBnClickedButtonRefresh(HWND hMainDialog);
void OnBnClickedCheckDoNotShowExcluded(HWND hMainDialog);
int GetTextLen(HWND hMainDialog, LPCTSTR lpszText);
void OnBnClickedButtonRemoveMS_Exclusion( HWND hMainDialog);
void OnBnClickedButtonAddMS_Exclusion( HWND hMainDialog );
void SetExcludedList(HWND hListBox );
void SetProcessList(HWND hListBox, HWND hListBoxExclusions, BOOL bFilter );
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
BOOL StartRegService();
bool IsWinNT();
void CenterDialogInWindow( HWND hWindow, HWND hDialog, BOOL Show=TRUE);
void ErrorMessage(LPTSTR str);
void StopRegService();

LRESULT OnDragEnter(WPARAM wp, LPARAM lp);
LRESULT OnDragDrop(WPARAM wp, LPARAM lp);
LRESULT OnDragAbort(WPARAM wp, LPARAM lp);
int GetLBItemUnderPt(HWND hLB, POINT pt);
