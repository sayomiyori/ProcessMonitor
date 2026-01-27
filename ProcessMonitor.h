#pragma once

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <commctrl.h>
#include <map>
#include <sddl.h>
#include <lmcons.h>
#include <algorithm>
#include <cwctype>


// Constants for windows
#define IDC_PROCESS_LIST 1001
#define IDC_MODULE_LIST 1002
#define IDC_TAB_CONTROL 1003
#define IDC_REFRESH_BTN 1004
#define IDC_KILL_BTN 1005
#define IDM_PROCESS_MENU 2000

// Structure for the process
struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::wstring fullPath;
    std::wstring userName;
    DWORD threadCount;
    SIZE_T workingSetSize;
    DWORD priority;
};

// Func
BOOL InitApplication(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
BOOL EnableDebugPrivilege();
void CreateMainWindowControls(HWND hWnd);
void ApplyListViewStyle(HWND hListView);
std::vector<ProcessInfo> GetProcessesList();
std::wstring GetProcessUserName(DWORD pid);
void RefreshProcessList(HWND hList);
void ShowProcessModules(HWND hList, DWORD pid);
void DisplayProcessDetails(DWORD pid);
void KillSelectedProcess();
void UpdateStatusBar(const wchar_t* text);
void ShowContextMenu(HWND hWnd, int x, int y);
void ShowProcessProperties(HWND hWnd);
void ShowSelectedProcessModules();
void ExportProcessList();