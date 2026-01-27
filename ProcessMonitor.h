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

#include <winternl.h>  // Äëÿ NT_SUCCESS è NTSTATUS
#pragma comment(lib, "ntdll.lib")


// Constants for windows
#define IDC_PROCESS_LIST 1001
#define IDC_MODULE_LIST 1002
#define IDC_TAB_CONTROL 1003
#define IDC_REFRESH_BTN 1004
#define IDC_KILL_BTN 1005
#define IDM_PROCESS_MENU 2000

// Constants for context menu
#define IDM_REFRESH     2100
#define IDM_KILL        2101
#define IDM_KILL_TREE   2102
#define IDM_PROPERTIES  2103
#define IDM_MODULES     2104
#define IDM_EXPORT      2105

//Const for dialog propert
#define IDD_PROPERTIES_DIALOG  3000
#define IDC_PROP_NAME          3001
#define IDC_PROP_PID           3002
#define IDC_PROP_PARENT_PID    3003
#define IDC_PROP_PATH          3004
#define IDC_PROP_CMD_LINE      3005
#define IDC_PROP_USER          3006
#define IDC_PROP_PRIORITY      3007
#define IDC_PROP_THREADS       3008
#define IDC_PROP_MEMORY        3009
#define IDC_PROP_CPU_USAGE     3010
#define IDC_PROP_START_TIME    3011
#define IDC_PROP_SESSION_ID    3012
#define IDC_PROP_INTEGRITY     3013
#define IDC_CLOSE_BTN          3014


// Structure for the process
struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::wstring fullPath;
    std::wstring userName;
    std::wstring commandLine;
    std::wstring integrityLvl;
    DWORD threadCount;
    SIZE_T workingSetSize;
    SIZE_T privateBytes;
    SIZE_T virtualSize;
    DWORD priority;
    DWORD sessionId;
    FILETIME createTime;
    FILETIME kernelTime;
    FILETIME userTime;
    double cpuUsage;

};

//Dialog producer
INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

//New func
ProcessInfo GetDetailedProcessInfo(DWORD pid);
std::wstring GetProcessCommandLine(DWORD pid);
std::wstring GetProcessIntegrityLevel(DWORD pid);
std::wstring FormatFileTime(FILETIME ft);
std::wstring FormatMemorySize(SIZE_T bytes);
double CalculateCPUUsage(DWORD pid, FILETIME* prevKernel, FILETIME* prevUser);



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
void ShowProcessProperties(HWND hParent);
void ShowSelectedProcessModules();
void ExportProcessList();
void KillProcessTree();
int KillProcessTreeRecursive(DWORD parentPid, int depth);