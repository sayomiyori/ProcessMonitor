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

#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Constants for windows
#define IDC_PROCESS_LIST 1001
#define IDC_MODULE_LIST 1002
#define IDC_TAB_CONTROL 1003
#define IDC_REFRESH_BTN 1004
#define IDC_KILL_BTN 1005
#define IDC_AUTOREFRESH_BTN 1006
#define IDC_FILTER_EDIT 1007
#define IDC_SEARCH_BTN 1008
#define IDC_SORT_COMBO 1009
#define IDT_AUTOREFRESH_TIMER 1010

// cpu using history
struct CPUHistory {
    ULONGLONG lastKernel = 0;
    ULONGLONG lastUser = 0;
    ULONGLONG lastSys = 0;
    FILETIME lastUpdate = { 0, 0 };
};

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
    ULONGLONG workingSetSize;
    ULONGLONG privateBytes;
    ULONGLONG virtualSize;
    DWORD priority;
    DWORD sessionId;
    FILETIME createTime;
    FILETIME kernelTime;
    FILETIME userTime;
    double cpuUsage;
};

// App state structure
struct AppState {
    BOOL autoRefresh;
    UINT refreshInterval;
    std::wstring filterText;
    int sortColumn;
    BOOL sortAscending;
    std::map<DWORD, CPUHistory> cpuPrevTimes;
};

// Dialog producers
INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK ExportDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

// Functions
ProcessInfo GetDetailedProcessInfo(DWORD pid);
std::wstring GetProcessCommandLine(DWORD pid);
std::wstring GetProcessIntegrityLevel(DWORD pid);
std::wstring FormatFileTime(FILETIME ft);
std::wstring FormatMemorySize(ULONGLONG bytes);
double CalculateCPUUsage(DWORD pid);
BOOL ExportToCSV(const std::wstring& filename, const std::vector<ProcessInfo>& processes);
BOOL ExportToTXT(const std::wstring& filename, const std::vector<ProcessInfo>& processes);
void CopyToClipboard(const std::wstring& text);
void SortProcessList(std::vector<ProcessInfo>& processes, int column, BOOL ascending);
void ApplyFilter(std::vector<ProcessInfo>& processes, const std::wstring& filter);
void ApplyFilterToUI();

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
void KillSelectedProcess();
void UpdateStatusBar(const wchar_t* text);
void ShowContextMenu(HWND hWnd, int x, int y);
void ShowProcessProperties(HWND hParent);
void ShowSelectedProcessModules();
void ExportProcessList();
void KillProcessTree();
int KillProcessTreeRecursive(DWORD parentPid, BOOL killParent);
void ToggleAutoRefresh();
void UpdateSorting();