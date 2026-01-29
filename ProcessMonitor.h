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
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <sstream>
#include <iomanip>

#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Constants for windows
#define IDC_PROCESS_LIST 1001
#define IDC_MODULE_LIST 1002
#define IDC_TAB_CONTROL 1003
#define IDC_KILL_BTN 1005
#define IDC_FILTER_EDIT 1007
#define IDC_SEARCH_BTN 1008
#define IDT_UI_UPDATE_TIMER 1010

// Constants for context menu
#define IDM_KILL                 2101
#define IDM_KILL_TREE            2102
#define IDM_PROPERTIES           2103
#define IDM_MODULES              2104
#define IDM_EXPORT               2105
#define IDM_COPYPID              2107
#define IDM_COPYNAME             2108
#define IDM_COPYPATH             2109

// Диалоги
#define IDD_PROPERTIES_DIALOG    3000
#define IDD_EXPORT_DIALOG        3001

// Структура для истории CPU
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

// App state structure (упрощенная)
struct AppState {
    UINT refreshInterval = 1000; // 1 секунда по умолчанию
    std::wstring filterText;
    int sortColumn = 1;
    BOOL sortAscending = TRUE;
};

// Dialog producers
INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK ExportDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

const DWORD UI_UPDATE_INTERVAL = 500;

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
void RefreshProcessList();
void RefreshListViewFromData(HWND hList, const std::vector<ProcessInfo>& processes);
void ShowProcessModules(HWND hList, DWORD pid);
void KillSelectedProcess();
void UpdateStatusBar(const wchar_t* text);
void ShowContextMenu(HWND hWnd, int x, int y);
void ShowProcessProperties(HWND hParent);
void ShowSelectedProcessModules();
void ExportProcessList();
void KillProcessTree();
int KillProcessTreeRecursive(DWORD parentPid, BOOL killParent);

// Функции для обновления в реальном времени
void StartRealTimeUpdates();
void StopRealTimeUpdates();
void CheckForDataUpdates();
void UpdateThreadProc();

// Глобальные переменные для многопоточности
extern HWND g_hMainWnd;
extern HWND g_hProcessList;
extern HWND g_hModuleList;
extern HWND g_hTabControl;
extern HWND g_hStatusBar;
extern HWND g_hFilterEdit;
extern HINSTANCE g_hInstance;
extern std::vector<ProcessInfo> g_processes;
extern std::vector<ProcessInfo> g_filteredProcesses;
extern AppState g_appState;
extern std::map<DWORD, CPUHistory> g_cpuHistory;

extern std::thread g_updateThread;
extern std::atomic<bool> g_updateThreadRunning;
extern std::atomic<bool> g_updateThreadStopRequest;
extern std::mutex g_processDataMutex;
extern std::condition_variable g_dataReadyCond;
extern bool g_newDataAvailable;
extern DWORD g_lastUpdateTick;