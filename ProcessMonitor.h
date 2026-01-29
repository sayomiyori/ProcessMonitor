// ProcessMonitor.h - обновленная версия
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7
#endif

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
#include <shellapi.h>
#include <shlobj.h>
#include <dbghelp.h>

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
#define IDM_REFRESH              2100
#define IDM_KILL                 2101
#define IDM_KILL_TREE            2102
#define IDM_PROPERTIES           2103
#define IDM_MODULES              2104
#define IDM_EXPORT               2105
#define IDM_AUTOREFRESH          2106
#define IDM_COPYPID              2107
#define IDM_COPYNAME             2108
#define IDM_COPYPATH             2109
#define IDM_OPENFILELOCATION     2110
#define IDM_SEARCHONLINE         2111
#define IDM_CREATEDUMP           2112
#define IDM_GOTOSERVICES         2113
#define IDM_SETPRIORITY          2114
#define IDM_AFFINITY             2115
#define IDM_UACVIRTUALIZATION    2116
#define IDM_CREATENEWTASK        2117
#define IDM_RUNASADMIN           2118
#define IDM_ALWAYSONTOP          2119
#define IDM_MINIMIZEONCLOSE      2120
#define IDM_SHOWALLUSERS         2121
#define IDM_ABOUT                2122
#define IDM_EXIT                 2123

// Submenu для приоритетов
#define IDM_PRIORITY_REALTIME    2124
#define IDM_PRIORITY_HIGH        2125
#define IDM_PRIORITY_ABOVENORMAL 2126
#define IDM_PRIORITY_NORMAL      2127
#define IDM_PRIORITY_BELOWNORMAL 2128
#define IDM_PRIORITY_IDLE        2129

// Диалоги
#define IDD_PROPERTIES_DIALOG    3000
#define IDD_EXPORT_DIALOG        3001
#define IDD_RUNTASK_DIALOG       3002
#define IDD_AFFINITY_DIALOG      3003




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
    HANDLE hProcess; // Для манипуляций с процессом
    ULONGLONG peakWorkingSetSize = 0;
    ULONGLONG peakPagefileUsage = 0;
    DWORD handleCount = 0;
    DWORD gdiObjects = 0;
    DWORD userObjects = 0;
    std::wstring windowTitle;
    std::wstring depStatus;
    std::wstring aslrStatus;
    std::wstring environment;
};

// App state structure
struct AppState {
    UINT refreshInterval = 1000;
    std::wstring filterText;
    int sortColumn = 1;
    BOOL sortAscending = TRUE;
    BOOL autoRefresh = TRUE;
    BOOL alwaysOnTop = FALSE;
    BOOL showAllUsers = TRUE;
    BOOL minimizeOnClose = FALSE;

    struct {
        bool memoryAsPercent = false;
        bool diskAsPercent = false;
        bool networkAsPercent = false;
    } resourceDisplay;

    // Другие настройки
    bool efficiencyMode = false;
    bool detailedView = false;
};

// Dialog producers
INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK ExportDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK RunTaskDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AffinityDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AboutDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
// Диалоговые процедуры
INT_PTR CALLBACK RunTaskDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AffinityDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AboutDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DetailedInfoDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DebugDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

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

// Новые функции как в диспетчере задач
void OpenFileLocation();
void SearchOnline();
void CreateDumpFile();
void GoToServices();
void SetProcessPriority(DWORD priority);
void SetProcessAffinity();
void RunNewTask();
void ShowAboutDialog();
void ToggleAlwaysOnTop();
void ToggleAutoRefresh();
void ToggleShowAllUsers();
void RestartAsAdministrator();
void AnalyzeWaitChain(); // Анализ цепочки ожидания
void CreateMiniDump(DWORD pid, const std::wstring& filePath);

// Функции для обновления в реальном времени
void StartRealTimeUpdates();
void StopRealTimeUpdates();
void CheckForDataUpdates();
void UpdateThreadProc();

// Новые функции для процессов
void ToggleExpandCollapse();
void ShowResourceValuesMenu();
void SetEfficiencyMode();
void DebugProcess();
void ShowDetailedInfo();
void RestartProcess();
void SuspendProcess();
void ResumeProcess();
void AnalyzeWaitChain();

// Настройки отображения ресурсов
void SetResourceDisplayMode(int mode);
void UpdateResourceDisplay();

// Подменю ресурсов
void CreateResourceValuesSubMenu(HMENU hMenu);


BOOL CreateMiniDump(DWORD pid, const wchar_t* filePath);

// Глобальные переменные для многопоточности
extern HWND g_hMainWnd;
extern HWND g_hProcessList;
extern HWND g_hModuleList;
extern HWND g_hTabControl;
extern HWND g_hStatusBar;
extern HWND g_hFilterEdit;
extern HWND g_hMenuBar;
extern HINSTANCE g_hInstance;
extern std::vector<ProcessInfo> g_processes;
extern std::vector<ProcessInfo> g_filteredProcesses;
extern AppState g_appState;
extern std::map<DWORD, CPUHistory> g_cpuHistory;
extern std::map<DWORD, DWORD_PTR> g_processAffinity;

extern std::thread g_updateThread;
extern std::atomic<bool> g_updateThreadRunning;
extern std::atomic<bool> g_updateThreadStopRequest;
extern std::mutex g_processDataMutex;
extern std::condition_variable g_dataReadyCond;
extern bool g_newDataAvailable;
extern DWORD g_lastUpdateTick;

extern bool g_isProcessTreeExpanded;
extern bool g_efficiencyModeEnabled;