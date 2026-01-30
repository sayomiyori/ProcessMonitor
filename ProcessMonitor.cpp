#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <commdlg.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include "ProcessMonitor.h"
#include "Resource.h"

#define UI_UPDATE_INTERVAL 1000

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "Dbghelp.lib")

// Global variables
HWND g_hMainWnd = NULL;
HWND g_hProcessList = NULL;
HWND g_hModuleList = NULL;
HWND g_hTabControl = NULL;
HWND g_hStatusBar = NULL;
HWND g_hFilterEdit = NULL;
HWND g_hPerformanceWnd = NULL;
HINSTANCE g_hInstance;
AppState g_appState;
std::vector<ProcessInfo> g_processes;
std::vector<ProcessInfo> g_filteredProcesses;
std::map<DWORD, CPUHistory> g_cpuHistory;
HWND g_hMenuBar = NULL;
std::map<DWORD, DWORD_PTR> g_processAffinity;
bool g_isProcessTreeExpanded = false;
bool g_efficiencyModeEnabled = false;
bool g_contextMenuActive = false;


// Многопоточные переменные
std::thread g_updateThread;
std::atomic<bool> g_updateThreadRunning(false);
std::atomic<bool> g_updateThreadStopRequest(false);
std::mutex g_processDataMutex;
std::condition_variable g_dataReadyCond;
bool g_newDataAvailable = false;
DWORD g_lastUpdateTick = 0;

// Helper macros for coordinates
#define GET_X_LPARAM(lParam) ((int)(short)LOWORD(lParam))
#define GET_Y_LPARAM(lParam) ((int)(short)HIWORD(lParam))

// Минимальные размеры окна
#define MIN_WINDOW_WIDTH 800
#define MIN_WINDOW_HEIGHT 600


// Прототипы функций
void RefreshProcessList();
void UpdateStatusBar(const wchar_t* text);
void ShowProcessModules(HWND hList, DWORD pid);
void RefreshListViewFromData(HWND hList, const std::vector<ProcessInfo>& processes);
void StartRealTimeUpdates();
void StopRealTimeUpdates();
void CheckForDataUpdates();
void ShowProcessProperties(HWND hParent);
void KillSelectedProcess();
INT_PTR CALLBACK ExportDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
void ExportProcessList();
void ToggleExpandCollapse();
void SetEfficiencyMode();
void DebugProcess();
void ShowDetailedInfo();
void RestartProcess();
void SuspendProcess();
void ResumeProcess();
void AnalyzeWaitChain();
void SetResourceDisplayMode(int mode);
void ToggleAlwaysOnTop();
void ToggleAutoRefresh();
void ToggleShowAllUsers();
void OpenFileLocation();
void SearchOnline();
BOOL CreateMiniDump(DWORD pid, const wchar_t* filePath);
void SetProcessPriority(DWORD priorityClass);
void SetProcessAffinity();
void RunNewTask();
void GoToServices();
void ShowAboutDialog();
INT_PTR CALLBACK RunTaskDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AffinityDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AboutDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DebugDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DetailedInfoDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
void KillProcessTree();
void UpdateThreadProc();



LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

BOOL IsRunAsAdministrator() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup)) {
        if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
            fIsRunAsAdmin = FALSE;
        }
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}


// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsRunAsAdministrator()) {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;

            if (!ShellExecuteEx(&sei)) {
                MessageBox(NULL,
                    L"The program requires administrator rights. \nRun it as an administrator.",
                    L"Access rights error",
                    MB_OK | MB_ICONERROR);
            }
            return 0;
        }
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    if (!InitApplication(hInstance)) {
        return FALSE;
    }

    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}


// Window Class Registration
BOOL InitApplication(HINSTANCE hInstance) {
    WNDCLASSEXW wcex;
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCE(IDR_MAIN_MENU);
    wcex.lpszClassName = L"ProcessMonitorClass";
    wcex.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON_SMALL));

    return RegisterClassExW(&wcex);
}

// Creating main window
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    g_hInstance = hInstance;

    g_hMainWnd = CreateWindowW(
        L"ProcessMonitorClass",
        L"Windows Process Monitor v2.0 - Miyori Code",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, 0, 1200, 700,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hMainWnd) {
        return FALSE;
    }

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);
    return TRUE;
}

// Новая функция: Открыть расположение файла
void OpenFileLocation() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    std::wstring path(512, L'\0');
    ListView_GetItemText(g_hProcessList, selected, 6, &path[0], 512);
    path.resize(wcslen(path.c_str()));

    if (path.empty() || path == L"N/A") {
        MessageBox(g_hMainWnd, L"Cannot get file path", L"Error", MB_ICONERROR);
        return;
    }

    // Извлекаем каталог из полного пути
    size_t lastBackslash = path.find_last_of(L'\\');
    if (lastBackslash != std::wstring::npos) {
        std::wstring directory = path.substr(0, lastBackslash);

        // Открываем папку в проводнике
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_DEFAULT;
        sei.lpVerb = L"open";
        sei.lpFile = directory.c_str();
        sei.nShow = SW_SHOW;

        if (!ShellExecuteEx(&sei)) {
            MessageBox(g_hMainWnd, L"Cannot open file location", L"Error", MB_ICONERROR);
        }
    }
}


void SearchOnline() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) return;

    std::wstring name(256, L'\0');
    ListView_GetItemText(g_hProcessList, selected, 1, &name[0], 256);
    name.resize(wcslen(name.c_str()));

    // Формируем URL для поиска
    std::wstring searchUrl = L"https://www.google.com/search?q=" + name + L"+process+windows";

    ShellExecute(NULL, L"open", searchUrl.c_str(), NULL, NULL, SW_SHOW);
}

// Новая функция: Создать дамп процесса
void CreateDumpFile() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Запрос имени файла для дампа
    wchar_t szFile[MAX_PATH] = { 0 };
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Dump Files (*.dmp)\0*.dmp\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrDefExt = L"dmp";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

    if (!GetSaveFileName(&ofn)) {
        return;
    }

    CreateMiniDump(pid, szFile);
}

// Новая функция: Перейти к службам
void GoToServices() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        // Если процесс не выбран, просто открываем services.msc
        ShellExecute(NULL, L"open", L"services.msc", NULL, NULL, SW_SHOW);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Попытка найти службы, связанные с процессом
    ShellExecute(NULL, L"open", L"services.msc", NULL, NULL, SW_SHOW);

    // Можно добавить более сложную логику позже
    MessageBox(g_hMainWnd,
        L"Service association feature is under development.\nServices console opened.",
        L"Information", MB_ICONINFORMATION);
}

BOOL CreateMiniDump(DWORD pid, const wchar_t* filePath) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        MessageBox(g_hMainWnd, L"Cannot open process", L"Error", MB_ICONERROR);
        return FALSE;
    }

    HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        MessageBox(g_hMainWnd, L"Cannot create dump file", L"Error", MB_ICONERROR);
        return FALSE;
    }

    // Создаем мини-дамп
    MINIDUMP_EXCEPTION_INFORMATION mdei;
    mdei.ThreadId = GetCurrentThreadId();
    mdei.ExceptionPointers = NULL;
    mdei.ClientPointers = FALSE;

    MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules);

    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, mdt,
        NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (success) {
        MessageBox(g_hMainWnd, L"Dump file created successfully", L"Success", MB_ICONINFORMATION);
        return TRUE;
    }
    else {
        MessageBox(g_hMainWnd, L"Failed to create dump file", L"Error", MB_ICONERROR);
        return FALSE;
    }
}

// Новая функция: Установить приоритет процесса
void SetProcessPriority(DWORD priorityClass) {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) {
        MessageBox(g_hMainWnd, L"Cannot open process", L"Error", MB_ICONERROR);
        return;
    }

    if (SetPriorityClass(hProcess, priorityClass)) {
        std::wstring message = L"Process priority changed successfully";
        UpdateStatusBar(message.c_str());
        RefreshProcessList();
    }
    else {
        MessageBox(g_hMainWnd, L"Failed to change process priority", L"Error", MB_ICONERROR);
    }

    CloseHandle(hProcess);
}

// Новая функция: Установить affinity (привязку к процессорам)
void SetProcessAffinity() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Показываем диалог выбора процессоров
    DialogBoxParam(g_hInstance, MAKEINTRESOURCE(IDD_AFFINITY_DIALOG),
        g_hMainWnd, AffinityDialog, (LPARAM)pid);
}

// Новая функция: Запустить новую задачу
void RunNewTask() {
    DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_RUNTASK_DIALOG), g_hMainWnd, RunTaskDialog);
}

INT_PTR CALLBACK RunTaskDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static std::wstring filePath;
    static std::wstring arguments;
    static BOOL runAsAdmin = FALSE;

    switch (message) {
    case WM_INITDIALOG:
        filePath.clear();
        arguments.clear();
        runAsAdmin = FALSE;
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_TASK_BROWSE: {
            OPENFILENAME ofn;
            wchar_t szFile[MAX_PATH] = { 0 };

            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hDlg;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

            if (GetOpenFileName(&ofn)) {
                SetDlgItemText(hDlg, IDC_TASK_PATH, szFile);
                filePath = szFile;
            }
            return TRUE;
        }

        case IDC_TASK_RUNASADMIN:
            runAsAdmin = IsDlgButtonChecked(hDlg, IDC_TASK_RUNASADMIN);
            return TRUE;

        case IDOK: {
            wchar_t buffer[MAX_PATH];

            GetDlgItemText(hDlg, IDC_TASK_PATH, buffer, MAX_PATH);
            filePath = buffer;

            GetDlgItemText(hDlg, IDC_TASK_ARGS, buffer, MAX_PATH);
            arguments = buffer;

            if (filePath.empty()) {
                MessageBox(hDlg, L"Please select a program to run", L"Error", MB_ICONERROR);
                return TRUE;
            }

            // Запускаем программу
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = runAsAdmin ? L"runas" : NULL;
            sei.lpFile = filePath.c_str();
            sei.lpParameters = arguments.empty() ? NULL : arguments.c_str();
            sei.nShow = SW_SHOW;

            if (ShellExecuteEx(&sei)) {
                MessageBox(hDlg, L"Task started successfully", L"Success", MB_ICONINFORMATION);
                EndDialog(hDlg, IDOK);
            }
            else {
                MessageBox(hDlg, L"Failed to start task", L"Error", MB_ICONERROR);
            }
            return TRUE;
        }

        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }

    return FALSE;
}


INT_PTR CALLBACK AffinityDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static DWORD pid;
    static DWORD_PTR currentAffinity = 0;
    static DWORD_PTR systemAffinity = 0;

    switch (message) {
    case WM_INITDIALOG: {
        pid = (DWORD)lParam;

        // Получаем текущую маску affinity
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            GetProcessAffinityMask(hProcess, &currentAffinity, &systemAffinity);
            CloseHandle(hProcess);
        }

        // Устанавливаем флажки в зависимости от currentAffinity
        for (int i = 0; i < 16; i++) {
            if (systemAffinity & (1 << i)) {
                EnableWindow(GetDlgItem(hDlg, IDC_AFFINITY_CPU0 + i), TRUE);

                if (currentAffinity & (1 << i)) {
                    CheckDlgButton(hDlg, IDC_AFFINITY_CPU0 + i, BST_CHECKED);
                }
            }
            else {
                EnableWindow(GetDlgItem(hDlg, IDC_AFFINITY_CPU0 + i), FALSE);
            }
        }

        // Выбираем радиокнопку
        if (currentAffinity == systemAffinity) {
            CheckRadioButton(hDlg, IDC_AFFINITY_ALL, IDC_AFFINITY_CUSTOM, IDC_AFFINITY_ALL);
        }
        else {
            CheckRadioButton(hDlg, IDC_AFFINITY_ALL, IDC_AFFINITY_CUSTOM, IDC_AFFINITY_CUSTOM);
        }
        return TRUE;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_AFFINITY_ALL: {
            // Снимаем все флажки и блокируем их
            for (int i = 0; i < 16; i++) {
                if (IsWindowEnabled(GetDlgItem(hDlg, IDC_AFFINITY_CPU0 + i))) {
                    CheckDlgButton(hDlg, IDC_AFFINITY_CPU0 + i, BST_UNCHECKED);
                }
            }
            return TRUE;
        }

        case IDC_AFFINITY_CUSTOM: {
            // Включаем возможность выбора
            return TRUE;
        }

        case IDOK: {
            DWORD_PTR newAffinity = 0;

            if (IsDlgButtonChecked(hDlg, IDC_AFFINITY_ALL) == BST_CHECKED) {
                newAffinity = systemAffinity;
            }
            else {
                for (int i = 0; i < 16; i++) {
                    if (IsDlgButtonChecked(hDlg, IDC_AFFINITY_CPU0 + i) == BST_CHECKED) {
                        newAffinity |= (1 << i);
                    }
                }

                // Проверяем, что выбран хотя бы один процессор
                if (newAffinity == 0) {
                    MessageBox(hDlg, L"Please select at least one CPU", L"Error", MB_ICONERROR);
                    return TRUE;
                }
            }

            // Применяем новую маску affinity
            HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
            if (hProcess) {
                if (SetProcessAffinityMask(hProcess, newAffinity)) {
                    MessageBox(hDlg, L"Affinity set successfully", L"Success", MB_ICONINFORMATION);
                    EndDialog(hDlg, IDOK);
                }
                else {
                    MessageBox(hDlg, L"Failed to set affinity", L"Error", MB_ICONERROR);
                }
                CloseHandle(hProcess);
            }
            else {
                MessageBox(hDlg, L"Cannot open process", L"Error", MB_ICONERROR);
            }
            return TRUE;
        }

        case IDCANCEL: {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        }
        break;
    }
    }

    return FALSE;
}

INT_PTR CALLBACK AboutDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG:
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}


// Новая функция: Показать About диалог
void ShowAboutDialog() {
    MessageBox(g_hMainWnd,
        L"Windows Process Monitor v2.0\n\n"
        L"Publisher: Miyori Code\n"
        L"Copyright © 2024 Miyori Code\n\n"
        L"A powerful process management tool for Windows\n"
        L"with real-time monitoring capabilities.",
        L"About Process Monitor",
        MB_OK | MB_ICONINFORMATION);
}

// Новая функция: Переключить "Always on Top"
void ToggleAlwaysOnTop() {
    g_appState.alwaysOnTop = !g_appState.alwaysOnTop;

    SetWindowPos(g_hMainWnd,
        g_appState.alwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST,
        0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE);

    // Обновляем меню
    HMENU hMenu = GetMenu(g_hMainWnd);
    if (hMenu) {
        CheckMenuItem(hMenu, IDM_ALWAYSONTOP,
            MF_BYCOMMAND | (g_appState.alwaysOnTop ? MF_CHECKED : MF_UNCHECKED));
    }
}



// Process tree completion function
int KillProcessTreeRecursive(DWORD parentPid, BOOL killParent) {
    int killedCount = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Collecting a list of child processes
    std::vector<DWORD> childPids;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid && pe.th32ProcessID != parentPid) {
                childPids.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &pe));
    }

    // Recursively killing all children
    for (DWORD childPid : childPids) {
        killedCount += KillProcessTreeRecursive(childPid, TRUE);
    }

    // Killing the current process (if necessary)
    if (killParent) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, parentPid);
        if (hProcess) {
            if (TerminateProcess(hProcess, 0)) {
                killedCount++;
            }
            CloseHandle(hProcess);
        }
    }

    CloseHandle(snapshot);
    return killedCount;
}

void KillProcessTree() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process to kill the tree", L"Error", MB_ICONWARNING);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD targetPid = (DWORD)lvi.lParam;

    std::wstring procName(256, L'\0');
    ListView_GetItemText(g_hProcessList, selected, 1, &procName[0], 256);
    procName.resize(wcslen(procName.c_str()));

    std::wstring message = L"Finish the process tree for \"" + procName +
        L"\" (PID: " + std::to_wstring(targetPid) +
        L")?\n\nAll child processes will also be terminated!";

    if (MessageBox(g_hMainWnd, message.c_str(), L"Confirm",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
        int killedCount = KillProcessTreeRecursive(targetPid, TRUE);

        std::wstring status = L"Complete processes: " + std::to_wstring(killedCount);
        UpdateStatusBar(status.c_str());

        RefreshProcessList();
    }
}

// CPU usage calculation function
double CalculateCPUUsage(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return 0.0;
    }

    FILETIME createTime, exitTime, kernelTime, userTime;
    FILETIME sysIdleTime, sysKernelTime, sysUserTime;

    if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime) ||
        !GetSystemTimes(&sysIdleTime, &sysKernelTime, &sysUserTime)) {
        CloseHandle(hProcess);
        return 0.0;
    }

    CPUHistory& history = g_cpuHistory[pid];

    ULONGLONG kernel = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
    ULONGLONG user = ((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;
    ULONGLONG sys = ((ULONGLONG)sysKernelTime.dwHighDateTime << 32) | sysKernelTime.dwLowDateTime +
        ((ULONGLONG)sysUserTime.dwHighDateTime << 32) | sysUserTime.dwLowDateTime;

    double cpuUsage = 0.0;

    if (history.lastUpdate.dwLowDateTime != 0 || history.lastUpdate.dwHighDateTime != 0) {
        ULONGLONG kernelDiff = kernel - history.lastKernel;
        ULONGLONG userDiff = user - history.lastUser;
        ULONGLONG sysDiff = sys - history.lastSys;

        if (sysDiff > 0) {
            cpuUsage = ((double)(kernelDiff + userDiff) / sysDiff) * 100.0;

            if (cpuUsage > 100.0) cpuUsage = 100.0;
            if (cpuUsage < 0.0) cpuUsage = 0.0;
        }
    }

    history.lastKernel = kernel;
    history.lastUser = user;
    history.lastSys = sys;
    GetSystemTimeAsFileTime(&history.lastUpdate);

    CloseHandle(hProcess);
    return cpuUsage;
}

// CSV export function
BOOL ExportToCSV(const std::wstring& filename, const std::vector<ProcessInfo>& processes) {
    std::wofstream file(filename);
    if (!file.is_open()) {
        return FALSE;
    }

    file << L"PID,Name,User,Memory (MB),Threads,CPU Usage (%),Priority,Session ID,Path\n";

    for (const auto& proc : processes) {
        file << proc.pid << L","
            << L"\"" << proc.name << L"\","
            << L"\"" << proc.userName << L"\","
            << (proc.workingSetSize / (1024 * 1024)) << L","
            << proc.threadCount << L","
            << proc.cpuUsage << L","
            << proc.priority << L","
            << proc.sessionId << L","
            << L"\"" << proc.fullPath << L"\"\n";
    }

    file.close();
    return TRUE;
}

// Export to TXT
BOOL ExportToTXT(const std::wstring& filename, const std::vector<ProcessInfo>& processes) {
    std::wofstream file(filename);
    if (!file.is_open()) {
        return FALSE;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    file << L"Windows Process Monitor - Process List\n";
    file << L"Generated: " << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
        << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"\n";
    file << L"========================================\n\n";

    for (const auto& proc : processes) {
        file << L"Process: " << proc.name << L"\n";
        file << L"PID: " << proc.pid << L"\n";
        file << L"User: " << proc.userName << L"\n";
        file << L"Memory: " << FormatMemorySize(proc.workingSetSize) << L"\n";
        file << L"Threads: " << proc.threadCount << L"\n";
        file << L"CPU Usage: " << proc.cpuUsage << L"%\n";
        file << L"Path: " << proc.fullPath << L"\n";
        file << L"----------------------------------------\n";
    }

    file.close();
    return TRUE;
}

//Export dialog
INT_PTR CALLBACK ExportDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static int exportFormat = 0; // 0 = CSV, 1 = TXT

    switch (message)
    {
    case WM_INITDIALOG:
    {
        CheckRadioButton(hDlg, IDC_EXPORT_CSV, IDC_EXPORT_TXT, IDC_EXPORT_CSV);

        wchar_t defaultPath[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, defaultPath);
        std::wstring fullPath = std::wstring(defaultPath) + L"\\ProcessList.csv";
        SetDlgItemText(hDlg, IDC_EXPORT_PATH, fullPath.c_str());
        return TRUE;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDOK:
        {
            wchar_t path[MAX_PATH];
            GetDlgItemText(hDlg, IDC_EXPORT_PATH, path, MAX_PATH);

            exportFormat = IsDlgButtonChecked(hDlg, IDC_EXPORT_CSV) ? 0 : 1;

            BOOL success = FALSE;
            if (exportFormat == 0)
            {
                success = ExportToCSV(path, g_filteredProcesses.empty() ? g_processes : g_filteredProcesses);
            }
            else
            {
                success = ExportToTXT(path, g_filteredProcesses.empty() ? g_processes : g_filteredProcesses);
            }

            if (success)
            {
                MessageBox(hDlg, L"Export completed successfully!", L"Success", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                MessageBox(hDlg, L"Failed to export!", L"Error", MB_OK | MB_ICONERROR);
            }
            EndDialog(hDlg, 0);
            return TRUE;
        }

        case IDCANCEL:
            EndDialog(hDlg, 0);
            return TRUE;

        case IDC_EXPORT_BROWSE:
        {
            OPENFILENAME ofn;
            std::wstring szFile(MAX_PATH, L'\0');

            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hDlg;
            ofn.lpstrFile = &szFile[0];
            ofn.nMaxFile = szFile.size();
            ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.lpstrFileTitle = NULL;
            ofn.nMaxFileTitle = 0;
            ofn.lpstrInitialDir = NULL;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

            if (GetSaveFileName(&ofn)) {
                SetDlgItemText(hDlg, IDC_EXPORT_PATH, szFile.c_str());
            }
            return TRUE;
        }


        default:
            break;
        }
        break;
    }

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }

    return FALSE;
}

// CopyToClipboard func
void CopyToClipboard(const std::wstring& text) {
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (text.length() + 1) * sizeof(wchar_t));
        if (hMem) {
            wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
            wcscpy_s(pMem, text.length() + 1, text.c_str());
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
        CloseClipboard();
    }
}

// Sort func
void SortProcessList(std::vector<ProcessInfo>& processes, int column, BOOL ascending) {
    std::sort(processes.begin(), processes.end(),
        [column, ascending](const ProcessInfo& a, const ProcessInfo& b) {
            int result = 0;
            switch (column) {
            case 0: // PID
                result = (a.pid < b.pid) ? -1 : (a.pid > b.pid) ? 1 : 0;
                break;
            case 1: // Name
                result = _wcsicmp(a.name.c_str(), b.name.c_str());
                break;
            case 2: // User
                result = _wcsicmp(a.userName.c_str(), b.userName.c_str());
                break;
            case 3: // Memory
                result = (a.workingSetSize < b.workingSetSize) ? -1 :
                    (a.workingSetSize > b.workingSetSize) ? 1 : 0;
                break;
            case 4: // Threads
                result = (a.threadCount < b.threadCount) ? -1 :
                    (a.threadCount > b.threadCount) ? 1 : 0;
                break;
            case 5: // CPU Usage
                result = (a.cpuUsage < b.cpuUsage) ? -1 :
                    (a.cpuUsage > b.cpuUsage) ? 1 : 0;
                break;
            default:
                result = 0;
            }
            return ascending ? result < 0 : result > 0;
        });
}

// filter func
void ApplyFilter(std::vector<ProcessInfo>& processes, const std::wstring& filter) {
    if (filter.empty()) {
        return;
    }

    std::wstring lowerFilter = filter;
    std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::towlower);

    auto it = std::remove_if(processes.begin(), processes.end(),
        [&lowerFilter](const ProcessInfo& proc) {
            std::wstring lowerName = proc.name;
            std::wstring lowerPath = proc.fullPath;
            std::wstring lowerUser = proc.userName;

            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            std::transform(lowerUser.begin(), lowerUser.end(), lowerUser.begin(), ::towlower);

            return lowerName.find(lowerFilter) == std::wstring::npos &&
                lowerPath.find(lowerFilter) == std::wstring::npos &&
                lowerUser.find(lowerFilter) == std::wstring::npos &&
                std::to_wstring(proc.pid).find(lowerFilter) == std::wstring::npos;
        });

    processes.erase(it, processes.end());
}

// GetDetailedProcessInfo - УДАЛЕНО ДУБЛИРОВАНИЕ ОБЪЯВЛЕНИЯ pmc
ProcessInfo GetDetailedProcessInfo(DWORD pid) {
    ProcessInfo info = {};
    info.pid = pid;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
        PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }

    if (hProcess)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(snapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        info.name = pe.szExeFile;
                        info.parentPid = pe.th32ParentProcessID;
                        info.threadCount = pe.cntThreads;
                        break;
                    }
                } while (Process32NextW(snapshot, &pe));
            }
            CloseHandle(snapshot);
        }

        std::wstring path(MAX_PATH, L'\0');

        // Use GetModuleFileNameEx for getting path
        if (GetModuleFileNameEx(hProcess, NULL, &path[0], MAX_PATH)) {
            path.resize(wcslen(path.c_str()));
            info.fullPath = path;
        }
        else {
            // alt method for sys process
            path.resize(MAX_PATH);
            if (GetProcessImageFileName(hProcess, &path[0], MAX_PATH)) {
                path.resize(wcslen(path.c_str()));
                info.fullPath = path;
            }
        }

        info.commandLine = GetProcessCommandLine(pid);
        info.userName = GetProcessUserName(pid);
        info.integrityLvl = GetProcessIntegrityLevel(pid);
        info.priority = GetPriorityClass(hProcess);
        ProcessIdToSessionId(pid, &info.sessionId);
        GetProcessTimes(hProcess, &info.createTime, NULL, &info.kernelTime, &info.userTime);

        // ТОЛЬКО ОДНО ОБЪЯВЛЕНИЕ pmc
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            info.workingSetSize = pmc.WorkingSetSize;
            info.privateBytes = pmc.PrivateUsage;
            info.virtualSize = pmc.PagefileUsage;
            info.peakWorkingSetSize = pmc.PeakWorkingSetSize;
            info.peakPagefileUsage = pmc.PeakPagefileUsage;
        }

        GetProcessHandleCount(hProcess, &info.handleCount);

        info.gdiObjects = GetGuiResources(hProcess, GR_GDIOBJECTS);
        info.userObjects = GetGuiResources(hProcess, GR_GDIOBJECTS);

        info.cpuUsage = CalculateCPUUsage(pid);
        CloseHandle(hProcess);
    }

    return info;
}

// GetProcessCommandLine
std::wstring GetProcessCommandLine(DWORD pid) {
    std::wstring cmdLine = L"N/A";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return cmdLine;
    }

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    static pNtQueryInformationProcess NtQueryInformationProcess = NULL;

    if (!NtQueryInformationProcess) {
        HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
        if (hNtdll) {
            NtQueryInformationProcess = (pNtQueryInformationProcess)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }

    if (NtQueryInformationProcess) {
        PROCESS_BASIC_INFORMATION pbi;
        NTSTATUS status = NtQueryInformationProcess(hProcess,
            ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

        if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
            PEB peb;
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
                RTL_USER_PROCESS_PARAMETERS upp;

                if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) {
                    if (upp.CommandLine.Length > 0) {
                        size_t bufferSize = (upp.CommandLine.Length / sizeof(wchar_t)) + 1;
                        std::wstring buffer(bufferSize, L'\0');

                        if (ReadProcessMemory(hProcess, upp.CommandLine.Buffer,
                            &buffer[0], upp.CommandLine.Length, &bytesRead)) {
                            buffer.resize(bytesRead / sizeof(wchar_t));
                            cmdLine = buffer;
                        }
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
    return cmdLine;
}

// GetProcessIntegrityLevel
std::wstring GetProcessIntegrityLevel(DWORD pid) {
    std::wstring integrity = L"Unknown";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return integrity;
    }

    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD tokenInfoSize = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &tokenInfoSize);

        if (tokenInfoSize > 0) {
            PTOKEN_MANDATORY_LABEL ptil = (PTOKEN_MANDATORY_LABEL)malloc(tokenInfoSize);
            if (ptil && GetTokenInformation(hToken, TokenIntegrityLevel,
                ptil, tokenInfoSize, &tokenInfoSize)) {
                DWORD integrityLevel = *GetSidSubAuthority(ptil,
                    (DWORD)(*GetSidSubAuthorityCount(ptil) - 1));

                if (integrityLevel < SECURITY_MANDATORY_LOW_RID) {
                    integrity = L"Untrusted";
                }
                else if (integrityLevel >= SECURITY_MANDATORY_LOW_RID &&
                    integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
                    integrity = L"Low";
                }
                else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                    integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                    integrity = L"Medium";
                }
                else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
                    integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
                    integrity = L"High";
                }
                else if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                    integrity = L"System";
                }
            }
            free(ptil);
        }
        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return integrity;
}

// Formating time
std::wstring FormatFileTime(FILETIME ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
        return L"N/A";
    }

    FILETIME localFt;
    FileTimeToLocalFileTime(&ft, &localFt);

    SYSTEMTIME st;
    FileTimeToSystemTime(&localFt, &st);

    std::wstringstream ss;
    ss << std::setw(4) << std::setfill(L'0') << st.wYear << L"-"
        << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-"
        << std::setw(2) << std::setfill(L'0') << st.wDay << L" "
        << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
        << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
        << std::setw(2) << std::setfill(L'0') << st.wSecond;

    return ss.str();
}

// Formating mem size
std::wstring FormatMemorySize(ULONGLONG bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB", L"PB" };
    double size = static_cast<double>(bytes);
    int unitIndex = 0;

    while (size >= 1024.0 && unitIndex < 5) {
        size /= 1024.0;
        unitIndex++;
    }

    std::wstringstream ss;
    ss << std::fixed << std::setprecision(2);

    if (unitIndex == 0) {
        ss << bytes << L" " << units[unitIndex];
    }
    else {
        ss << size << L" " << units[unitIndex];
    }

    return ss.str();
}

// GetProcessUserName
std::wstring GetProcessUserName(DWORD pid) {
    if (pid == 0) return L"SYSTEM (Idle)";
    if (pid == 4) return L"SYSTEM";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            return L"SYSTEM";
        }
        return L"Access Denied";
    }

    HANDLE hToken = NULL;
    std::wstring username = L"Unknown";

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD tokenInfoSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);

        if (tokenInfoSize > 0) {
            PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenInfoSize);
            if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoSize, &tokenInfoSize)) {
                std::wstring name(256, L'\0');
                std::wstring domain(256, L'\0');
                DWORD nameSize = 256;
                DWORD domainSize = 256;
                SID_NAME_USE sidType;

                if (LookupAccountSid(NULL, pTokenUser->User.Sid,
                    &name[0], &nameSize, &domain[0], &domainSize, &sidType)) {
                    name.resize(nameSize);
                    domain.resize(domainSize);

                    if (domainSize > 0 && domain[0] != L'\0') {
                        username = domain + L"\\" + name;
                    }
                    else {
                        username = name;
                    }
                }
                else {
                    username = L"SYSTEM";
                }
            }
            free(pTokenUser);
        }
        else {
            username = L"SYSTEM";
        }
        CloseHandle(hToken);
    }
    else {
        username = L"SYSTEM";
    }

    CloseHandle(hProcess);
    return username;
}

// GetProcessesList
std::vector<ProcessInfo> GetProcessesList() {
    std::vector<ProcessInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == 0) continue;

            ProcessInfo info;
            info.pid = processEntry.th32ProcessID;
            info.parentPid = processEntry.th32ParentProcessID;
            info.name = processEntry.szExeFile;
            info.threadCount = processEntry.cntThreads;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
            if (hProcess) {
                std::wstring path(MAX_PATH, L'\0');
                if (GetModuleFileNameExW(hProcess, NULL, &path[0], MAX_PATH)) {
                    path.resize(wcslen(path.c_str()));
                    info.fullPath = path;
                }

                PROCESS_MEMORY_COUNTERS_EX pmc;
                if ((PROCESS_MEMORY_COUNTERS*)&pmc) {
                    info.workingSetSize = pmc.WorkingSetSize;
                }

                info.userName = GetProcessUserName(info.pid);
                info.cpuUsage = CalculateCPUUsage(info.pid);

                CloseHandle(hProcess);
            }
            else {
                info.userName = GetProcessUserName(info.pid);
            }

            processes.push_back(info);
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return processes;
}

// PropertiesDialog
INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static DWORD processPid = 0;
    static ProcessInfo procInfo;

    switch (message) {
    case WM_INITDIALOG: {
        processPid = (DWORD)lParam;

        procInfo = GetDetailedProcessInfo(processPid);

        if (procInfo.pid == 0) {
            MessageBox(hDlg, L"Couldn't get information about the process", L"Error",
                MB_OK | MB_ICONERROR);
            EndDialog(hDlg, 0);
            return TRUE;
        }

        SetDlgItemText(hDlg, IDC_PROP_NAME, procInfo.name.c_str());
        SetDlgItemInt(hDlg, IDC_PROP_PID, procInfo.pid, FALSE);
        SetDlgItemInt(hDlg, IDC_PROP_PARENT_PID, procInfo.parentPid, FALSE);
        SetDlgItemText(hDlg, IDC_PROP_PATH, procInfo.fullPath.c_str());
        SetDlgItemText(hDlg, IDC_PROP_CMD_LINE, procInfo.commandLine.c_str());
        SetDlgItemText(hDlg, IDC_PROP_USER, procInfo.userName.c_str());

        std::wstring priorityStr;
        switch (procInfo.priority) {
        case REALTIME_PRIORITY_CLASS: priorityStr = L"Real-time"; break;
        case HIGH_PRIORITY_CLASS: priorityStr = L"High"; break;
        case ABOVE_NORMAL_PRIORITY_CLASS: priorityStr = L"Above Normal"; break;
        case NORMAL_PRIORITY_CLASS: priorityStr = L"Normal"; break;
        case BELOW_NORMAL_PRIORITY_CLASS: priorityStr = L"Below Normal"; break;
        case IDLE_PRIORITY_CLASS: priorityStr = L"Idle"; break;
        default: priorityStr = L"Unknown"; break;
        }
        SetDlgItemText(hDlg, IDC_PROP_PRIORITY, priorityStr.c_str());

        SetDlgItemInt(hDlg, IDC_PROP_THREADS, procInfo.threadCount, FALSE);

        // mem stream
        std::wstringstream memoryStream;
        memoryStream << L"Working Set: " << FormatMemorySize(procInfo.workingSetSize)
            << L"\nPrivate Bytes: " << FormatMemorySize(procInfo.privateBytes)
            << L"\nVirtual Size: " << FormatMemorySize(procInfo.virtualSize);
        SetDlgItemText(hDlg, IDC_PROP_MEMORY, memoryStream.str().c_str());

        // CPU Usage
        std::wstringstream cpuStream;
        cpuStream << std::fixed << std::setprecision(2) << procInfo.cpuUsage << L"%";
        SetDlgItemText(hDlg, IDC_PROP_CPU_USAGE, cpuStream.str().c_str());

        SetDlgItemText(hDlg, IDC_PROP_START_TIME, FormatFileTime(procInfo.createTime).c_str());
        SetDlgItemInt(hDlg, IDC_PROP_SESSION_ID, procInfo.sessionId, FALSE);
        SetDlgItemText(hDlg, IDC_PROP_INTEGRITY, procInfo.integrityLvl.c_str());

        // window title
        std::wstring title = L"Process Properties: " + procInfo.name +
            L" (PID: " + std::to_wstring(procInfo.pid) + L")";
        SetWindowText(hDlg, title.c_str());

        return TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE_BTN || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }

    return FALSE;
}

// ShowProcessProperties
void ShowProcessProperties(HWND hParent) {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(hParent, L"Select a process to view the properties",
            L"Information", MB_OK | MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (ListView_GetItem(g_hProcessList, &lvi)) {
        DWORD pid = (DWORD)lvi.lParam;
        DialogBoxParam(g_hInstance,
            MAKEINTRESOURCE(IDD_PROPERTIES_DIALOG),
            hParent, PropertiesDialog, (LPARAM)pid);
    }
}

// ShowSelectedProcessModules
void ShowSelectedProcessModules() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process to view modules",
            L"Information", MB_OK | MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (ListView_GetItem(g_hProcessList, &lvi)) {
        DWORD pid = (DWORD)lvi.lParam;

        TabCtrl_SetCurSel(g_hTabControl, 1);
        ShowProcessModules(g_hModuleList, pid);

        ShowWindow(g_hProcessList, SW_HIDE);
        ShowWindow(g_hModuleList, SW_SHOW);

        std::wstring status = L"Process modules PID: " + std::to_wstring(pid);
        UpdateStatusBar(status.c_str());
    }
}

// KillSelectedProcess
void KillSelectedProcess() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select the process to kill",
            L"Error", MB_ICONWARNING);
        return;
    }

    std::wstring name(256, L'\0');
    ListView_GetItemText(g_hProcessList, selected, 1, &name[0], 256);
    name.resize(wcslen(name.c_str()));

    std::wstring message = L"End the process \"" + name + L"\"?";

    if (MessageBox(g_hMainWnd, message.c_str(), L"Confirm",
        MB_YESNO | MB_ICONQUESTION) == IDYES) {

        LVITEM lvi;
        ZeroMemory(&lvi, sizeof(LVITEM));
        lvi.iItem = selected;
        lvi.mask = LVIF_PARAM;

        if (ListView_GetItem(g_hProcessList, &lvi)) {
            DWORD pid = (DWORD)lvi.lParam;

            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                if (TerminateProcess(hProcess, 0)) {
                    std::wstring statusBuffer = L"The process is completed: " + name;
                    UpdateStatusBar(statusBuffer.c_str());

                    g_cpuHistory.erase(pid);

                    RefreshProcessList();
                }
                else {
                    DWORD error = GetLastError();
                    std::wstring errorMsg = L"The process could not be completed. Error code: " +
                        std::to_wstring(error);
                    MessageBox(g_hMainWnd, errorMsg.c_str(),
                        L"Error", MB_ICONERROR);
                }
                CloseHandle(hProcess);
            }
            else {
                DWORD error = GetLastError();
                std::wstring errorMsg = L"The process could not be opened. Error code: " +
                    std::to_wstring(error);
                MessageBox(g_hMainWnd, errorMsg.c_str(),
                    L"Error", MB_ICONERROR);
            }
        }
    }
}

// EnableDebugPrivilege
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return result && GetLastError() == ERROR_SUCCESS;
}

// Обновление статус-бара
void UpdateStatusBar(const wchar_t* text) {
    if (g_hStatusBar) {
        SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)text);
        SendMessage(g_hStatusBar, SB_SETTEXT, 1, (LPARAM)L"Windows Process Monitor v2.0");

        // Обновляем время и память
        SYSTEMTIME st;
        GetLocalTime(&st);
        std::wstringstream timeStream;
        timeStream << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
            << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
            << std::setw(2) << std::setfill(L'0') << st.wSecond;
        SendMessage(g_hStatusBar, SB_SETTEXT, 2, (LPARAM)timeStream.str().c_str());

        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);

        std::wstringstream memStream;
        memStream << std::fixed << std::setprecision(1)
            << L"Memory: "
            << (float)(memInfo.ullTotalPhys - memInfo.ullAvailPhys) / memInfo.ullTotalPhys * 100.0f
            << L"% used";
        SendMessage(g_hStatusBar, SB_SETTEXT, 3, (LPARAM)memStream.str().c_str());
    }
}

BOOL g_isContextMenuActive = FALSE;

// Context menu
void ShowContextMenu(HWND hWnd, int x, int y) {
    HMENU hMenu = CreatePopupMenu();

    if (!hMenu) return; 

    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    BOOL hasSelection = (selected != -1);

    if (hasSelection) {
        // Основные операции
        AppendMenu(hMenu, MF_STRING, IDM_KILL, L"End Task");
        AppendMenu(hMenu, MF_STRING, IDM_KILL_TREE, L"End Process Tree");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Развернуть/Свернуть
        AppendMenu(hMenu, MF_STRING, IDM_EXPAND_COLLAPSE,
            g_isProcessTreeExpanded ? L"Collapse" : L"Expand");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Подменю Priority
        HMENU hPriorityMenu = CreatePopupMenu();
        AppendMenu(hPriorityMenu, MF_STRING, IDM_PRIORITY_REALTIME, L"Realtime");
        AppendMenu(hPriorityMenu, MF_STRING, IDM_PRIORITY_HIGH, L"High");
        AppendMenu(hPriorityMenu, MF_STRING, IDM_PRIORITY_ABOVENORMAL, L"Above Normal");
        AppendMenu(hPriorityMenu, MF_STRING, IDM_PRIORITY_NORMAL, L"Normal");
        AppendMenu(hPriorityMenu, MF_STRING, IDM_PRIORITY_BELOWNORMAL, L"Below Normal");
        AppendMenu(hPriorityMenu, MF_STRING, IDM_PRIORITY_IDLE, L"Idle");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hPriorityMenu, L"Set Priority");

        AppendMenu(hMenu, MF_STRING, IDM_AFFINITY, L"Set Affinity...");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Режим эффективности
        AppendMenu(hMenu, MF_STRING, IDM_EFFICIENCY_MODE,
            g_efficiencyModeEnabled ? L"Disable Efficiency Mode" : L"Enable Efficiency Mode");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Управление процессом
        AppendMenu(hMenu, MF_STRING, IDM_SUSPEND, L"Suspend Process");
        AppendMenu(hMenu, MF_STRING, IDM_RESUME, L"Resume Process");
        AppendMenu(hMenu, MF_STRING, IDM_RESTART, L"Restart Process");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Создание дампа
        AppendMenu(hMenu, MF_STRING, IDM_CREATEDUMP, L"Create Memory Dump File");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Информация
        AppendMenu(hMenu, MF_STRING, IDM_PROPERTIES, L"Properties");
        AppendMenu(hMenu, MF_STRING, IDM_MODULES, L"Show Modules (DLL)");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Быстрые действия
        AppendMenu(hMenu, MF_STRING, IDM_OPENFILELOCATION, L"Open File Location");
        AppendMenu(hMenu, MF_STRING, IDM_SEARCHONLINE, L"Search Online");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

        // Копирование
        HMENU hCopyMenu = CreatePopupMenu();
        AppendMenu(hCopyMenu, MF_STRING, IDM_COPYPID, L"Copy PID");
        AppendMenu(hCopyMenu, MF_STRING, IDM_COPYNAME, L"Copy Process Name");
        AppendMenu(hCopyMenu, MF_STRING, IDM_COPYPATH, L"Copy Full Path");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hCopyMenu, L"Copy");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    }

    // Общие пункты меню
    AppendMenu(hMenu, MF_STRING, IDM_CREATENEWTASK, L"Run New Task...");
    AppendMenu(hMenu, MF_STRING, IDM_EXPORT, L"Export List...");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_REFRESH, L"Refresh");
    AppendMenu(hMenu, MF_STRING, IDM_EXIT, L"Exit");

    // Убедимся, что окно находится поверх всех
    SetForegroundWindow(hWnd);

    // Устанавливаем флаг и отключаем таймер перед показом меню
    g_contextMenuActive = true;
    KillTimer(hWnd, 1);  // Отключаем таймер обновлений

    // Показываем меню и получаем выбранную команду
    UINT cmd = TrackPopupMenuEx(hMenu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NOANIMATION,
        x, y, hWnd, NULL);

    // Включаем таймер обратно и сбрасываем флаг после закрытия меню
    SetTimer(hWnd, 1, UI_UPDATE_INTERVAL, NULL);
    g_contextMenuActive = false;

    // Обрабатываем выбранную команду
    if (cmd != 0) {
        SendMessage(hWnd, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
    }

    DestroyMenu(hMenu);
}

void ToggleExpandCollapse() {
    g_isProcessTreeExpanded = !g_isProcessTreeExpanded;

    if (g_isProcessTreeExpanded) {
        UpdateStatusBar(L"Process tree expanded");
        // Здесь можно добавить логику для отображения дерева процессов
    }
    else {
        UpdateStatusBar(L"Process tree collapsed");
    }
}

void SetEfficiencyMode() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProcess) {
        BOOL success = FALSE;
        if (g_efficiencyModeEnabled) {
            // Восстанавливаем нормальный приоритет
            success = SetPriorityClass(hProcess, NORMAL_PRIORITY_CLASS);
            if (success) {
                g_efficiencyModeEnabled = false;
                UpdateStatusBar(L"Efficiency mode disabled (normal priority restored)");
            }
        }
        else {
            // Устанавливаем низкий приоритет для экономии ресурсов
            success = SetPriorityClass(hProcess, BELOW_NORMAL_PRIORITY_CLASS);
            if (success) {
                g_efficiencyModeEnabled = true;
                UpdateStatusBar(L"Efficiency mode enabled (below normal priority)");
            }
        }
        CloseHandle(hProcess);

        if (success) {
            g_efficiencyModeEnabled = !g_efficiencyModeEnabled;

            std::wstring message = g_efficiencyModeEnabled ?
                L"Efficiency mode enabled for process" :
                L"Efficiency mode disabled for process";
            UpdateStatusBar(message.c_str());
        }
        else {
            DWORD error = GetLastError();

            if (error == ERROR_PROC_NOT_FOUND || error == ERROR_INVALID_PARAMETER) {
                // Функция не поддерживается в этой версии Windows
                MessageBox(g_hMainWnd,
                    L"Efficiency mode is not supported on this version of Windows.\n"
                    L"Requires Windows 10 version 1709 or later.",
                    L"Feature Not Available",
                    MB_ICONINFORMATION | MB_OK);
            }
            else {
                MessageBox(g_hMainWnd, L"Failed to set efficiency mode", L"Error", MB_ICONERROR);
            }
        }
    }
    else {
        MessageBox(g_hMainWnd, L"Cannot open process", L"Error", MB_ICONERROR);
    }
}

BOOL SetProcessPowerThrottling(HANDLE hProcess, BOOL enable) {
    // Динамическая загрузка функции для совместимости
    typedef BOOL(WINAPI* PFN_SetProcessInformation)(
        HANDLE,
        PROCESS_INFORMATION_CLASS,
        PVOID,
        DWORD);

    static PFN_SetProcessInformation pfnSetProcessInformation = NULL;
    static BOOL initialized = FALSE;

    if (!initialized) {
        HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
        if (hKernel32) {
            pfnSetProcessInformation = (PFN_SetProcessInformation)
                GetProcAddress(hKernel32, "SetProcessInformation");
        }
        initialized = TRUE;
    }

    if (!pfnSetProcessInformation) {
        // Функция недоступна в этой версии Windows
        return FALSE;
    }

    PROCESS_POWER_THROTTLING_STATE powerThrottling;
    ZeroMemory(&powerThrottling, sizeof(powerThrottling));
    powerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;

    if (enable) {
        powerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
        powerThrottling.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    }
    else {
        powerThrottling.ControlMask = 0;
        powerThrottling.StateMask = 0;
    }

    return pfnSetProcessInformation(hProcess, ProcessPowerThrottling,
        &powerThrottling, sizeof(powerThrottling));
}


// Функция для отладки процесса
void DebugProcess() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Открываем диалог отладки
    DialogBoxParam(g_hInstance, MAKEINTRESOURCE(IDD_DEBUG_DIALOG),
        g_hMainWnd, DebugDialog, (LPARAM)pid);
}

// Диалог отладки
INT_PTR CALLBACK DebugDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static DWORD processPid = 0;
    static std::wstring processName;

    switch (message) {
    case WM_INITDIALOG: {
        processPid = (DWORD)lParam;

        // Получаем имя процесса
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processPid);
        if (hProcess) {
            wchar_t name[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, NULL, name, MAX_PATH)) {
                processName = name;
                // Извлекаем только имя файла
                size_t pos = processName.find_last_of(L'\\');
                if (pos != std::wstring::npos) {
                    processName = processName.substr(pos + 1);
                }
            }
            else {
                processName = L"Unknown";
            }
            CloseHandle(hProcess);
        }

        SetDlgItemText(hDlg, IDC_DEBUG_PROC_NAME, processName.c_str());
        SetDlgItemInt(hDlg, IDC_DEBUG_PID, processPid, FALSE);

        return TRUE;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_DEBUG_ATTACH: {
            // Прикрепление отладчика
            if (MessageBox(hDlg,
                L"Attaching a debugger may cause the process to pause.\nContinue?",
                L"Debugger Attach", MB_YESNO | MB_ICONQUESTION) == IDYES) {

                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processPid);
                if (hProcess) {
                    if (DebugActiveProcess(processPid)) {
                        MessageBox(hDlg, L"Debugger attached successfully",
                            L"Success", MB_ICONINFORMATION);
                    }
                    else {
                        MessageBox(hDlg, L"Failed to attach debugger",
                            L"Error", MB_ICONERROR);
                    }
                    CloseHandle(hProcess);
                }
                else {
                    MessageBox(hDlg, L"Cannot open process",
                        L"Error", MB_ICONERROR);
                }
            }
            return TRUE;
        }

        case IDC_DEBUG_DETACH: {
            // Отсоединение отладчика
            if (DebugActiveProcessStop(processPid)) {
                MessageBox(hDlg, L"Debugger detached successfully",
                    L"Success", MB_ICONINFORMATION);
            }
            else {
                MessageBox(hDlg, L"Failed to detach debugger",
                    L"Error", MB_ICONERROR);
            }
            return TRUE;
        }

        case IDC_DEBUG_BREAK: {
            // Прерывание процесса
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processPid);
            if (hProcess) {
                if (DebugBreakProcess(hProcess)) {
                    MessageBox(hDlg, L"Process break successful",
                        L"Success", MB_ICONINFORMATION);
                }
                else {
                    MessageBox(hDlg, L"Failed to break process",
                        L"Error", MB_ICONERROR);
                }
                CloseHandle(hProcess);
            }
            else {
                MessageBox(hDlg, L"Cannot open process",
                    L"Error", MB_ICONERROR);
            }
            return TRUE;
        }

        case IDC_DEBUG_CONTINUE: {
            // Продолжение процесса после прерывания
            MessageBox(hDlg,
                L"Continue functionality requires a debugger event loop.\n"
                L"This feature is limited in this implementation.",
                L"Information", MB_ICONINFORMATION);
            return TRUE;
        }

        case IDOK:
        case IDCANCEL:
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }

    return FALSE;
}

// Функция для показа детальной информации
void ShowDetailedInfo() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (ListView_GetItem(g_hProcessList, &lvi)) {
        DWORD pid = (DWORD)lvi.lParam;
        DialogBoxParam(g_hInstance,
            MAKEINTRESOURCE(IDD_DETAILED_INFO_DIALOG),
            g_hMainWnd, DetailedInfoDialog, (LPARAM)pid);
    }
}

// Диалог детальной информации
INT_PTR CALLBACK DetailedInfoDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static DWORD processPid = 0;
    static ProcessInfo procInfo;

    switch (message) {
    case WM_INITDIALOG: {
        processPid = (DWORD)lParam;

        procInfo = GetDetailedProcessInfo(processPid);

        if (procInfo.pid == 0) {
            MessageBox(hDlg, L"Couldn't get detailed information about the process",
                L"Error", MB_OK | MB_ICONERROR);
            EndDialog(hDlg, 0);
            return TRUE;
        }

        SetDlgItemText(hDlg, IDC_PROP_NAME, procInfo.name.c_str());
        SetDlgItemInt(hDlg, IDC_PROP_PID, procInfo.pid, FALSE);
        SetDlgItemInt(hDlg, IDC_PROP_PARENT_PID, procInfo.parentPid, FALSE);
        SetDlgItemText(hDlg, IDC_PROP_PATH, procInfo.fullPath.c_str());
        SetDlgItemText(hDlg, IDC_PROP_CMD_LINE, procInfo.commandLine.c_str());
        SetDlgItemText(hDlg, IDC_PROP_USER, procInfo.userName.c_str());

        // Приоритет
        std::wstring priorityStr;
        switch (procInfo.priority) {
        case REALTIME_PRIORITY_CLASS: priorityStr = L"Realtime"; break;
        case HIGH_PRIORITY_CLASS: priorityStr = L"High"; break;
        case ABOVE_NORMAL_PRIORITY_CLASS: priorityStr = L"Above Normal"; break;
        case NORMAL_PRIORITY_CLASS: priorityStr = L"Normal"; break;
        case BELOW_NORMAL_PRIORITY_CLASS: priorityStr = L"Below Normal"; break;
        case IDLE_PRIORITY_CLASS: priorityStr = L"Idle"; break;
        default: priorityStr = L"Unknown"; break;
        }
        SetDlgItemText(hDlg, IDC_PROP_PRIORITY, priorityStr.c_str());

        SetDlgItemInt(hDlg, IDC_PROP_THREADS, procInfo.threadCount, FALSE);

        // Память с детальной информацией
        std::wstringstream memoryStream;
        memoryStream << L"Working Set: " << FormatMemorySize(procInfo.workingSetSize)
            << L"\nPrivate Bytes: " << FormatMemorySize(procInfo.privateBytes)
            << L"\nVirtual Size: " << FormatMemorySize(procInfo.virtualSize)
            << L"\nPeak Working Set: " << FormatMemorySize(procInfo.workingSetSize) // Здесь можно добавить реальные данные
            << L"\nPeak Pagefile Usage: " << FormatMemorySize(procInfo.virtualSize);
        SetDlgItemText(hDlg, IDC_PROP_MEMORY, memoryStream.str().c_str());

        // CPU Usage
        std::wstringstream cpuStream;
        cpuStream << std::fixed << std::setprecision(2) << procInfo.cpuUsage << L"%";
        SetDlgItemText(hDlg, IDC_PROP_CPU_USAGE, cpuStream.str().c_str());

        SetDlgItemText(hDlg, IDC_PROP_START_TIME, FormatFileTime(procInfo.createTime).c_str());
        SetDlgItemInt(hDlg, IDC_PROP_SESSION_ID, procInfo.sessionId, FALSE);
        SetDlgItemText(hDlg, IDC_PROP_INTEGRITY, procInfo.integrityLvl.c_str());

        // Дополнительная информация (заглушки)
        SetDlgItemInt(hDlg, IDC_PROP_HANDLES, 0, FALSE); // Можно добавить реальное количество хендлов
        SetDlgItemInt(hDlg, IDC_PROP_GDI_OBJECTS, 0, FALSE);
        SetDlgItemInt(hDlg, IDC_PROP_USER_OBJECTS, 0, FALSE);
        SetDlgItemText(hDlg, IDC_PROP_IO_COUNTERS, L"N/A");
        SetDlgItemText(hDlg, IDC_PROP_WINDOW_TITLE, L"N/A");
        SetDlgItemText(hDlg, IDC_PROP_DEP_STATUS, L"N/A");
        SetDlgItemText(hDlg, IDC_PROP_ASLR_STATUS, L"N/A");
        SetDlgItemText(hDlg, IDC_PROP_ENVIRONMENT, L"N/A");

        // Заголовок окна
        std::wstring title = L"Detailed Information: " + procInfo.name +
            L" (PID: " + std::to_wstring(procInfo.pid) + L")";
        SetWindowText(hDlg, title.c_str());

        return TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE_BTN || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }

    return FALSE;
}

// Функция для перезапуска процесса
void RestartProcess() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Получаем путь к исполняемому файлу
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        MessageBox(g_hMainWnd, L"Cannot open process", L"Error", MB_ICONERROR);
        return;
    }

    wchar_t path[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) {
        CloseHandle(hProcess);

        // Завершаем процесс
        KillSelectedProcess();

        // Запускаем заново
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpFile = path;
        sei.nShow = SW_SHOW;

        if (ShellExecuteEx(&sei)) {
            UpdateStatusBar(L"Process restarted");
        }
        else {
            MessageBox(g_hMainWnd, L"Failed to restart process", L"Error", MB_ICONERROR);
        }
    }
    else {
        CloseHandle(hProcess);
        MessageBox(g_hMainWnd, L"Cannot get process path", L"Error", MB_ICONERROR);
    }
}

// Функция для приостановки процесса
void SuspendProcess() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Используем NtSuspendProcess для приостановки
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE);
        pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");

        if (NtSuspendProcess) {
            HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
            if (hProcess) {
                NTSTATUS status = NtSuspendProcess(hProcess);
                CloseHandle(hProcess);

                if (NT_SUCCESS(status)) {
                    UpdateStatusBar(L"Process suspended");
                    RefreshProcessList();
                }
                else {
                    MessageBox(g_hMainWnd, L"Failed to suspend process", L"Error", MB_ICONERROR);
                }
            }
            else {
                MessageBox(g_hMainWnd, L"Cannot open process", L"Error", MB_ICONERROR);
            }
        }
    }
}

// Функция для возобновления процесса
void ResumeProcess() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.iItem = selected;
    lvi.mask = LVIF_PARAM;

    if (!ListView_GetItem(g_hProcessList, &lvi)) {
        return;
    }

    DWORD pid = (DWORD)lvi.lParam;

    // Используем NtResumeProcess для возобновления
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE);
        pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");

        if (NtResumeProcess) {
            HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
            if (hProcess) {
                NTSTATUS status = NtResumeProcess(hProcess);
                CloseHandle(hProcess);

                if (NT_SUCCESS(status)) {
                    UpdateStatusBar(L"Process resumed");
                    RefreshProcessList();
                }
                else {
                    MessageBox(g_hMainWnd, L"Failed to resume process", L"Error", MB_ICONERROR);
                }
            }
            else {
                MessageBox(g_hMainWnd, L"Cannot open process", L"Error", MB_ICONERROR);
            }
        }
    }
}

// Функция для анализа цепочки ожидания
void AnalyzeWaitChain() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
        return;
    }

    MessageBox(g_hMainWnd,
        L"Wait chain analysis is a complex feature that requires additional system APIs.\n"
        L"This feature is planned for future versions.",
        L"Information",
        MB_ICONINFORMATION);
}

// Функции для настроек отображения ресурсов
void SetResourceDisplayMode(int mode) {
    switch (mode) {
    case IDM_RES_MEMORY_PERCENT:
        g_appState.resourceDisplay.memoryAsPercent = true;
        UpdateStatusBar(L"Memory display set to percentages");
        break;
    case IDM_RES_MEMORY_VALUES:
        g_appState.resourceDisplay.memoryAsPercent = false;
        UpdateStatusBar(L"Memory display set to values");
        break;
    case IDM_RES_DISK_PERCENT:
        g_appState.resourceDisplay.diskAsPercent = true;
        UpdateStatusBar(L"Disk display set to percentages");
        break;
    case IDM_RES_DISK_VALUES:
        g_appState.resourceDisplay.diskAsPercent = false;
        UpdateStatusBar(L"Disk display set to values");
        break;
    case IDM_RES_NETWORK_PERCENT:
        g_appState.resourceDisplay.networkAsPercent = true;
        UpdateStatusBar(L"Network display set to percentages");
        break;
    case IDM_RES_NETWORK_VALUES:
        g_appState.resourceDisplay.networkAsPercent = false;
        UpdateStatusBar(L"Network display set to values");
        break;
    case IDM_RES_ALL_PERCENT:
        g_appState.resourceDisplay.memoryAsPercent = true;
        g_appState.resourceDisplay.diskAsPercent = true;
        g_appState.resourceDisplay.networkAsPercent = true;
        UpdateStatusBar(L"All resources display set to percentages");
        break;
    case IDM_RES_ALL_VALUES:
        g_appState.resourceDisplay.memoryAsPercent = false;
        g_appState.resourceDisplay.diskAsPercent = false;
        g_appState.resourceDisplay.networkAsPercent = false;
        UpdateStatusBar(L"All resources display set to values");
        break;
    }

    // Обновляем отображение
    RefreshProcessList();
}



// AutoSizeListViewColumns
void AutoSizeListViewColumns(HWND hListView) {
    if (!hListView) return;

    int columnCount = Header_GetItemCount(ListView_GetHeader(hListView));
    for (int i = 0; i < columnCount; i++) {
        ListView_SetColumnWidth(hListView, i, LVSCW_AUTOSIZE);
    }
}

// RefreshProcessList
void RefreshProcessList() {
    // Просто устанавливаем флаг для обновления
    std::lock_guard<std::mutex> lock(g_processDataMutex);
    g_newDataAvailable = true;
}

// ShowProcessModules
void ShowProcessModules(HWND hList, DWORD pid) {
    if (!hList) return;

    ListView_DeleteAllItems(hList);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(snapshot, &moduleEntry)) {
            int i = 0;
            do {
                LVITEM lvi;
                ZeroMemory(&lvi, sizeof(LVITEM));
                lvi.mask = LVIF_TEXT;
                lvi.iItem = i;
                lvi.iSubItem = 0;
                lvi.pszText = moduleEntry.szModule;
                ListView_InsertItem(hList, &lvi);

                ListView_SetItemText(hList, i, 1, moduleEntry.szExePath);
                i++;
            } while (Module32NextW(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
    }

    for (int i = 0; i < 2; i++) {
        ListView_SetColumnWidth(hList, i, LVSCW_AUTOSIZE_USEHEADER);
    }
}

// ApplyListViewStyle
void ApplyListViewStyle(HWND hListView) {
    // Using standart styles, bcs LVS_EX_AUTOSIZECOLUMNS not exist
    ListView_SetExtendedListViewStyle(hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}

// CreateMainWindowControls
void CreateMainWindowControls(HWND hWnd) {
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);

    // Панель инструментов
    int buttonHeight = 30;
    int buttonSpacing = 10;
    int panelHeight = 40;

    HWND hButtonPanel = CreateWindow(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, rcClient.right, panelHeight,
        hWnd, (HMENU)1000, g_hInstance, NULL);

    int x = buttonSpacing;
    int y = (panelHeight - buttonHeight) / 2;

    // Только кнопка Kill
    CreateWindow(L"BUTTON", L"Kill Process",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, 100, buttonHeight, hWnd, (HMENU)IDC_KILL_BTN,
        g_hInstance, NULL);
    x += 100 + buttonSpacing;

    // Поле фильтра
    CreateWindow(L"STATIC", L"Filter:",
        WS_CHILD | WS_VISIBLE,
        x, y + 3, 35, 20, hWnd, NULL, g_hInstance, NULL);
    x += 35;

    g_hFilterEdit = CreateWindow(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        x, y, 200, buttonHeight, hWnd, (HMENU)IDC_FILTER_EDIT,
        g_hInstance, NULL);
    x += 200 + buttonSpacing;

    CreateWindow(L"BUTTON", L"Apply Filter",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, 100, buttonHeight, hWnd, (HMENU)IDC_SEARCH_BTN,
        g_hInstance, NULL);

    // Tab Control
    g_hTabControl = CreateWindowEx(0, WC_TABCONTROL, L"",
        WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
        0, panelHeight, rcClient.right, rcClient.bottom - panelHeight - 20,
        hWnd, (HMENU)IDC_TAB_CONTROL,
        g_hInstance, NULL);

    TCITEM tie = { 0 };
    tie.mask = TCIF_TEXT;

    const wchar_t* tabs[] = { L"Processes", L"Modules", L"Performance" };
    for (int i = 0; i < 3; i++) {
        tie.pszText = (LPWSTR)tabs[i];
        TabCtrl_InsertItem(g_hTabControl, i, &tie);
    }

    // Получаем область для содержимого таба
    RECT rcTab;
    GetClientRect(g_hTabControl, &rcTab);
    TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

    // ListView для процессов
    g_hProcessList = CreateWindowEx(0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left,
        rcTab.bottom - rcTab.top,
        g_hTabControl, (HMENU)IDC_PROCESS_LIST,
        g_hInstance, NULL);

    ApplyListViewStyle(g_hProcessList);

    // Столбцы ListView
    struct ColumnInfo {
        const wchar_t* name;
        int width;
    } columns[] = {
        { L"PID", 70 },
        { L"Process Name", 200 },
        { L"User", 150 },
        { L"Memory (MB)", 90 },
        { L"Threads", 70 },
        { L"CPU %", 70 },
        { L"Path", 400 }
    };

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    for (int i = 0; i < sizeof(columns) / sizeof(columns[0]); i++) {
        lvc.iSubItem = i;
        lvc.pszText = (LPWSTR)columns[i].name;
        lvc.cx = columns[i].width;
        lvc.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_hProcessList, i, &lvc);
    }

    // ListView для модулей
    g_hModuleList = CreateWindowEx(0, WC_LISTVIEW, L"",
        WS_CHILD | WS_BORDER | LVS_REPORT,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left,
        rcTab.bottom - rcTab.top,
        g_hTabControl, (HMENU)IDC_MODULE_LIST,
        g_hInstance, NULL);

    ApplyListViewStyle(g_hModuleList);

    const wchar_t* moduleColumns[] = { L"Module Name", L"Path" };
    int moduleWidths[] = { 250, 500 };

    for (int i = 0; i < 2; i++) {
        lvc.iSubItem = i;
        lvc.pszText = (LPWSTR)moduleColumns[i];
        lvc.cx = moduleWidths[i];
        ListView_InsertColumn(g_hModuleList, i, &lvc);
    }

    // Окно производительности
    g_hPerformanceWnd = CreateWindow(L"STATIC", L"Performance metrics will be displayed here",
        WS_CHILD | WS_BORDER | SS_CENTER,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left,
        rcTab.bottom - rcTab.top,
        g_hTabControl, NULL, g_hInstance, NULL);

    // Скрываем ненужные вкладки
    ShowWindow(g_hModuleList, SW_HIDE);
    ShowWindow(g_hPerformanceWnd, SW_HIDE);

    // Статус-бар
    g_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWnd, NULL, g_hInstance, NULL);

    // Части статус-бара (пропорционально ширине окна)
    int parts[5];
    parts[0] = rcClient.right * 25 / 100;   // 25% для статуса
    parts[1] = rcClient.right * 50 / 100;   // 50% для версии
    parts[2] = rcClient.right * 65 / 100;   // 65% для времени
    parts[3] = rcClient.right * 80 / 100;   // 80% для памяти
    parts[4] = -1;
    SendMessage(g_hStatusBar, SB_SETPARTS, 5, (LPARAM)parts);

    // Инициализация данных
    std::lock_guard<std::mutex> lock(g_processDataMutex);
    g_processes = GetProcessesList();
    g_filteredProcesses = g_processes;
    g_newDataAvailable = true;
}

void ToggleAutoRefresh() {
    g_appState.autoRefresh = !g_appState.autoRefresh;

    if (g_appState.autoRefresh) {
        StartRealTimeUpdates();
        UpdateStatusBar(L"Auto refresh enabled");
    }
    else {
        StopRealTimeUpdates();
        UpdateStatusBar(L"Auto refresh disabled");
    }
}

void ToggleShowAllUsers() {
    g_appState.showAllUsers = !g_appState.showAllUsers;

    // Обновляем список процессов
    RefreshProcessList();

    UpdateStatusBar(g_appState.showAllUsers ?
        L"Showing processes from all users" :
        L"Showing only current user processes");
}

// Main window procedur
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_GETMINMAXINFO:
    {
        LPMINMAXINFO pMMI = (LPMINMAXINFO)lParam;
        pMMI->ptMinTrackSize.x = MIN_WINDOW_WIDTH;
        pMMI->ptMinTrackSize.y = MIN_WINDOW_HEIGHT;
        return 0;
    }

    case WM_CREATE:
        CreateMainWindowControls(hWnd);
        EnableDebugPrivilege();
        StartRealTimeUpdates();
        SetTimer(hWnd, 1, UI_UPDATE_INTERVAL, NULL);
        UpdateStatusBar(L"Real-time monitoring started");
        break;

    case WM_SIZE:
    {
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        // Обновляем статус-бар
        if (g_hStatusBar) {
            SendMessage(g_hStatusBar, WM_SIZE, 0, 0);

            // Пересчитываем части статус-бара
            int parts[5];
            parts[0] = rcClient.right * 25 / 100;   // 25% для статуса
            parts[1] = rcClient.right * 50 / 100;   // 50% для версии
            parts[2] = rcClient.right * 65 / 100;   // 65% для времени
            parts[3] = rcClient.right * 80 / 100;   // 80% для памяти
            parts[4] = -1;
            SendMessage(g_hStatusBar, SB_SETPARTS, 5, (LPARAM)parts);
        }

        // Обновляем панель инструментов
        HWND hButtonPanel = GetDlgItem(hWnd, 1000);
        if (hButtonPanel) {
            SetWindowPos(hButtonPanel, NULL, 0, 0, rcClient.right, 40, SWP_NOZORDER);
        }

        // Обновляем Tab Control
        if (g_hTabControl) {
            SetWindowPos(g_hTabControl, NULL,
                0, 40,
                rcClient.right, rcClient.bottom - 60,
                SWP_NOZORDER);

            RECT rcTab;
            GetClientRect(g_hTabControl, &rcTab);
            TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

            int tabWidth = rcTab.right - rcTab.left;
            int tabHeight = rcTab.bottom - rcTab.top;

            if (g_hProcessList && IsWindowVisible(g_hProcessList)) {
                SetWindowPos(g_hProcessList, NULL,
                    rcTab.left, rcTab.top,
                    tabWidth, tabHeight,
                    SWP_NOZORDER);
            }

            if (g_hModuleList && IsWindowVisible(g_hModuleList)) {
                SetWindowPos(g_hModuleList, NULL,
                    rcTab.left, rcTab.top,
                    tabWidth, tabHeight,
                    SWP_NOZORDER);
            }

            if (g_hPerformanceWnd && IsWindowVisible(g_hPerformanceWnd)) {
                SetWindowPos(g_hPerformanceWnd, NULL,
                    rcTab.left, rcTab.top,
                    tabWidth, tabHeight,
                    SWP_NOZORDER);
            }
        }
        break;
    }

    case WM_TIMER:
        if (wParam == 1) {
            if (g_contextMenuActive) {
                return 0;  // Полностью блокируем обработку таймера, если меню активно
            }
            CheckForDataUpdates();
        }
        break;

    case WM_CLOSE:
        if (g_appState.minimizeOnClose) {
            ShowWindow(hWnd, SW_MINIMIZE);
            return 0;
        }
        DestroyWindow(hWnd);
        break;

    case WM_NOTIFY:
    {
        LPNMHDR lpnmh = (LPNMHDR)lParam;

        if (lpnmh->idFrom == IDC_PROCESS_LIST) {
            if (lpnmh->code == LVN_COLUMNCLICK) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (g_appState.sortColumn == pnmv->iSubItem) {
                    g_appState.sortAscending = !g_appState.sortAscending;
                }
                else {
                    g_appState.sortColumn = pnmv->iSubItem;
                    g_appState.sortAscending = TRUE;
                }

                // Применяем новую сортировку
                std::lock_guard<std::mutex> lock(g_processDataMutex);
                SortProcessList(g_filteredProcesses, g_appState.sortColumn, g_appState.sortAscending);
                g_newDataAvailable = true;
            }
        }
        else if (lpnmh->idFrom == IDC_TAB_CONTROL && lpnmh->code == TCN_SELCHANGE) {
            int sel = TabCtrl_GetCurSel(g_hTabControl);

            ShowWindow(g_hProcessList, SW_HIDE);
            ShowWindow(g_hModuleList, SW_HIDE);
            ShowWindow(g_hPerformanceWnd, SW_HIDE);

            switch (sel) {
            case 0: // Processes
                if (g_hProcessList) ShowWindow(g_hProcessList, SW_SHOW);
                break;
            case 1: // Modules
                if (g_hModuleList) ShowWindow(g_hModuleList, SW_SHOW);
                break;
            case 2: // Performance
                if (g_hPerformanceWnd) ShowWindow(g_hPerformanceWnd, SW_SHOW);
                break;
            }
        }
        break;
    }


    case WM_RBUTTONUP:
    {
        // Проверяем, было ли нажатие на списке процессов
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        HWND hwndUnderMouse = ChildWindowFromPoint(hWnd, pt);

        if (hwndUnderMouse == g_hProcessList) {
            // Преобразуем в экранные координаты
            ClientToScreen(hWnd, &pt);

            // Находим элемент под курсором
            POINT clientPt = pt;
            ScreenToClient(g_hProcessList, &clientPt);

            LVHITTESTINFO hitTestInfo = { 0 };
            hitTestInfo.pt = clientPt;
            int itemIndex = ListView_HitTest(g_hProcessList, &hitTestInfo);

            // Если клик точно на элементе (не на заголовке или пустом месте)
            if (itemIndex != -1 && (hitTestInfo.flags & LVHT_ONITEM)) {
                ListView_SetItemState(g_hProcessList, -1, 0, LVIS_SELECTED);
                ListView_SetItemState(g_hProcessList, itemIndex, LVIS_SELECTED, LVIS_SELECTED);
                ListView_EnsureVisible(g_hProcessList, itemIndex, FALSE);

                ShowContextMenu(hWnd, pt.x, pt.y);
                return 0;
            }
        }
        break;
    }

    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);

        switch (wmId) {
        case IDM_EFFICIENCY_MODE:
            SetEfficiencyMode();
            break;

        case IDM_SUSPEND:
            SuspendProcess();
            break;

        case IDM_RESUME:
            ResumeProcess();
            break;

        case IDM_RESTART:
            RestartProcess();
            break;

        case IDM_ANALYZE_WAIT_CHAIN:
            AnalyzeWaitChain();
            break;

        case IDC_KILL_BTN: {
            KillSelectedProcess();
            break;
        }

        case IDC_SEARCH_BTN: {
            wchar_t filter[256];
            GetWindowText(g_hFilterEdit, filter, 256);
            g_appState.filterText = filter;

            std::lock_guard<std::mutex> lock(g_processDataMutex);
            g_filteredProcesses = g_processes;
            if (!g_appState.filterText.empty()) {
                ApplyFilter(g_filteredProcesses, g_appState.filterText);
            }
            g_newDataAvailable = true;
            break;
        }

        case IDM_KILL: {
            KillSelectedProcess();
            break;
        }

        case IDM_KILL_TREE: {
            KillProcessTree();
            break;
        }

        case IDM_PROPERTIES: {
            ShowProcessProperties(hWnd);
            break;
        }

        case IDM_MODULES: {
            ShowSelectedProcessModules();
            break;
        }

        case IDM_EXPORT: {
            DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_EXPORT_DIALOG), hWnd, ExportDialog);
            break;
        }

        case IDM_COPYPID: {
            int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
            if (selected != -1) {
                std::wstring pid(32, L'\0');
                ListView_GetItemText(g_hProcessList, selected, 0, &pid[0], 32);
                pid.resize(wcslen(pid.c_str()));
                CopyToClipboard(pid);
                UpdateStatusBar(L"PID copied to clipboard");
            }
            break;
        }

        case IDM_COPYNAME: {
            int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
            if (selected != -1) {
                std::wstring name(256, L'\0');
                ListView_GetItemText(g_hProcessList, selected, 1, &name[0], 256);
                name.resize(wcslen(name.c_str()));
                CopyToClipboard(name);
                UpdateStatusBar(L"Process name copied to clipboard");
            }
            break;
        }

        case IDM_COPYPATH: {
            int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
            if (selected != -1) {
                std::wstring path(512, L'\0');
                ListView_GetItemText(g_hProcessList, selected, 6, &path[0], 512);
                path.resize(wcslen(path.c_str()));
                CopyToClipboard(path);
                UpdateStatusBar(L"Path copied to clipboard");
            }
            break;
        }

        case IDM_OPENFILELOCATION: {
            OpenFileLocation();
            break;
        }

        case IDM_SEARCHONLINE: {
            SearchOnline();
            break;
        }

        case IDM_CREATEDUMP: {
            int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
            if (selected == -1) {
                MessageBox(g_hMainWnd, L"Select a process first", L"Information", MB_ICONINFORMATION);
                break;
            }

            LVITEM lvi;
            ZeroMemory(&lvi, sizeof(LVITEM));
            lvi.iItem = selected;
            lvi.mask = LVIF_PARAM;

            if (!ListView_GetItem(g_hProcessList, &lvi)) {
                break;
            }

            DWORD pid = (DWORD)lvi.lParam;

            // Запрос имени файла для дампа
            wchar_t szFile[MAX_PATH] = { 0 };
            OPENFILENAME ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = g_hMainWnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"Dump Files (*.dmp)\0*.dmp\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.lpstrDefExt = L"dmp";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

            if (!GetSaveFileName(&ofn)) {
                break;
            }

            CreateMiniDump(pid, szFile);
            break;
        }

        case IDM_EXPAND_COLLAPSE:
            ToggleExpandCollapse();
            break;

        case IDM_DEBUG_PROCESS:
            DebugProcess();
            break;

        case IDM_DETAILED_INFO:
            ShowDetailedInfo();
            break;

            // Обработка настроек отображения ресурсов
        case IDM_RES_MEMORY_PERCENT:
        case IDM_RES_MEMORY_VALUES:
        case IDM_RES_DISK_PERCENT:
        case IDM_RES_DISK_VALUES:
        case IDM_RES_NETWORK_PERCENT:
        case IDM_RES_NETWORK_VALUES:
        case IDM_RES_ALL_PERCENT:
        case IDM_RES_ALL_VALUES:
            SetResourceDisplayMode(wmId);
            break;

        case IDM_GOTOSERVICES: {
            int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
            if (selected == -1) {
                // Если процесс не выбран, просто открываем services.msc
                ShellExecute(NULL, L"open", L"services.msc", NULL, NULL, SW_SHOW);
                break;
            }

            LVITEM lvi;
            ZeroMemory(&lvi, sizeof(LVITEM));
            lvi.iItem = selected;
            lvi.mask = LVIF_PARAM;

            if (!ListView_GetItem(g_hProcessList, &lvi)) {
                break;
            }

            DWORD pid = (DWORD)lvi.lParam;

            // Попытка найти службы, связанные с процессом
            ShellExecute(NULL, L"open", L"services.msc", NULL, NULL, SW_SHOW);

            MessageBox(g_hMainWnd,
                L"Service association feature is under development.\nServices console opened.",
                L"Information", MB_ICONINFORMATION);
            break;
        }

        case IDM_CREATENEWTASK: {
            RunNewTask();
            break;
        }

        case IDM_ABOUT: {
            ShowAboutDialog();
            break;
        }

        case IDM_ALWAYSONTOP: {
            ToggleAlwaysOnTop();
            break;
        }

        case IDM_AUTOREFRESH: {
            ToggleAutoRefresh();
            break;
        }

        case IDM_SHOWALLUSERS: {
            ToggleShowAllUsers();
            break;
        }

        case IDM_EXIT: {
            DestroyWindow(hWnd);
            break;
        }

                     // Приоритеты
        case IDM_PRIORITY_REALTIME: {
            SetProcessPriority(REALTIME_PRIORITY_CLASS);
            break;
        }

        case IDM_PRIORITY_HIGH: {
            SetProcessPriority(HIGH_PRIORITY_CLASS);
            break;
        }

        case IDM_PRIORITY_ABOVENORMAL: {
            SetProcessPriority(ABOVE_NORMAL_PRIORITY_CLASS);
            break;
        }

        case IDM_PRIORITY_NORMAL: {
            SetProcessPriority(NORMAL_PRIORITY_CLASS);
            break;
        }

        case IDM_PRIORITY_BELOWNORMAL: {
            SetProcessPriority(BELOW_NORMAL_PRIORITY_CLASS);
            break;
        }

        case IDM_PRIORITY_IDLE: {
            SetProcessPriority(IDLE_PRIORITY_CLASS);
            break;
        }

        case IDM_AFFINITY: {
            SetProcessAffinity();
            break;
        }

        case IDM_MINIMIZEONCLOSE: {
            g_appState.minimizeOnClose = !g_appState.minimizeOnClose;
            UpdateStatusBar(g_appState.minimizeOnClose ?
                L"Minimize on close enabled" :
                L"Minimize on close disabled");
            break;
        }

        case IDM_REFRESH: {
            RefreshProcessList();
            break;
        }

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    }

    case WM_CONTEXTMENU: {
        if ((HWND)wParam == g_hProcessList) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };

            // Конвертируем экранные координаты в клиентские для ListView
            POINT clientPt = pt;
            ScreenToClient(g_hProcessList, &clientPt);

            // Проверяем, кликнули ли на элемент
            LVHITTESTINFO hitTestInfo = { 0 };
            hitTestInfo.pt = clientPt;
            int itemIndex = ListView_HitTest(g_hProcessList, &hitTestInfo);

            if (itemIndex != -1) {
                // Выделяем элемент, на который кликнули
                ListView_SetItemState(g_hProcessList, -1, 0, LVIS_SELECTED);
                ListView_SetItemState(g_hProcessList, itemIndex, LVIS_SELECTED, LVIS_SELECTED);
                ListView_SetSelectionMark(g_hProcessList, itemIndex);

                ShowContextMenu(hWnd, pt.x, pt.y);
            }
            return 0;
        }
        break;
    }

    case WM_DESTROY:
        StopRealTimeUpdates();
        KillTimer(hWnd, 1);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// ExportProcessList
void ExportProcessList() {
    DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_EXPORT_DIALOG), g_hMainWnd, ExportDialog);
}

// Функция потока обновления
void UpdateThreadProc() {
    while (!g_updateThreadStopRequest.load()) {
        try {
            // Получаем новый список процессов
            auto newProcesses = GetProcessesList();

            // Безопасно обновляем глобальный список
            {
                std::lock_guard<std::mutex> lock(g_processDataMutex);
                g_processes = std::move(newProcesses);
                g_newDataAvailable = true;
                g_lastUpdateTick = GetTickCount();
            }

            // Уведомляем главный поток
            g_dataReadyCond.notify_one();

            // Задержка перед следующим обновлением
            for (int i = 0; i < 10; i++) {
                if (g_updateThreadStopRequest.load()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        catch (const std::exception& e) {
            // Обработка ошибок в потоке
        }
    }
    g_updateThreadRunning.store(false);
}

// Запуск реального обновления
void StartRealTimeUpdates() {
    if (g_updateThreadRunning.load()) {
        return;
    }

    g_updateThreadStopRequest.store(false);
    g_updateThreadRunning.store(true);

    try {
        g_updateThread = std::thread(UpdateThreadProc);
    }
    catch (...) {
        g_updateThreadRunning.store(false);
    }
}

// Остановка реального обновления
void StopRealTimeUpdates() {
    if (!g_updateThreadRunning.load()) {
        return;
    }

    g_updateThreadStopRequest.store(true);

    if (g_updateThread.joinable()) {
        try {
            g_updateThread.join();
        }
        catch (...) {
            g_updateThread.detach();
        }
    }

    g_updateThreadRunning.store(false);
}

// Проверка обновлений данных и обновление UI - ИСПРАВЛЕНА
void CheckForDataUpdates() {
    static DWORD lastUiUpdate = 0;
    DWORD currentTick = GetTickCount();

    // Проверяем обновления не чаще чем раз в UI_UPDATE_INTERVAL мс
    if (currentTick - lastUiUpdate < UI_UPDATE_INTERVAL) {
        return;
    }

    if (g_contextMenuActive) {
        return;
    }

    // Пытаемся захватить мьютекс без блокировки
    std::unique_lock<std::mutex> lock(g_processDataMutex, std::try_to_lock);

    if (lock.owns_lock() && g_newDataAvailable) {
        // Применяем фильтры и сортировку
        g_filteredProcesses = g_processes;

        if (!g_appState.filterText.empty()) {
            ApplyFilter(g_filteredProcesses, g_appState.filterText);
        }

        SortProcessList(g_filteredProcesses, g_appState.sortColumn, g_appState.sortAscending);

        // Обновляем интерфейс
        if (g_hProcessList && IsWindowVisible(g_hProcessList)) {
            RefreshListViewFromData(g_hProcessList, g_filteredProcesses);
        }

        // Обновляем статус бар
        std::wstringstream statusStream;
        statusStream << L"Processes: " << g_processes.size()
            << L" (Filtered: " << g_filteredProcesses.size() << L") | Real-time";

        if (g_hStatusBar) {
            SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)statusStream.str().c_str());
            SendMessage(g_hStatusBar, SB_SETTEXT, 1, (LPARAM)L"Windows Process Monitor v2.0");

            // Обновляем время
            SYSTEMTIME st;
            GetLocalTime(&st);
            std::wstringstream timeStream;
            timeStream << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
                << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
                << std::setw(2) << std::setfill(L'0') << st.wSecond;
            SendMessage(g_hStatusBar, SB_SETTEXT, 2, (LPARAM)timeStream.str().c_str());

            // Обновляем использование памяти
            MEMORYSTATUSEX memInfo;
            memInfo.dwLength = sizeof(MEMORYSTATUSEX);
            GlobalMemoryStatusEx(&memInfo);

            std::wstringstream memStream;
            memStream << std::fixed << std::setprecision(1)
                << L"Memory: "
                << (float)(memInfo.ullTotalPhys - memInfo.ullAvailPhys) / memInfo.ullTotalPhys * 100.0f
                << L"% used";
            SendMessage(g_hStatusBar, SB_SETTEXT, 3, (LPARAM)memStream.str().c_str());
        }

        g_newDataAvailable = false;
        lastUiUpdate = currentTick;
    }
}

// Более эффективная версия с использованием LVITEM напрямую
// Функция обновления ListView
void RefreshListViewFromData(HWND hList, const std::vector<ProcessInfo>& processes) {
    if (!hList || !IsWindow(hList) || g_contextMenuActive) return;

    if (g_contextMenuActive) return;

    // Сохраняем выделение
    int selectedIndex = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    DWORD selectedPid = 0;
    if (selectedIndex != -1) {
        LVITEM lvi = { 0 };
        lvi.iItem = selectedIndex;
        lvi.mask = LVIF_PARAM;
        if (ListView_GetItem(hList, &lvi)) {
            selectedPid = (DWORD)lvi.lParam;
        }
    }

    // Отключаем перерисовку
    SendMessage(hList, WM_SETREDRAW, FALSE, 0);

    // Очищаем список
    int oldItemCount = ListView_GetItemCount(hList);
    int newItemCount = static_cast<int>(processes.size());

    // Обновляем существующие строки или добавляем новые
    for (int i = 0; i < newItemCount; i++) {
        const ProcessInfo& proc = processes[i];

        // Подготавливаем данные для колонок
        std::wstring pidStr = std::to_wstring(proc.pid);

        // Форматируем память с одним знаком после запятой
        std::wstringstream memoryStream;
        memoryStream << std::fixed << std::setprecision(1)
            << (proc.workingSetSize / (1024.0 * 1024.0));
        std::wstring memoryStr = memoryStream.str();

        std::wstring threadsStr = std::to_wstring(proc.threadCount);

        std::wstringstream cpuStream;
        cpuStream << std::fixed << std::setprecision(1) << proc.cpuUsage;
        std::wstring cpuStr = cpuStream.str();

        if (i < oldItemCount) {
            // Обновляем существующую строку
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT | LVIF_PARAM;
            lvi.iItem = i;
            lvi.lParam = proc.pid;

            // Обновляем PID
            lvi.iSubItem = 0;
            lvi.pszText = const_cast<wchar_t*>(pidStr.c_str());
            ListView_SetItem(hList, &lvi);

            // Обновляем остальные колонки
            ListView_SetItemText(hList, i, 1, const_cast<wchar_t*>(proc.name.c_str()));
            ListView_SetItemText(hList, i, 2, const_cast<wchar_t*>(proc.userName.c_str()));
            ListView_SetItemText(hList, i, 3, const_cast<wchar_t*>(memoryStr.c_str()));
            ListView_SetItemText(hList, i, 4, const_cast<wchar_t*>(threadsStr.c_str()));
            ListView_SetItemText(hList, i, 5, const_cast<wchar_t*>(cpuStr.c_str()));
            ListView_SetItemText(hList, i, 6, const_cast<wchar_t*>(proc.fullPath.c_str()));
        }
        else {
            // Добавляем новую строку
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT | LVIF_PARAM;
            lvi.iItem = i;
            lvi.iSubItem = 0;
            lvi.pszText = const_cast<wchar_t*>(pidStr.c_str());
            lvi.lParam = proc.pid;

            int itemIndex = ListView_InsertItem(hList, &lvi);
            if (itemIndex != -1) {
                ListView_SetItemText(hList, itemIndex, 1, const_cast<wchar_t*>(proc.name.c_str()));
                ListView_SetItemText(hList, itemIndex, 2, const_cast<wchar_t*>(proc.userName.c_str()));
                ListView_SetItemText(hList, itemIndex, 3, const_cast<wchar_t*>(memoryStr.c_str()));
                ListView_SetItemText(hList, itemIndex, 4, const_cast<wchar_t*>(threadsStr.c_str()));
                ListView_SetItemText(hList, itemIndex, 5, const_cast<wchar_t*>(cpuStr.c_str()));
                ListView_SetItemText(hList, itemIndex, 6, const_cast<wchar_t*>(proc.fullPath.c_str()));
            }
        }
    }

    // Удаляем лишние строки
    if (newItemCount < oldItemCount) {
        for (int i = oldItemCount - 1; i >= newItemCount; i--) {
            ListView_DeleteItem(hList, i);
        }
    }

    // Восстанавливаем выделение
    if (selectedPid != 0) {
        for (int i = 0; i < newItemCount; i++) {
            LVITEM lvi = { 0 };
            lvi.iItem = i;
            lvi.mask = LVIF_PARAM;
            if (ListView_GetItem(hList, &lvi) && (DWORD)lvi.lParam == selectedPid) {
                ListView_SetItemState(hList, i, LVIS_SELECTED | LVIS_FOCUSED,
                    LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(hList, i, FALSE);
                break;
            }
        }
    }

    // Автоматический размер столбцов
    for (int i = 0; i < 7; i++) {
        ListView_SetColumnWidth(hList, i, LVSCW_AUTOSIZE_USEHEADER);
    }

    // Включаем перерисовку
    SendMessage(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, NULL, TRUE);
    UpdateWindow(hList);
}