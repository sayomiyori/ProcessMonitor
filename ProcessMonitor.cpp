#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600  // Windows Vista для QueryFullProcessImageNameW
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
#include <iomanip>  // Для std::setw, std::setfill

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")

#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include "ProcessMonitor.h"
#include "Resource.h"

// Global variables
HWND g_hMainWnd = NULL;
HWND g_hProcessList = NULL;
HWND g_hModuleList = NULL;
HWND g_hTabControl = NULL;
HWND g_hStatusBar = NULL;
HWND g_hFilterEdit = NULL;
HWND g_hSortCombo = NULL;
HWND g_hPerformanceWnd = NULL;
std::vector<ProcessInfo> g_processes;
std::vector<ProcessInfo> g_filteredProcesses;
HINSTANCE g_hInstance;
AppState g_appState = { FALSE, 2000, L"", 1, TRUE };
std::map<DWORD, CPUHistory> g_cpuHistory;
ULONGLONG g_totalMemory = 0;
ULONGLONG g_availableMemory = 0;

// Helper macros for coordinates
#define GET_X_LPARAM(lParam) ((int)(short)LOWORD(lParam))
#define GET_Y_LPARAM(lParam) ((int)(short)HIWORD(lParam))

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
    // Проверка прав администратора
    if (!IsRunAsAdministrator()) {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
            // Перезапуск с правами администратора
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;

            if (!ShellExecuteEx(&sei)) {
                MessageBox(NULL,
                    L"Программа требует прав администратора.\nЗапустите её от имени администратора.",
                    L"Ошибка прав доступа",
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

    // Main message loop
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
    wcex.hIcon = LoadIcon(hInstance, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"ProcessMonitorClass";
    wcex.hIconSm = LoadIcon(hInstance, IDI_APPLICATION);

    return RegisterClassExW(&wcex);
}

// Creating main window
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    g_hInstance = hInstance;

    g_hMainWnd = CreateWindowW(
        L"ProcessMonitorClass",
        L"Монитор процессов Windows v2.0",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 1200, 700,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hMainWnd) {
        return FALSE;
    }

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);
    return TRUE;
}

// Функция завершения дерева процессов
int KillProcessTreeRecursive(DWORD parentPid, BOOL killParent) {
    int killedCount = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Собираем список дочерних процессов
    std::vector<DWORD> childPids;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid && pe.th32ProcessID != parentPid) {
                childPids.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &pe));
    }

    // Рекурсивно убиваем всех детей
    for (DWORD childPid : childPids) {
        killedCount += KillProcessTreeRecursive(childPid, TRUE);
    }

    // Убиваем текущий процесс (если нужно)
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
        MessageBox(g_hMainWnd, L"Select a process to complete the tree", L"Error", MB_ICONWARNING);
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

        RefreshProcessList(g_hProcessList);
    }
}

// Функция расчета использования CPU
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

// Функция экспорта в CSV
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

// Функция экспорта в TXT
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

// Диалог экспорта
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

// Функция копирования в буфер обмена
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

// Функция сортировки
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

// Функция фильтрации
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

// Получение детальной информации о процессе
ProcessInfo GetDetailedProcessInfo(DWORD pid) {
    ProcessInfo info = {};
    info.pid = pid;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }

    if (hProcess) {
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

        // Используем GetModuleFileNameEx для получения пути
        if (GetModuleFileNameEx(hProcess, NULL, &path[0], MAX_PATH)) {
            path.resize(wcslen(path.c_str()));
            info.fullPath = path;
        }
        else {
            // Альтернативный способ для системных процессов
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

        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            info.workingSetSize = pmc.WorkingSetSize;
            info.privateBytes = pmc.PrivateUsage;
            info.virtualSize = pmc.PagefileUsage;
        }

        info.cpuUsage = CalculateCPUUsage(pid);
        CloseHandle(hProcess);
    }

    return info;
}

// Получение командной строки процесса
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

// Получение уровня целостности процесса
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

// Форматирование времени
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

// Форматирование размера памяти
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

// Получение имени пользователя процесса
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

// Получение списка процессов
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

                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
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

// Диалог свойств процесса
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

        // Формируем строку памяти
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

        // Заголовок окна
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

// Отображение свойств процесса
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

// Отображение модулей выбранного процесса
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

// Функция завершения выбранного процесса
void KillSelectedProcess() {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBox(g_hMainWnd, L"Select the process to complete",
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

                    RefreshProcessList(g_hProcessList);
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

// Включение привилегий отладки
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

// Контекстное меню
void ShowContextMenu(HWND hWnd, int x, int y) {
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;

    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    BOOL hasSelection = (selected != -1);

    AppendMenu(hMenu, MF_STRING, IDM_REFRESH, L"Обновить");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);

    if (hasSelection) {
        AppendMenu(hMenu, MF_STRING, IDM_KILL, L"Завершить процесс");
        AppendMenu(hMenu, MF_STRING, IDM_KILL_TREE, L"Завершить дерево процессов");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenu(hMenu, MF_STRING, IDM_PROPERTIES, L"Свойства процесса");
        AppendMenu(hMenu, MF_STRING, IDM_MODULES, L"Показать модули (DLL)");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenu(hMenu, MF_STRING, IDM_COPYPID, L"Копировать PID");
        AppendMenu(hMenu, MF_STRING, IDM_COPYNAME, L"Копировать имя");
        AppendMenu(hMenu, MF_STRING, IDM_COPYPATH, L"Копировать путь");
    }

    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_EXPORT, L"Экспорт списка...");
    AppendMenu(hMenu, MF_STRING, IDM_AUTOREFRESH, g_appState.autoRefresh ? L"Отключить автообновление" : L"Включить автообновление");

    SetForegroundWindow(hWnd);
    UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD, x, y, 0, hWnd, NULL);

    if (cmd != 0) {
        SendMessage(hWnd, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
    }

    DestroyMenu(hMenu);
}

// Обновление списка процессов
void RefreshProcessList(HWND hList) {
    int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
    DWORD selectedPid = 0;
    if (selected != -1) {
        LVITEM lvi;
        ZeroMemory(&lvi, sizeof(LVITEM));
        lvi.iItem = selected;
        lvi.mask = LVIF_PARAM;
        if (ListView_GetItem(g_hProcessList, &lvi)) {
            selectedPid = (DWORD)lvi.lParam;
        }
    }

    ListView_DeleteAllItems(hList);
    g_processes = GetProcessesList();

    g_filteredProcesses = g_processes;
    if (!g_appState.filterText.empty()) {
        ApplyFilter(g_filteredProcesses, g_appState.filterText);
    }

    SortProcessList(g_filteredProcesses, g_appState.sortColumn, g_appState.sortAscending);

    std::vector<ProcessInfo>& displayList = g_filteredProcesses.empty() ? g_processes : g_filteredProcesses;

    for (size_t i = 0; i < displayList.size(); i++) {
        const ProcessInfo& proc = displayList[i];

        LVITEM lvi;
        ZeroMemory(&lvi, sizeof(LVITEM));
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = (int)i;
        lvi.iSubItem = 0;

        std::wstring pidStr = std::to_wstring(proc.pid);
        lvi.pszText = const_cast<LPWSTR>(pidStr.c_str());
        lvi.lParam = proc.pid;
        ListView_InsertItem(hList, &lvi);

        ListView_SetItemText(hList, i, 1, const_cast<LPWSTR>(proc.name.c_str()));
        ListView_SetItemText(hList, i, 2, const_cast<LPWSTR>(proc.userName.c_str()));

        // Memory
        std::wstringstream memoryStream;
        memoryStream << std::fixed << std::setprecision(1) << (proc.workingSetSize / (1024.0 * 1024.0));
        std::wstring memoryStr = memoryStream.str();
        ListView_SetItemText(hList, i, 3, const_cast<LPWSTR>(memoryStr.c_str()));

        // Threads
        std::wstring threadsStr = std::to_wstring(proc.threadCount);
        ListView_SetItemText(hList, i, 4, const_cast<LPWSTR>(threadsStr.c_str()));

        // CPU Usage
        std::wstringstream cpuStream;
        cpuStream << std::fixed << std::setprecision(1) << proc.cpuUsage;
        std::wstring cpuStr = cpuStream.str();
        ListView_SetItemText(hList, i, 5, const_cast<LPWSTR>(cpuStr.c_str()));

        ListView_SetItemText(hList, i, 6, const_cast<LPWSTR>(proc.fullPath.c_str()));
    }

    if (selectedPid != 0) {
        for (int i = 0; i < ListView_GetItemCount(hList); i++) {
            LVITEM lvi;
            ZeroMemory(&lvi, sizeof(LVITEM));
            lvi.iItem = i;
            lvi.mask = LVIF_PARAM;
            ListView_GetItem(hList, &lvi);

            if ((DWORD)lvi.lParam == selectedPid) {
                ListView_SetItemState(hList, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(hList, i, FALSE);
                break;
            }
        }
    }

    for (int i = 0; i < 7; i++) {
        ListView_SetColumnWidth(hList, i, LVSCW_AUTOSIZE_USEHEADER);
    }

    std::wstringstream statusStream;
    statusStream << L"Processes: " << g_processes.size()
        << L" (Filtered: " << displayList.size() << L")";
    UpdateStatusBar(statusStream.str().c_str());
}

// Отображение модулей процесса
void ShowProcessModules(HWND hList, DWORD pid) {
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

// Включение/выключение автообновления
void ToggleAutoRefresh() {
    g_appState.autoRefresh = !g_appState.autoRefresh;
    if (g_appState.autoRefresh) {
        SetTimer(g_hMainWnd, IDT_AUTOREFRESH_TIMER, g_appState.refreshInterval, NULL);
        UpdateStatusBar(L"Auto-refresh: ON");
    }
    else {
        KillTimer(g_hMainWnd, IDT_AUTOREFRESH_TIMER);
        UpdateStatusBar(L"Auto-refresh: OFF");
    }
}

// Применение фильтра
void ApplyFilterToUI() {
    std::wstring filter(256, L'\0');
    GetWindowText(g_hFilterEdit, &filter[0], 256);
    filter.resize(wcslen(filter.c_str()));
    g_appState.filterText = filter;
    RefreshProcessList(g_hProcessList);
}

// Обновление сортировки
void UpdateSorting() {
    RefreshProcessList(g_hProcessList);
}

// Применение стилей к ListView
void ApplyListViewStyle(HWND hListView) {
    // Используем стандартные стили, так как LVS_EX_AUTOSIZECOLUMNS не существует
    ListView_SetExtendedListViewStyle(hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}

// Создание элементов управления главного окна
void CreateMainWindowControls(HWND hWnd) {
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);

    HWND hButtonPanel = CreateWindow(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, rcClient.right, 40,
        hWnd, (HMENU)1000, g_hInstance, NULL);

    int x = 10;
    CreateWindow(L"BUTTON", L"Обновить",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, 5, 80, 30, hWnd, (HMENU)IDC_REFRESH_BTN,
        g_hInstance, NULL);
    x += 90;

    CreateWindow(L"BUTTON", L"Завершить",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, 5, 80, 30, hWnd, (HMENU)IDC_KILL_BTN,
        g_hInstance, NULL);
    x += 90;

    CreateWindow(L"BUTTON", g_appState.autoRefresh ? L"Стоп автообновление" : L"Автообновление",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, 5, 120, 30, hWnd, (HMENU)IDC_AUTOREFRESH_BTN,
        g_hInstance, NULL);
    x += 130;

    // Поле фильтра
    CreateWindow(L"STATIC", L"Фильтр:", WS_CHILD | WS_VISIBLE,
        x, 10, 40, 20, hWnd, NULL, g_hInstance, NULL);
    x += 45;

    g_hFilterEdit = CreateWindow(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        x, 5, 150, 30, hWnd, (HMENU)IDC_FILTER_EDIT,
        g_hInstance, NULL);
    x += 160;

    CreateWindow(L"BUTTON", L"Поиск",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, 5, 80, 30, hWnd, (HMENU)IDC_SEARCH_BTN,
        g_hInstance, NULL);

    g_hTabControl = CreateWindowEx(0, WC_TABCONTROL, L"",
        WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
        0, 40, rcClient.right, rcClient.bottom - 60,
        hWnd, (HMENU)IDC_TAB_CONTROL,
        g_hInstance, NULL);

    TCITEM tie = { 0 };
    tie.mask = TCIF_TEXT;

    const wchar_t* tabs[] = { L"Processes", L"Modules", L"Performance" };
    for (int i = 0; i < 3; i++) {
        tie.pszText = (LPWSTR)tabs[i];
        TabCtrl_InsertItem(g_hTabControl, i, &tie);
    }

    RECT rcTab;
    GetClientRect(g_hTabControl, &rcTab);
    TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

    g_hProcessList = CreateWindowEx(0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left,
        rcTab.bottom - rcTab.top,
        g_hTabControl, (HMENU)IDC_PROCESS_LIST,
        g_hInstance, NULL);

    ApplyListViewStyle(g_hProcessList);

    struct ColumnInfo {
        const wchar_t* name;
        int width;
    } columns[] = {
        { L"PID", 80 },
        { L"Process Name", 200 },
        { L"User", 150 },
        { L"Memory (MB)", 100 },
        { L"Threads", 80 },
        { L"CPU %", 80 },
        { L"Path", 350 }
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

    g_hPerformanceWnd = CreateWindow(L"STATIC", L"Performance metrics will be displayed here",
        WS_CHILD | WS_BORDER | SS_CENTER,
        rcTab.left, rcTab.top,
        rcTab.right - rcTab.left,
        rcTab.bottom - rcTab.top,
        g_hTabControl, NULL, g_hInstance, NULL);

    ShowWindow(g_hModuleList, SW_HIDE);
    ShowWindow(g_hPerformanceWnd, SW_HIDE);

    g_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWnd, NULL, g_hInstance, NULL);

    int parts[] = { 200, 400, 600, 800, -1 };
    SendMessage(g_hStatusBar, SB_SETPARTS, 5, (LPARAM)parts);


    if (!g_hStatusBar) {
        // Обработка ошибки создания статус-бара
        MessageBox(hWnd, L"Failed to create status bar", L"Error", MB_OK | MB_ICONERROR);
    }
}

// Основная процедура окна
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        CreateMainWindowControls(hWnd);
        EnableDebugPrivilege();
        RefreshProcessList(g_hProcessList);
        UpdateStatusBar(L"Ready");
        break;

    case WM_SIZE:
    {
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        HDWP hdwp = BeginDeferWindowPos(5);
        if (!hdwp) {
            // Если BeginDeferWindowPos не удался, выходим
            break;
        }

        if (g_hStatusBar) {
            hdwp = DeferWindowPos(hdwp, g_hStatusBar, NULL,
                0, rcClient.bottom - 20,
                rcClient.right, 20,
                SWP_NOZORDER);
        }

        HWND hButtonPanel = GetDlgItem(hWnd, 1000);
        if (hButtonPanel) {
            hdwp = DeferWindowPos(hdwp, hButtonPanel, NULL,
                0, 0,
                rcClient.right, 40,
                SWP_NOZORDER);
        }

        if (g_hTabControl) {
            hdwp = DeferWindowPos(hdwp, g_hTabControl, NULL,
                0, 40,
                rcClient.right,
                rcClient.bottom - 60,
                SWP_NOZORDER);

            RECT rcTab;
            GetClientRect(g_hTabControl, &rcTab);
            TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

            if (g_hProcessList) {
                hdwp = DeferWindowPos(hdwp, g_hProcessList, NULL,
                    rcTab.left, rcTab.top,
                    rcTab.right - rcTab.left,
                    rcTab.bottom - rcTab.top,
                    SWP_NOZORDER);
            }

            if (g_hModuleList) {
                hdwp = DeferWindowPos(hdwp, g_hModuleList, NULL,
                    rcTab.left, rcTab.top,
                    rcTab.right - rcTab.left,
                    rcTab.bottom - rcTab.top,
                    SWP_NOZORDER);
            }

            if (g_hPerformanceWnd) {
                hdwp = DeferWindowPos(hdwp, g_hPerformanceWnd, NULL,
                    rcTab.left, rcTab.top,
                    rcTab.right - rcTab.left,
                    rcTab.bottom - rcTab.top,
                    SWP_NOZORDER);
            }
        }

        EndDeferWindowPos(hdwp);
        break;
    }

    case WM_TIMER:
        if (wParam == IDT_AUTOREFRESH_TIMER && g_appState.autoRefresh) {
            RefreshProcessList(g_hProcessList);
        }
        break;

    case WM_NOTIFY:
    {
        LPNMHDR lpnmh = (LPNMHDR)lParam;

        if (lpnmh->idFrom == IDC_PROCESS_LIST) {
            if (lpnmh->code == LVN_ITEMCHANGED) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (pnmv->uNewState & LVIS_SELECTED) {
                    // Можно добавить обработку выбора элемента
                }
            }
            else if (lpnmh->code == LVN_COLUMNCLICK) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (g_appState.sortColumn == pnmv->iSubItem) {
                    g_appState.sortAscending = !g_appState.sortAscending;
                }
                else {
                    g_appState.sortColumn = pnmv->iSubItem;
                    g_appState.sortAscending = TRUE;
                }
                UpdateSorting();
            }
        }
        else if (lpnmh->idFrom == IDC_TAB_CONTROL && lpnmh->code == TCN_SELCHANGE) {
            int sel = TabCtrl_GetCurSel(g_hTabControl);

            ShowWindow(g_hProcessList, SW_HIDE);
            ShowWindow(g_hModuleList, SW_HIDE);
            ShowWindow(g_hPerformanceWnd, SW_HIDE);

            switch (sel) {
            case 0: // Processes
                if (g_hProcessList) {
                    ShowWindow(g_hProcessList, SW_SHOW);
                }
                break;
            case 1: // Modules
                if (g_hModuleList) {
                    ShowWindow(g_hModuleList, SW_SHOW);
                }
                break;
            case 2: // Performance
                if (g_hPerformanceWnd) {
                    ShowWindow(g_hPerformanceWnd, SW_SHOW);
                }
                break;
            }
        }
        break;
    }

    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);

        switch (wmId) {
        case IDC_REFRESH_BTN:
            RefreshProcessList(g_hProcessList);
            break;

        case IDC_KILL_BTN:
            KillSelectedProcess();
            break;

        case IDC_AUTOREFRESH_BTN:
            ToggleAutoRefresh();
            break;

        case IDC_SEARCH_BTN:
            ApplyFilterToUI();
            break;

        case IDM_REFRESH:
            RefreshProcessList(g_hProcessList);
            break;

        case IDM_KILL:
            KillSelectedProcess();
            break;

        case IDM_KILL_TREE:
            KillProcessTree();
            break;

        case IDM_PROPERTIES:
            ShowProcessProperties(hWnd);
            break;

        case IDM_MODULES:
            ShowSelectedProcessModules();
            break;

        case IDM_EXPORT:
            DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_EXPORT_DIALOG), hWnd, ExportDialog);
            break;

        case IDM_AUTOREFRESH:
            ToggleAutoRefresh();
            break;

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

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    }

    case WM_CONTEXTMENU:
        if ((HWND)wParam == g_hProcessList) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };

            if (pt.x == -1 && pt.y == -1) {
                GetCursorPos(&pt);
            }

            ShowContextMenu(hWnd, pt.x, pt.y);
            return 0;
        }
        break;

    case WM_DESTROY:
        if (g_appState.autoRefresh) {
            KillTimer(hWnd, IDT_AUTOREFRESH_TIMER);
        }
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Экспорт списка процессов
void ExportProcessList() {
    DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_EXPORT_DIALOG), g_hMainWnd, ExportDialog);
}