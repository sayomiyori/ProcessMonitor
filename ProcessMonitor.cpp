#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "ProcessMonitor.h"

//Global variables
HWND g_hMainWnd = NULL;
HWND g_hProcessList = NULL;
HWND g_hModuleList = NULL;
HWND g_hTabControl = NULL;
HWND g_hStatusBar = NULL;
std::vector<ProcessInfo> g_processes;
std::map<DWORD, std::vector<std::wstring>> g_processModules;
HINSTANCE g_hInstance;

//Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	//Initializing common controls
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES;
	InitCommonControlsEx(&icex);

	if (!InitApplication(hInstance)) {
		return FALSE;
	}

	if (!InitInstance(hInstance, nCmdShow)) {
		return FALSE;
	}

	//The main message loop
	MSG msg;
	HACCEL hAccelTable = NULL;

	while (GetMessage(&msg, nullptr, 0, 0)) {
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}

//Window Class Registration
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

//Creating main window
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
	g_hInstance = hInstance;

	g_hMainWnd = CreateWindowW(
		L"ProcessMonitorClass",
		L"Windows Process Monitor",
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

//KillProcessTree func
void KillProcessTree() {
	int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
	if (selected == -1) {
		MessageBox(g_hMainWnd, L"Select a process to complete the tree", L"Error", MB_ICONWARNING);
		return;
	}

	//Take Pid selected process
	LVITEM lvi;
	ZeroMemory(&lvi, sizeof(LVITEM));
	lvi.iItem = selected;
	lvi.mask = LVIF_PARAM;

	if (!ListView_GetItem(g_hProcessList, &lvi)) {
		return;
	}

	DWORD targetPid = (DWORD)lvi.lParam;
	wchar_t procName[256];
	ListView_GetItemText(g_hProcessList, selected, 1, procName, 256);

	//confirm query
	wchar_t message[512];
	swprintf_s(message, L"Finish the process tree for \"%s\" (PID: %lu)?\n\All child processes will also be terminated!",
		procName, targetPid);

	if (MessageBox(g_hMainWnd, message, L"Confirm",
		MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
		int killedCount = KillProcessTreeRecursive(targetPid, 0);

		wchar_t status[256];
		swprintf_s(status, L"Complete processes: %d", killedCount);
		UpdateStatusBar(status);

		//Updating process list
		RefreshProcessList(g_hProcessList);
	}

}

int KillProcessTreeRecursive(DWORD parentPid, int depth) {
	int killedCount = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);

	//First, we terminate all child processes

	if (Process32FirstW(snapshot, &pe)) {
		do {
			if (pe.th32ParentProcessID == parentPid) {
				//Recursively terminating child processes
				killedCount += KillProcessTreeRecursive(pe.th32ProcessID, depth + 1);

				//Terminating the current child process
				HANDLE hChild = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
				if (hChild) {
					TerminateProcess(hChild, 0);
					CloseHandle(hChild);
					killedCount++;
				}
			}
			
		} while (Process32NextW(snapshot, &pe));
	}

	//Now we are completing the parent process.
	if (depth > 0) {
		HANDLE hParent = OpenProcess(PROCESS_TERMINATE, FALSE, parentPid);
		if (hParent) {
			TerminateProcess(hParent, 0);
			CloseHandle(hParent);
			killedCount++;
		}
	}

	CloseHandle(snapshot);
	return killedCount;
}

//Main window procedure
	LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message) 
		{
		case WM_CREATE:
			CreateMainWindowControls(hWnd);
			EnableDebugPrivilege();
			RefreshProcessList(g_hProcessList);
			{
				std::wstring status = L"Done. Downloaded processes: " +
					std::to_wstring(g_processes.size());
				UpdateStatusBar(status.c_str());  
			}
			break;

		case WM_SIZE:
		{
			RECT rcClient;
			GetClientRect(hWnd, &rcClient);

			// Place the status bar at the bottom
			if (g_hStatusBar)
			{
				SendMessage(g_hStatusBar, WM_SIZE, 0, 0);

				// Getting the height of the status bar
				RECT rcStatus;
				GetWindowRect(g_hStatusBar, &rcStatus);
				int statusHeight = rcStatus.bottom - rcStatus.top;

				//Find the button panel
				HWND hButtonPanel = FindWindowEx(hWnd, NULL, L"STATIC", NULL);
				int buttonPanelHeight = 0;
				if (hButtonPanel) {
					RECT rcPanel;
					GetWindowRect(hButtonPanel, &rcPanel);
					buttonPanelHeight = rcPanel.bottom - rcPanel.top;

					// Placing the button panel
					SetWindowPos(hButtonPanel, NULL, 0, 0, rcClient.right, buttonPanelHeight, SWP_NOZORDER);
				}

				// Place Tab Control (between the button panel and the status bar)
				if (g_hTabControl)
				{
					SetWindowPos(g_hTabControl, NULL,
						0, buttonPanelHeight,  // Top margin = height of the button panel
						rcClient.right,
						rcClient.bottom - buttonPanelHeight - statusHeight,
						SWP_NOZORDER);

					// Placing the ListView inside the TAB
					RECT rcTab;
					GetClientRect(g_hTabControl, &rcTab);
					TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

					SetWindowPos(g_hProcessList, NULL,
						rcTab.left, rcTab.top,
						rcTab.right - rcTab.left,
						rcTab.bottom - rcTab.top,
						SWP_NOZORDER);

					SetWindowPos(g_hModuleList, NULL,
						rcTab.left, rcTab.top,
						rcTab.right - rcTab.left,
						rcTab.bottom - rcTab.top,
						SWP_NOZORDER);
				}
			}
			break;
		}

		

		case WM_NOTIFY:
		{
			LPNMHDR lpnmh = (LPNMHDR)lParam;

			// ListView click processing
			if (lpnmh->idFrom == IDC_PROCESS_LIST &&
				lpnmh->code == LVN_ITEMCHANGED)
			{
				LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
				if (pnmv->uNewState & LVIS_SELECTED) 
				{
					LVITEM lvi;
					ZeroMemory(&lvi, sizeof(LVITEM));
					lvi.iItem = pnmv->iItem;
					lvi.mask = LVIF_PARAM;
					if (ListView_GetItem(g_hProcessList, &lvi)) {
						DWORD pid = (DWORD)lvi.lParam;
					}
				}
			}

			//Tab change processing
			else if (lpnmh->idFrom == IDC_TAB_CONTROL &&
				lpnmh->code == TCN_SELCHANGE) 
			{
				int sel = TabCtrl_GetCurSel(g_hTabControl);
				if (sel == 0) {
					ShowWindow(g_hProcessList, SW_SHOW);
					ShowWindow(g_hModuleList, SW_HIDE);
				}
				else {
					ShowWindow(g_hProcessList, SW_HIDE);
					ShowWindow(g_hModuleList, SW_SHOW);
				}
			}
			break;
		}

		case WM_CONTEXTMENU:
		{
			// Проверяем, вызвано ли меню для списка процессов
			if ((HWND)wParam == g_hProcessList) {
				POINT pt = { 0, 0 };

				// Если координаты = -1, значит меню вызвано клавишей
				if (lParam == -1) {
					// Получаем выбранный элемент
					int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
					if (selected != -1) {
						// Получаем координаты элемента
						RECT rc;
						ListView_GetItemRect(g_hProcessList, selected, &rc, LVIR_BOUNDS);
						pt.x = rc.left;
						pt.y = rc.bottom;
						ClientToScreen(g_hProcessList, &pt);
					}
					else {
						// Используем текущую позицию курсора
						GetCursorPos(&pt);
					}
				}
				else {
					// Используем переданные координаты
					pt.x = LOWORD(lParam);
					pt.y = HIWORD(lParam);
				}

				ShowContextMenu(hWnd, pt.x, pt.y);
				return 0; // Обработано
			}
			break;
		}
		

		case WM_COMMAND:
		{
			int wmId = LOWORD(wParam);

			switch (wmId) {
			case IDC_REFRESH_BTN:
				RefreshProcessList(g_hProcessList);
				{
					wchar_t statusBuffer[256];
					swprintf_s(statusBuffer, L"Список обновлен. Процессов: %zu", g_processes.size());
					UpdateStatusBar(statusBuffer);
				}
				break;

			case IDC_KILL_BTN:
				KillSelectedProcess();
				break;

				// Обработка пунктов контекстного меню
			case IDM_REFRESH:
				RefreshProcessList(g_hProcessList);
				{
					wchar_t statusBuffer[256];
					swprintf_s(statusBuffer, L"Список обновлен. Процессов: %zu", g_processes.size());
					UpdateStatusBar(statusBuffer);
				}
				break;

			case IDM_KILL:  // Завершить процесс
				KillSelectedProcess();
				break;

			case IDM_KILL_TREE:  // Завершить дерево процессов
				KillProcessTree();
				break;

			case IDM_PROPERTIES:  // Свойства процесса
				ShowProcessProperties(hWnd);
				break;

			case IDM_MODULES:  // Показать модули
				ShowSelectedProcessModules();
				break;

			case IDM_EXPORT:  // Экспорт списка
				ExportProcessList();
				break;

			default:
				return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;
		}
		

		case WM_DESTROY:
			PostQuitMessage(0);
			break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		return 0;
	}

	//Getting detailed information about the process
	ProcessInfo GetDetailedProcessInfo(DWORD pid) {
		ProcessInfo info = {};
		info.pid = pid;

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, pid);

		if (!hProcess) 
		{
			//Try with less rights

			hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		}
		if (hProcess) 
		{
			//Based info from TOOLHELP
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snapshot != INVALID_HANDLE_VALUE)
			{
				PROCESSENTRY32W pe;
				pe.dwSize = sizeof(PROCESSENTRY32W);

				if (Process32FirstW(snapshot, &pe))
				{
					do
					{
						if (pe.th32ProcessID == pid)
						{
							info.name = pe.szExeFile;
							info.parentPid = pe.th32ParentProcessID;
							info.threadCount = pe.cntThreads;
							break;
						}
					} while (Process32NextW(snapshot, &pe));
				}
				CloseHandle(snapshot);
			}
			
		

			//Full path

			wchar_t path[MAX_PATH] = { 0 };
			DWORD pathSize = MAX_PATH;

			if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) 
			{
				info.fullPath = path;
			}
			else if(QueryFullProcessImageNameW(hProcess, 0, path, &pathSize))
			{
				info.fullPath = path;
			}

			//CommandLine
			info.commandLine = GetProcessCommandLine(pid);

			//User
			info.userName = GetProcessUserName(pid);

			//Integrity LVL
			info.integrityLvl = GetProcessIntegrityLevel(pid);

			//Priority
			info.priority = GetPriorityClass(hProcess);

			//Session ID
			ProcessIdToSessionId(pid, &info.sessionId);

			//Creation time
			GetProcessTimes(hProcess, &info.createTime, NULL,
				&info.kernelTime, &info.userTime);

			//Memory usage
			PROCESS_MEMORY_COUNTERS_EX pmc;
			if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) 
			{
				info.workingSetSize = pmc.WorkingSetSize;
				info.privateBytes = pmc.PrivateUsage;
				info.virtualSize = pmc.PagefileUsage;
			}

			//Using cpu (simple calculation)
			static FILETIME prevKernel = { 0 }, prevUser = { 0 };
			info.cpuUsage = CalculateCPUUsage(pid, &prevKernel, &prevUser);

			CloseHandle(hProcess);
		}

		return info;
	}

	//Getting the process command prompt
	std::wstring GetProcessCommandLine(DWORD pid) {
		std::wstring cmdLine = L"Not available";

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, pid);

		if (!hProcess) {
			return cmdLine;
		}


		//Use NtQueryInformationProcess to get the command line
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

			if (NT_SUCCESS(status)) {
				PEB peb;
				SIZE_T bytesRead;

				if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
					RTL_USER_PROCESS_PARAMETERS upp;

					if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) {
						if (upp.CommandLine.Length > 0) {
							wchar_t* buffer = new wchar_t[upp.CommandLine.Length / sizeof(wchar_t) + 1];

							if (ReadProcessMemory(hProcess, upp.CommandLine.Buffer,
								buffer, upp.CommandLine.Length, &bytesRead)) {
								buffer[bytesRead / sizeof(wchar_t)] = L'\0';
								cmdLine = buffer;
							}

							delete[] buffer;
						}
					}
				}
			}
		}

		CloseHandle(hProcess);
		return cmdLine;
	}

	//Getting the process integrity level

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
					else if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID ) {
						integrity = L"Low";
					}
					else if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID &&
						integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
						integrity = L"Medium";
					}
					else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID &&
						integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
						integrity = L"High";
					}
					else if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
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

	//Time formatting
	std::wstring FormatFileTime(FILETIME ft) {
		if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
			return L"N/A";
		}

		FILETIME localFt;
		FileTimeToLocalFileTime(&ft, &localFt);

		SYSTEMTIME st;
		FileTimeToSystemTime(&localFt, &st);

		wchar_t buffer[64];
		swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond);

		return buffer;
	}

	//Formatting the memory size
	std::wstring FormatMemorySize(SIZE_T bytes) {
		const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
		double size = (double)bytes;
		int unitIndex = 0;

		while (size >= 1024.0 && unitIndex < 3) {
			size /= 1024.0;
			unitIndex++;
		}

		wchar_t buffer[32];
		swprintf_s(buffer, L"%.2f %s", size, units[unitIndex]);

		return buffer;
	}

	//Calculation of CPU usage
	double CalculateCPUUsage(DWORD pid, FILETIME* prevKernel, FILETIME* prevUser) 
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProcess) return 0.0;

		FILETIME createTime, exitTime, kernelTime, userTime;
		FILETIME sysIdleTime, sysKernelTime, sysUserTime;

		if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime) ||
			!GetSystemTimes(&sysIdleTime, &sysKernelTime, &sysUserTime)) {
			CloseHandle(hProcess);
			return 0.0;
		}

		// A simple implementation is to return 0 for an example
		CloseHandle(hProcess);
		return 0.0;
	}

	//Process Properties Dialog procedure
	INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
	{
		static DWORD processPid = 0;
		static ProcessInfo procInfo;

		switch (message) 
		{
			case WM_INITDIALOG: 
			{
				processPid = (DWORD)lParam;
				
				//We receive detailed information about the process
				procInfo = GetDetailedProcessInfo(processPid);

				if (procInfo.pid == 0) 
				{
					MessageBox(hDlg, L"Couldn't get information about the process", L"Error",
						MB_OK | MB_ICONERROR);
					EndDialog(hDlg, 0);
					return TRUE;
				}

				//Filling in the dialog fields
				SetDlgItemText(hDlg, IDC_PROP_NAME, procInfo.name.c_str());
				SetDlgItemInt(hDlg, IDC_PROP_PID, procInfo.pid, FALSE);
				SetDlgItemInt(hDlg, IDC_PROP_PARENT_PID, procInfo.parentPid, FALSE);
				SetDlgItemText(hDlg, IDC_PROP_PATH, procInfo.fullPath.c_str());
				SetDlgItemText(hDlg, IDC_PROP_CMD_LINE, procInfo.commandLine.c_str());
				SetDlgItemText(hDlg, IDC_PROP_USER, procInfo.userName.c_str());

				//Priority
				std::wstring priorityStr;
				switch (procInfo.priority) 
				{
					case REALTIME_PRIORITY_CLASS: priorityStr = L"Real-time"; break;
					case HIGH_PRIORITY_CLASS: priorityStr = L"High"; break;
					case ABOVE_NORMAL_PRIORITY_CLASS: priorityStr = L"Above Normal"; break;
					case NORMAL_PRIORITY_CLASS: priorityStr = L"Normal"; break;
					case BELOW_NORMAL_PRIORITY_CLASS: priorityStr = L"Below Normal"; break;
					case IDLE_PRIORITY_CLASS: priorityStr = L"Idle"; break;
					default: priorityStr = L"Unknown"; break;
				}
				SetDlgItemText(hDlg, IDC_PROP_PRIORITY, priorityStr.c_str());

				//Thread and memory
				SetDlgItemInt(hDlg, IDC_PROP_THREADS, procInfo.threadCount, FALSE);

				wchar_t memoryStr[256];
				swprintf_s(memoryStr, L"Working Set: %s\nPrivate Bytes: %s\nVirtual Size: %s",
					FormatMemorySize(procInfo.workingSetSize).c_str(),
					FormatMemorySize(procInfo.privateBytes).c_str(),
					FormatMemorySize(procInfo.virtualSize).c_str());
				SetDlgItemText(hDlg, IDC_PROP_MEMORY, memoryStr);


				//Using CPU
				wchar_t cpuStr[64];
				swprintf_s(cpuStr, L"%.2f%%", procInfo.cpuUsage);
				SetDlgItemText(hDlg, IDC_PROP_CPU_USAGE, cpuStr);

				//Start time
				SetDlgItemText(hDlg, IDC_PROP_START_TIME, FormatFileTime(procInfo.createTime).c_str());

				//Session ID
				SetDlgItemInt(hDlg, IDC_PROP_SESSION_ID, procInfo.sessionId, FALSE);

				//Integrity level
				SetDlgItemText(hDlg, IDC_PROP_INTEGRITY, procInfo.integrityLvl.c_str());

				//Setting the window title
				wchar_t title[256];
				swprintf_s(title, L"Threads Properties: %s (PID: %lu)",
					procInfo.name.c_str(), procInfo.pid);
				SetWindowText(hDlg, title);


				//Setting Icon
				HICON hIcon = LoadIcon(NULL, IDI_APPLICATION);
				SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

				return TRUE;
			}

			case WM_COMMAND:
				if (LOWORD(wParam) == IDC_CLOSE_BTN || LOWORD(wParam) == IDCANCEL) 
				{
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

	// Show process properties 
	void ShowProcessProperties(HWND hParent) 
	{
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) 
		{
			MessageBox(hParent, L"Select a process to view the properties",
				L"Information", MB_OK | MB_ICONINFORMATION);
			return;
		}

		// Getting the PID
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(LVITEM));
		lvi.iItem = selected;
		lvi.mask = LVIF_PARAM;

		if (ListView_GetItem(g_hProcessList, &lvi)) 
		{
			DWORD pid = (DWORD)lvi.lParam;
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_PROPERTIES_DIALOG),
				hParent, PropertiesDialog, (LPARAM)pid);
		}
	}

	// Show the modules of the selected process
	void ShowSelectedProcessModules() 
	{
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) 
		{
			MessageBox(g_hMainWnd, L"Выберите процесс для просмотра модулей",
				L"Информация", MB_OK | MB_ICONINFORMATION);
			return;
		}

		// Getting PID
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(LVITEM));
		lvi.iItem = selected;
		lvi.mask = LVIF_PARAM;

		if (ListView_GetItem(g_hProcessList, &lvi)) 
		{
			DWORD pid = (DWORD)lvi.lParam;
			// Switch to the modules tab
			TabCtrl_SetCurSel(g_hTabControl, 1);
			ShowProcessModules(g_hModuleList, pid);

			// Showing modules and hiding processes
			ShowWindow(g_hProcessList, SW_HIDE);
			ShowWindow(g_hModuleList, SW_SHOW);

			// Updating status
			std::wstring status = L"Process Modules PID: " + std::to_wstring(pid);
			UpdateStatusBar(status.c_str());
		}
	}

	// Exporting a list of processes (stub)
	void ExportProcessList() 
	{
		MessageBox(g_hMainWnd, L"Export function in development",
			L"Info", MB_OK | MB_ICONINFORMATION);
	}

	// A function for displaying the context menu
	void ShowContextMenu(HWND hWnd, int x, int y) 
	{
		HMENU hMenu = CreatePopupMenu();
		if (!hMenu) return;

		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		BOOL hasSelecetion = (selected != -1);

		AppendMenu(hMenu, MF_STRING, IDM_REFRESH, L"Update");
		AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
		if (hasSelecetion) {
			AppendMenu(hMenu, MF_STRING, IDM_KILL, L"End the process");
			AppendMenu(hMenu, MF_STRING, IDM_KILL_TREE, L"Complete the process tree");
			AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
			AppendMenu(hMenu, MF_STRING, IDM_PROPERTIES, L"Process Properties");
			AppendMenu(hMenu, MF_STRING, IDM_MODULES, L"Show modules (DLL)");
		}
		else {
			AppendMenu(hMenu, MF_STRING, IDM_KILL, L"End the process");
			AppendMenu(hMenu, MF_STRING, IDM_KILL_TREE, L"Complete the process tree");
			AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
			AppendMenu(hMenu, MF_STRING, IDM_PROPERTIES, L"Process Properties");
			AppendMenu(hMenu, MF_STRING, IDM_MODULES, L"Show modules (DLL)");
		}
		AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenu(hMenu, MF_STRING, IDM_EXPORT, L"Exporting the list...");

		SetForegroundWindow(hWnd);
		TrackPopupMenu(hMenu,
			TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_TOPALIGN,
			x, y, 0, hWnd, NULL);
		PostMessage(hWnd, WM_NULL, 0, 0);  // Сбрасываем состояние меню

		DestroyMenu(hMenu);
	}


	//Creating controls in the main window
	
	void CreateMainWindowControls(HWND hWnd) 
	{
		RECT rcClient;
		GetClientRect(hWnd, &rcClient);

		// Creating a panel for buttons ABOVE the Tab Control
		HWND hButtonPanel = CreateWindow(L"STATIC", L"",
			WS_CHILD | WS_VISIBLE | SS_LEFT,
			0, 0, rcClient.right, 30,
			hWnd, NULL, g_hInstance, NULL);

		if (hButtonPanel) 
		{
			// Setting the background color for the button panel (optional)
			SendMessage(hButtonPanel, WM_SETFONT,
				(WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
		}

		// Creating buttons ABOVE the button panel
		CreateWindow(L"BUTTON", L"Update",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			10, 5, 80, 25, hWnd, (HMENU)IDC_REFRESH_BTN,
			g_hInstance, NULL);

		CreateWindow(L"BUTTON", L"Close",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			100, 5, 80, 25, hWnd, (HMENU)IDC_KILL_BTN,
			g_hInstance, NULL);

		// Creating a Tab Control UNDER the button panel
		g_hTabControl = CreateWindowEx(0, WC_TABCONTROL, L"",
			WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
			0, 30, // Top margin = height of the button panel
			rcClient.right, rcClient.bottom - 55, // Minus the height of the button panel and the status of the bar
			hWnd, (HMENU)IDC_TAB_CONTROL,
			g_hInstance, NULL);

		if (!g_hTabControl) 
		{
			MessageBox(hWnd, L"Couldn't create Tab Control", L"Error", MB_OK);
			return;
		}

		// Adding tabs
		TCITEM tie;
		ZeroMemory(&tie, sizeof(TCITEM));
		tie.mask = TCIF_TEXT;

		wchar_t tabProcesses[] = L"Processes";
		wchar_t tabModules[] = L"Modules (DLL)";

		tie.pszText = tabProcesses;
		TabCtrl_InsertItem(g_hTabControl, 0, &tie);

		tie.pszText = tabModules;
		TabCtrl_InsertItem(g_hTabControl, 1, &tie);

		// Creating a ListView for processes INSIDE Tab Control
		RECT rcTab;
		GetClientRect(g_hTabControl, &rcTab);
		TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);

		g_hProcessList = CreateWindowEx(0, WC_LISTVIEW, L"",
			WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
			rcTab.left, rcTab.top,
			rcTab.right - rcTab.left,
			rcTab.bottom - rcTab.top,
			g_hTabControl, (HMENU)IDC_PROCESS_LIST,
			g_hInstance, NULL);

		if (!g_hProcessList) 
		{
			MessageBox(hWnd, L"Failed to create a list of processes", L"Error", MB_OK);
			return;
		}

		ApplyListViewStyle(g_hProcessList);

		//Setting up columns for the process list
		LVCOLUMN lvc;
		ZeroMemory(&lvc, sizeof(LVCOLUMN));
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

		// Creating headings for 6 columns
		wchar_t* columnTitles[] = 
		{
			const_cast<wchar_t*>(L"PID"),
			const_cast<wchar_t*>(L"Process Name"),
			const_cast<wchar_t*>(L"User"),
			const_cast<wchar_t*>(L"Memory (MB)"),
			const_cast<wchar_t*>(L"Threads "),
			const_cast<wchar_t*>(L"Path")
		};

		int columnWidths[] = { 80, 200, 150, 100, 80, 350 };

		// We insert 6 columns
		for (int i = 0; i < 6; i++) 
		{
			lvc.iSubItem = i;
			lvc.pszText = columnTitles[i];
			lvc.cx = columnWidths[i];
			lvc.fmt = LVCFMT_LEFT;
			ListView_InsertColumn(g_hProcessList, i, &lvc);
		}

		// Creating a ListView for modules (hidden for now)
		g_hModuleList = CreateWindowEx(0, WC_LISTVIEW, L"",
			WS_CHILD | WS_BORDER | LVS_REPORT,
			rcTab.left, rcTab.top,
			rcTab.right - rcTab.left,
			rcTab.bottom - rcTab.top,
			g_hTabControl, (HMENU)IDC_MODULE_LIST,
			g_hInstance, NULL);

		if (!g_hModuleList) 
		{
			MessageBox(hWnd, L"Couldn't create a list of modules", L"Error", MB_OK);
			return;
		}

		ApplyListViewStyle(g_hModuleList);

		// Setting up the speakers for the modules (2 speakers)
		wchar_t colModuleName[] = L"Module Name";
		wchar_t colModulePath[] = L"Path";

		lvc.iSubItem = 0;
		lvc.pszText = colModuleName;
		lvc.cx = 250;
		ListView_InsertColumn(g_hModuleList, 0, &lvc);

		lvc.iSubItem = 1;
		lvc.pszText = colModulePath;
		lvc.cx = 500;
		ListView_InsertColumn(g_hModuleList, 1, &lvc);

		// Hiding the modules initially
		ShowWindow(g_hModuleList, SW_HIDE);

		// Creating a status bar
		g_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
			WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
			0, 0, 0, 0, hWnd, NULL, g_hInstance, NULL);

		if (!g_hStatusBar) 
		{
			MessageBox(hWnd, L"Couldn't create a status bar", L"Error", MB_OK);
			return;
		}

		int parts[] = { 300, 600, -1 };
		SendMessage(g_hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
	}

	//Applying styles to a ListView
	void ApplyListViewStyle(HWND hListView) 
	{
		ListView_SetExtendedListViewStyle(hListView,
			LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

	}

	//Getting a list of processes
	std::vector<ProcessInfo> GetProcessesList() 
	{
		std::vector<ProcessInfo> processes;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) 
		{
			return processes;
		}

		PROCESSENTRY32W processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(snapshot, &processEntry)) 
		{
			do {
				ProcessInfo info;
				info.pid = processEntry.th32ProcessID;
				info.parentPid = processEntry.th32ParentProcessID;
				info.name = processEntry.szExeFile;
				info.threadCount = processEntry.cntThreads;

				//Getting additional information
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ,
					FALSE, info.pid);

				if (hProcess) 
				{
					// Full path
					wchar_t path[MAX_PATH];
					if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) 
					{
						info.fullPath = path;
					}

					//Memory usage
					PROCESS_MEMORY_COUNTERS pmc;
					if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) 
					{
						info.workingSetSize = pmc.WorkingSetSize / (1024 * 1024); // MB
					}

					//Priority
					info.priority = GetPriorityClass(hProcess);

					// User name 
					info.userName = GetProcessUserName(info.pid);

					CloseHandle(hProcess);
				}
				else 
				{
					// If the process could not be opened, we still get the username
					info.userName = GetProcessUserName(info.pid);
				}

				processes.push_back(info);
			} while (Process32NextW(snapshot, &processEntry));
		}

		CloseHandle(snapshot);

		// Sorting by process name
		std::sort(processes.begin(), processes.end(),
			[](const ProcessInfo& a, const ProcessInfo& b) 
			{
				return a.name < b.name;
			});

		return processes;
	}

	// ============ A FUNCTION FOR GETTING THE USERNAME OF A PROCESS ============

	std::wstring GetProcessUserName(DWORD pid) 
	{
		//Special system processes
		if (pid == 0) return L"SYSTEM (Idle)";
		if (pid == 4) return L"SYSTEM";

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProcess) 
		{
			DWORD error = GetLastError();
			if (error == ERROR_ACCESS_DENIED) 
			{
				return L"SYSTEM";
			}
			return L"Access Denied";
		}

		HANDLE hToken = NULL;
		std::wstring username = L"Unknown";

		// Trying to open the process token
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
		{
			DWORD tokenInfoSize = 0;

			// 1. First, we get the buffer size
			GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);

			if (tokenInfoSize > 0) 
			{
				// 2. Allocating memory for information about the token
				PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenInfoSize);
				if (pTokenUser) 
				{
					// 3. Getting information about the token user
					if (GetTokenInformation(hToken, TokenUser, pTokenUser,
						tokenInfoSize, &tokenInfoSize)) 
					{

						wchar_t name[256] = { 0 };
						wchar_t domain[256] = { 0 };
						DWORD nameSize = 256;
						DWORD domainSize = 256;
						SID_NAME_USE sidType;

						// 4. Converting the SID to a readable name
						if (LookupAccountSid(NULL, pTokenUser->User.Sid,
							name, &nameSize, domain, &domainSize, &sidType)) 
						{

							if (domainSize > 0 && wcslen(domain) > 0) 
							{
								username = std::wstring(domain) + L"\\" + name;
							}
							else 
							{
								username = name;
							}
						}
						else 
						{
							//Couldn't convert SID to name
							username = L"SYSTEM";
						}
					}
					free(pTokenUser);
				}
			}
			else 
			{
				// Couldn't get information about the token
				username = L"SYSTEM";
			}

			CloseHandle(hToken);
		}
		else 
		{
			// Couldn't open the token
			username = L"SYSTEM";
		}

		CloseHandle(hProcess);
		return username;
	}


	// Updating the list of processes in the ListView
	void RefreshProcessList(HWND hList) 
	{
		//Clearing the list
		ListView_DeleteAllItems(hList);

		//We get an up-to-date list of processes
		g_processes = GetProcessesList();

		//Filling in the ListView
		for (size_t i = 0; i < g_processes.size(); i++) 
		{
			const ProcessInfo& proc = g_processes[i];

			LVITEM lvi;
			ZeroMemory(&lvi, sizeof(LVITEM));  // Important: we reset the structure
			lvi.mask = LVIF_TEXT | LVIF_PARAM;
			lvi.iItem = (int)i;
			lvi.iSubItem = 0;
			lvi.pszText = (LPWSTR)std::to_wstring(proc.pid).c_str();
			lvi.lParam = proc.pid;  // Saving the PID in lParam
			ListView_InsertItem(hList, &lvi);

			// Column 1: Process name
			ListView_SetItemText(hList, i, 1, (LPWSTR)proc.name.c_str());

			// Column 2: User name (using a new feature)
			std::wstring username = GetProcessUserName(proc.pid);
			ListView_SetItemText(hList, i, 2, (LPWSTR)username.c_str());

			// Column 3: Memory (MB)
			wchar_t memoryStr[32];
			if (proc.workingSetSize > 0) 
			{
				swprintf_s(memoryStr, L"%llu", proc.workingSetSize);
			}
			else 
			{
				wcscpy_s(memoryStr, L"0");
			}
			ListView_SetItemText(hList, i, 3, memoryStr);

			//Column 4: Flows
			wchar_t threadsStr[32];
			swprintf_s(threadsStr, L"%lu", proc.threadCount);
			ListView_SetItemText(hList, i, 4, threadsStr);

			// Column 5: The path
			ListView_SetItemText(hList, i, 5, (LPWSTR)proc.fullPath.c_str());
		}

		//Auto-adjusting column widths
		for (int i = 0; i < 6; i++) 
		{  // 6 columns
			ListView_SetColumnWidth(hList, i, LVSCW_AUTOSIZE_USEHEADER);
		}

		std::wstring status = L"Loaded processes: " + std::to_wstring(g_processes.size());
		UpdateStatusBar(status.c_str());  
	}

	//Showing the modules of the selected process
	void ShowProcessModules(HWND hList, DWORD pid) 
	{
		ListView_DeleteAllItems(hList);

		std::vector<std::wstring> modules;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

		if (snapshot != INVALID_HANDLE_VALUE) 
		{
			MODULEENTRY32W moduleEntry;
			moduleEntry.dwSize = sizeof(MODULEENTRY32W);

			if (Module32FirstW(snapshot, &moduleEntry)) 
			{
				int i = 0;
				do 
				{
					LVITEM lvi;
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
	}

	//Displaying detailed information about the process
	void DisplayProcessDetails(DWORD pid) 
	{
		//Here you can add the output to the third tab.
	}

	// Completion of the selected process
	void KillSelectedProcess() 
	{
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) 
		{
			MessageBox(g_hMainWnd, L"Select the process to complete",
				L"Error", MB_ICONWARNING);
			return;
		}

		wchar_t name[256];
		ListView_GetItemText(g_hProcessList, selected, 1, name, 256);

		wchar_t message[512];
		swprintf_s(message, L"End the process \"%s\"?", name);

		if (MessageBox(g_hMainWnd, message, L"Confirm",
			MB_YESNO | MB_ICONQUESTION) == IDYES) 
		{
			// Getting the PID from the ListView correctly
			LVITEM lvi;
			ZeroMemory(&lvi, sizeof(LVITEM));
			lvi.iItem = selected;
			lvi.mask = LVIF_PARAM;

			if (ListView_GetItem(g_hProcessList, &lvi)) 
			{
				DWORD pid = (DWORD)lvi.lParam;

				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
				if (hProcess) 
				{
					if (TerminateProcess(hProcess, 0)) 
					{
						wchar_t statusBuffer[512];
						swprintf_s(statusBuffer, L"The process is completed: %s", name);
						UpdateStatusBar(statusBuffer); 
						RefreshProcessList(g_hProcessList);
					}
					else 
					{
						DWORD error = GetLastError();
						wchar_t errorMsg[256];
						swprintf_s(errorMsg, L"The process could not be completed. Error code: %lu", error);
						MessageBox(g_hMainWnd, errorMsg,
							L"Error", MB_ICONERROR);
					}
					CloseHandle(hProcess);
				}
				else 
				{
					DWORD error = GetLastError();
					wchar_t errorMsg[256];
					swprintf_s(errorMsg, L"The process could not be opened. Error code: %lu", error);
					MessageBox(g_hMainWnd, errorMsg,
						L"Error", MB_ICONERROR);
				}
			}
		}
	}

	//Enabling debugging privileges
	BOOL EnableDebugPrivilege() 
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES tp;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
		{
			return FALSE;
		}

		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) 
		{
			CloseHandle(hToken);
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		CloseHandle(hToken);

		return result && GetLastError() == ERROR_SUCCESS;

	}

	//Updating the status of the bar
	void UpdateStatusBar(const wchar_t* text) 
	{
		if (g_hStatusBar) 
		{
			SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)text);
			SendMessage(g_hStatusBar, SB_SETTEXT, 1, (LPARAM)L"Windows Process Monitor v1.0");

			// Updating the date/time in the third part
			SYSTEMTIME st;
			GetLocalTime(&st);
			wchar_t timeStr[64];
			swprintf_s(timeStr, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
			SendMessage(g_hStatusBar, SB_SETTEXT, 2, (LPARAM)timeStr); 
		}
	}

