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
			// Checking whether the menu has been called for the ListView of processes
			if ((HWND)wParam == g_hProcessList) {
				// Getting the cursor coordinates
				POINT pt;
				pt.x = LOWORD(lParam);
				pt.y = HIWORD(lParam);

				// If coordinates = -1, it means there was a right-click on the element
				if (pt.x == -1 && pt.y == -1) {
					// Getting the selected item
					int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
					if (selected != -1) {
						// Getting the coordinates of the selected element
						RECT rc;
						ListView_GetItemRect(g_hProcessList, selected, &rc, LVIR_BOUNDS);
						pt.x = rc.left;
						pt.y = rc.bottom;
						ClientToScreen(g_hProcessList, &pt);
					}
					else {
						// If nothing is selected, use the current cursor position
						GetCursorPos(&pt);
					}
				}

				ShowContextMenu(hWnd, pt.x, pt.y);
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
					swprintf_s(statusBuffer, L"List updated. Processes: %zu", g_processes.size());
					UpdateStatusBar(statusBuffer); 
				}
				break;

			case IDC_KILL_BTN:
				KillSelectedProcess();
				break;

				// Processing context menu items
			case IDM_PROCESS_MENU + 1:  
				RefreshProcessList(g_hProcessList);
				{
					std::wstring status = L"List updated. Processes: " +
						std::to_wstring(g_processes.size());
					UpdateStatusBar(status.c_str());
				}
				break;

			case IDM_PROCESS_MENU + 2:  // End the process
				KillSelectedProcess();
				break;

			case IDM_PROCESS_MENU + 3:  // Complete the process tree
				MessageBox(hWnd, L"Функция 'Завершить дерево процессов' в разработке",
					L"Информация", MB_OK | MB_ICONINFORMATION);
				break;

			case IDM_PROCESS_MENU + 4:  // Process Properties
				ShowProcessProperties(hWnd);
				break;

			case IDM_PROCESS_MENU + 5:  // Show modules
				ShowSelectedProcessModules();
				break;

			case IDM_PROCESS_MENU + 6:  // Exporting a list
				ExportProcessList();
				break;

			default:
				// Processing other commands
				break;
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

	// Show process properties (stub)
	void ShowProcessProperties(HWND hWnd) {
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) {
			MessageBox(hWnd, L"Выберите процесс для просмотра свойств",
				L"Информация", MB_OK | MB_ICONINFORMATION);
			return;
		}

		wchar_t procName[256];
		ListView_GetItemText(g_hProcessList, selected, 1, procName, 256);

		// Getting the PID
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(LVITEM));
		lvi.iItem = selected;
		lvi.mask = LVIF_PARAM;

		if (ListView_GetItem(g_hProcessList, &lvi)) {
			DWORD pid = (DWORD)lvi.lParam;
			wchar_t msg[512];
			swprintf_s(msg, L"Свойства процесса:\n\nИмя: %s\nPID: %lu", procName, pid);
			MessageBox(hWnd, msg, L"Свойства процесса", MB_OK | MB_ICONINFORMATION);
		}
	}

	// Show the modules of the selected process
	void ShowSelectedProcessModules() {
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) {
			MessageBox(g_hMainWnd, L"Выберите процесс для просмотра модулей",
				L"Информация", MB_OK | MB_ICONINFORMATION);
			return;
		}

		// Getting PID
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(LVITEM));
		lvi.iItem = selected;
		lvi.mask = LVIF_PARAM;

		if (ListView_GetItem(g_hProcessList, &lvi)) {
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
	void ExportProcessList() {
		MessageBox(g_hMainWnd, L"Export function in development",
			L"Info", MB_OK | MB_ICONINFORMATION);
	}

	// A function for displaying the context menu
	void ShowContextMenu(HWND hWnd, int x, int y) {
		HMENU hMenu = CreatePopupMenu();
		if (!hMenu) return;

		// Adding menu items
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 1, L"Update");
		AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 2, L"End the process");
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 3, L"Complete the process tree");
		AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 4, L"Process Properties");
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 5, L"Show modules (DLL)");
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 6, L"Exporting the list...");

		//Show menu
		TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
			x, y, 0, hWnd, NULL);

		DestroyMenu(hMenu);
	}


	//Creating controls in the main window
	
	void CreateMainWindowControls(HWND hWnd) {
		RECT rcClient;
		GetClientRect(hWnd, &rcClient);

		// Creating a panel for buttons ABOVE the Tab Control
		HWND hButtonPanel = CreateWindow(L"STATIC", L"",
			WS_CHILD | WS_VISIBLE | SS_LEFT,
			0, 0, rcClient.right, 30,
			hWnd, NULL, g_hInstance, NULL);

		if (hButtonPanel) {
			// Setting the background color for the button panel (optional)
			SendMessage(hButtonPanel, WM_SETFONT,
				(WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
		}

		// Creating buttons ABOVE the button panel
		CreateWindow(L"BUTTON", L"Update",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			10, 5, 80, 25, hButtonPanel, (HMENU)IDC_REFRESH_BTN,
			g_hInstance, NULL);

		CreateWindow(L"BUTTON", L"Close",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			100, 5, 80, 25, hButtonPanel, (HMENU)IDC_KILL_BTN,
			g_hInstance, NULL);

		// Creating a Tab Control UNDER the button panel
		g_hTabControl = CreateWindowEx(0, WC_TABCONTROL, L"",
			WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
			0, 30, // Top margin = height of the button panel
			rcClient.right, rcClient.bottom - 55, // Minus the height of the button panel and the status of the bar
			hWnd, (HMENU)IDC_TAB_CONTROL,
			g_hInstance, NULL);

		if (!g_hTabControl) {
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

		if (!g_hProcessList) {
			MessageBox(hWnd, L"Failed to create a list of processes", L"Error", MB_OK);
			return;
		}

		ApplyListViewStyle(g_hProcessList);

		//Setting up columns for the process list
		LVCOLUMN lvc;
		ZeroMemory(&lvc, sizeof(LVCOLUMN));
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

		// Creating headings for 6 columns
		wchar_t* columnTitles[] = {
			const_cast<wchar_t*>(L"PID"),
			const_cast<wchar_t*>(L"Process Name"),
			const_cast<wchar_t*>(L"User"),
			const_cast<wchar_t*>(L"Memory (MB)"),
			const_cast<wchar_t*>(L"Threads "),
			const_cast<wchar_t*>(L"Path")
		};

		int columnWidths[] = { 80, 200, 150, 100, 80, 350 };

		// We insert 6 columns
		for (int i = 0; i < 6; i++) {
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

		if (!g_hModuleList) {
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

		if (!g_hStatusBar) {
			MessageBox(hWnd, L"Couldn't create a status bar", L"Error", MB_OK);
			return;
		}

		int parts[] = { 300, 600, -1 };
		SendMessage(g_hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
	}

	//Applying styles to a ListView
	void ApplyListViewStyle(HWND hListView) {
		ListView_SetExtendedListViewStyle(hListView,
			LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

	}

	//Getting a list of processes
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
				ProcessInfo info;
				info.pid = processEntry.th32ProcessID;
				info.parentPid = processEntry.th32ParentProcessID;
				info.name = processEntry.szExeFile;
				info.threadCount = processEntry.cntThreads;

				//Getting additional information
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ,
					FALSE, info.pid);

				if (hProcess) {
					// Full path
					wchar_t path[MAX_PATH];
					if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) {
						info.fullPath = path;
					}

					//Memory usage
					PROCESS_MEMORY_COUNTERS pmc;
					if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
						info.workingSetSize = pmc.WorkingSetSize / (1024 * 1024); // MB
					}

					//Priority
					info.priority = GetPriorityClass(hProcess);

					// User name 
					info.userName = GetProcessUserName(info.pid);

					CloseHandle(hProcess);
				}
				else {
					// If the process could not be opened, we still get the username
					info.userName = GetProcessUserName(info.pid);
				}

				processes.push_back(info);
			} while (Process32NextW(snapshot, &processEntry));
		}

		CloseHandle(snapshot);

		// Sorting by process name
		std::sort(processes.begin(), processes.end(),
			[](const ProcessInfo& a, const ProcessInfo& b) {
				return a.name < b.name;
			});

		return processes;
	}

	// ============ A FUNCTION FOR GETTING THE USERNAME OF A PROCESS ============

	std::wstring GetProcessUserName(DWORD pid) {
		//Special system processes
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

		// Trying to open the process token
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
			DWORD tokenInfoSize = 0;

			// 1. First, we get the buffer size
			GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);

			if (tokenInfoSize > 0) {
				// 2. Allocating memory for information about the token
				PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenInfoSize);
				if (pTokenUser) {
					// 3. Getting information about the token user
					if (GetTokenInformation(hToken, TokenUser, pTokenUser,
						tokenInfoSize, &tokenInfoSize)) {

						wchar_t name[256] = { 0 };
						wchar_t domain[256] = { 0 };
						DWORD nameSize = 256;
						DWORD domainSize = 256;
						SID_NAME_USE sidType;

						// 4. Converting the SID to a readable name
						if (LookupAccountSid(NULL, pTokenUser->User.Sid,
							name, &nameSize, domain, &domainSize, &sidType)) {

							if (domainSize > 0 && wcslen(domain) > 0) {
								username = std::wstring(domain) + L"\\" + name;
							}
							else {
								username = name;
							}
						}
						else {
							//Couldn't convert SID to name
							username = L"SYSTEM";
						}
					}
					free(pTokenUser);
				}
			}
			else {
				// Couldn't get information about the token
				username = L"SYSTEM";
			}

			CloseHandle(hToken);
		}
		else {
			// Couldn't open the token
			username = L"SYSTEM";
		}

		CloseHandle(hProcess);
		return username;
	}


	// Updating the list of processes in the ListView
	void RefreshProcessList(HWND hList) {
		//Clearing the list
		ListView_DeleteAllItems(hList);

		//We get an up-to-date list of processes
		g_processes = GetProcessesList();

		//Filling in the ListView
		for (size_t i = 0; i < g_processes.size(); i++) {
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
			if (proc.workingSetSize > 0) {
				swprintf_s(memoryStr, L"%llu", proc.workingSetSize);
			}
			else {
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
		for (int i = 0; i < 6; i++) {  // 6 columns
			ListView_SetColumnWidth(hList, i, LVSCW_AUTOSIZE_USEHEADER);
		}

		std::wstring status = L"Loaded processes: " + std::to_wstring(g_processes.size());
		UpdateStatusBar(status.c_str());  
	}

	//Showing the modules of the selected process
	void ShowProcessModules(HWND hList, DWORD pid) {
		ListView_DeleteAllItems(hList);

		std::vector<std::wstring> modules;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

		if (snapshot != INVALID_HANDLE_VALUE) {
			MODULEENTRY32W moduleEntry;
			moduleEntry.dwSize = sizeof(MODULEENTRY32W);

			if (Module32FirstW(snapshot, &moduleEntry)) {
				int i = 0;
				do {
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
	void DisplayProcessDetails(DWORD pid) {
		//Here you can add the output to the third tab.
	}

	// Completion of the selected process
	void KillSelectedProcess() {
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) {
			MessageBox(g_hMainWnd, L"Select the process to complete",
				L"Error", MB_ICONWARNING);
			return;
		}

		wchar_t name[256];
		ListView_GetItemText(g_hProcessList, selected, 1, name, 256);

		wchar_t message[512];
		swprintf_s(message, L"End the process \"%s\"?", name);

		if (MessageBox(g_hMainWnd, message, L"Confirm",
			MB_YESNO | MB_ICONQUESTION) == IDYES) {
			// Getting the PID from the ListView correctly
			LVITEM lvi;
			ZeroMemory(&lvi, sizeof(LVITEM));
			lvi.iItem = selected;
			lvi.mask = LVIF_PARAM;

			if (ListView_GetItem(g_hProcessList, &lvi)) {
				DWORD pid = (DWORD)lvi.lParam;

				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
				if (hProcess) {
					if (TerminateProcess(hProcess, 0)) {
						wchar_t statusBuffer[512];
						swprintf_s(statusBuffer, L"The process is completed: %s", name);
						UpdateStatusBar(statusBuffer); 
						RefreshProcessList(g_hProcessList);
					}
					else {
						DWORD error = GetLastError();
						wchar_t errorMsg[256];
						swprintf_s(errorMsg, L"The process could not be completed. Error code: %lu", error);
						MessageBox(g_hMainWnd, errorMsg,
							L"Error", MB_ICONERROR);
					}
					CloseHandle(hProcess);
				}
				else {
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

	//Updating the status of the bar
	void UpdateStatusBar(const wchar_t* text) {
		if (g_hStatusBar) {
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
/*
// Заглушка для main (добавьте в самый конец файла)
#ifdef _DEBUG
// Для отладки: оставляем консоль
	int main() {
		HINSTANCE hInstance = GetModuleHandle(NULL);
		return WinMain(hInstance, NULL, GetCommandLineA(), SW_SHOWDEFAULT);
	}
#else
// Для релиза: без консоли
	int __stdcall WinMainCRTStartup() {
		HINSTANCE hInstance = GetModuleHandle(NULL);
		int result = WinMain(hInstance, NULL, GetCommandLineA(), SW_SHOWDEFAULT);
		ExitProcess(result);
		return result;
	}
#endif*/
