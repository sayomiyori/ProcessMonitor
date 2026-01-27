#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ТОЛЬКО библиотеки, НИКАКИХ pragma для линкера
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

//Глобальные переменные 
HWND g_hMainWnd = NULL;
HWND g_hProcessList = NULL;
HWND g_hModuleList = NULL;
HWND g_hTabControl = NULL;
HWND g_hStatusBar = NULL;
std::vector<ProcessInfo> g_processes;
std::map<DWORD, std::vector<std::wstring>> g_processModules;
HINSTANCE g_hInstance;

//Точка входа
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	//Инициализируем common controls
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

	//Главный цикл сообщений
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

//Регистрация класса окна
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

//Создание main window
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

	ShowWindow(g_hMainWnd, nCmdShow);  // <-- ДОБАВЬТЕ
	UpdateWindow(g_hMainWnd);          // <-- ДОБАВЬТЕ
	return TRUE;
}

//Главная оконная процедура
	LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message) 
		{
		case WM_CREATE:
			CreateMainWindowControls(hWnd);
			EnableDebugPrivilege();
			RefreshProcessList(g_hProcessList);
			{
				std::wstring status = L"Готово. Загружено процессов: " +
					std::to_wstring(g_processes.size());
				UpdateStatusBar(status.c_str());  // <-- ИСПРАВЛЕНО: добавлено .c_str()
			}
			break;

		case WM_SIZE:
		{
			RECT rcClient;
			GetClientRect(hWnd, &rcClient);

			// Размещаем статус бар внизу
			if (g_hStatusBar)
			{
				SendMessage(g_hStatusBar, WM_SIZE, 0, 0);

				// Получаем высоту статус-бара
				RECT rcStatus;
				GetWindowRect(g_hStatusBar, &rcStatus);
				int statusHeight = rcStatus.bottom - rcStatus.top;

				// Находим панель кнопок
				HWND hButtonPanel = FindWindowEx(hWnd, NULL, L"STATIC", NULL);
				int buttonPanelHeight = 0;
				if (hButtonPanel) {
					RECT rcPanel;
					GetWindowRect(hButtonPanel, &rcPanel);
					buttonPanelHeight = rcPanel.bottom - rcPanel.top;

					// Размещаем панель кнопок
					SetWindowPos(hButtonPanel, NULL, 0, 0, rcClient.right, buttonPanelHeight, SWP_NOZORDER);
				}

				// Размещаем Tab Control (между панелью кнопок и статус-баром)
				if (g_hTabControl)
				{
					SetWindowPos(g_hTabControl, NULL,
						0, buttonPanelHeight,  // Отступ сверху = высота панели кнопок
						rcClient.right,
						rcClient.bottom - buttonPanelHeight - statusHeight,
						SWP_NOZORDER);

					// Размещаем ListView внутри TAB
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

			// Обработка кликов по ListView
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

			//Обработка смены вкладок
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
			// Проверяем, было ли меню вызвано для ListView процессов
			if ((HWND)wParam == g_hProcessList) {
				// Получаем координаты курсора
				POINT pt;
				pt.x = LOWORD(lParam);
				pt.y = HIWORD(lParam);

				// Если координаты = -1, значит было нажатие правой кнопкой на элементе
				if (pt.x == -1 && pt.y == -1) {
					// Получаем выбранный элемент
					int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
					if (selected != -1) {
						// Получаем координаты выбранного элемента
						RECT rc;
						ListView_GetItemRect(g_hProcessList, selected, &rc, LVIR_BOUNDS);
						pt.x = rc.left;
						pt.y = rc.bottom;
						ClientToScreen(g_hProcessList, &pt);
					}
					else {
						// Если ничего не выбрано, используем текущую позицию курсора
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
					swprintf_s(statusBuffer, L"Список обновлен. Процессов: %zu", g_processes.size());
					UpdateStatusBar(statusBuffer);  // Правильно - передаем wchar_t*
				}
				break;

			case IDC_KILL_BTN:
				KillSelectedProcess();
				break;

				// Обработка пунктов контекстного меню
			case IDM_PROCESS_MENU + 1:  // Обновить
				RefreshProcessList(g_hProcessList);
				{
					std::wstring status = L"Список обновлен. Процессов: " +
						std::to_wstring(g_processes.size());
					UpdateStatusBar(status.c_str());
				}
				break;

			case IDM_PROCESS_MENU + 2:  // Завершить процесс
				KillSelectedProcess();
				break;

			case IDM_PROCESS_MENU + 3:  // Завершить дерево процессов
				MessageBox(hWnd, L"Функция 'Завершить дерево процессов' в разработке",
					L"Информация", MB_OK | MB_ICONINFORMATION);
				break;

			case IDM_PROCESS_MENU + 4:  // Свойства процесса
				ShowProcessProperties(hWnd);
				break;

			case IDM_PROCESS_MENU + 5:  // Показать модули
				ShowSelectedProcessModules();
				break;

			case IDM_PROCESS_MENU + 6:  // Экспорт списка
				ExportProcessList();
				break;

			default:
				// Обработка других команд
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

	// Показать свойства процесса (заглушка)
	void ShowProcessProperties(HWND hWnd) {
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) {
			MessageBox(hWnd, L"Выберите процесс для просмотра свойств",
				L"Информация", MB_OK | MB_ICONINFORMATION);
			return;
		}

		wchar_t procName[256];
		ListView_GetItemText(g_hProcessList, selected, 1, procName, 256);

		// Получаем PID
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

	// Показать модули выбранного процесса
	void ShowSelectedProcessModules() {
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) {
			MessageBox(g_hMainWnd, L"Выберите процесс для просмотра модулей",
				L"Информация", MB_OK | MB_ICONINFORMATION);
			return;
		}

		// Получаем PID
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(LVITEM));
		lvi.iItem = selected;
		lvi.mask = LVIF_PARAM;

		if (ListView_GetItem(g_hProcessList, &lvi)) {
			DWORD pid = (DWORD)lvi.lParam;
			// Переключаемся на вкладку модулей
			TabCtrl_SetCurSel(g_hTabControl, 1);
			ShowProcessModules(g_hModuleList, pid);

			// Показываем модули и скрываем процессы
			ShowWindow(g_hProcessList, SW_HIDE);
			ShowWindow(g_hModuleList, SW_SHOW);

			// Обновляем статус
			std::wstring status = L"Модули процесса PID: " + std::to_wstring(pid);
			UpdateStatusBar(status.c_str());
		}
	}

	// Экспорт списка процессов (заглушка)
	void ExportProcessList() {
		MessageBox(g_hMainWnd, L"Функция экспорта в разработке",
			L"Информация", MB_OK | MB_ICONINFORMATION);
	}

	// Функция для отображения контекстного меню
	void ShowContextMenu(HWND hWnd, int x, int y) {
		HMENU hMenu = CreatePopupMenu();
		if (!hMenu) return;

		// Добавляем пункты меню
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 1, L"Обновить");
		AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 2, L"Завершить процесс");
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 3, L"Завершить дерево процессов");
		AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 4, L"Свойства процесса");
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 5, L"Показать модули (DLL)");
		AppendMenu(hMenu, MF_STRING, IDM_PROCESS_MENU + 6, L"Экспорт списка...");

		// Показываем меню
		TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
			x, y, 0, hWnd, NULL);

		DestroyMenu(hMenu);
	}


	//Создание элементов управления в главном окне
	//Создание элементов управления в главном окне
	void CreateMainWindowControls(HWND hWnd) {
		RECT rcClient;
		GetClientRect(hWnd, &rcClient);

		// Создаем панель для кнопок НАД Tab Control
		HWND hButtonPanel = CreateWindow(L"STATIC", L"",
			WS_CHILD | WS_VISIBLE | SS_LEFT,
			0, 0, rcClient.right, 30,
			hWnd, NULL, g_hInstance, NULL);

		if (hButtonPanel) {
			// Устанавливаем цвет фона для панели кнопок (опционально)
			SendMessage(hButtonPanel, WM_SETFONT,
				(WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
		}

		// Создаем кнопки НАД панели кнопок
		CreateWindow(L"BUTTON", L"Обновить",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			10, 5, 80, 25, hButtonPanel, (HMENU)IDC_REFRESH_BTN,
			g_hInstance, NULL);

		CreateWindow(L"BUTTON", L"Завершить",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			100, 5, 80, 25, hButtonPanel, (HMENU)IDC_KILL_BTN,
			g_hInstance, NULL);

		// Создаем Tab Control ПОД панелью кнопок
		g_hTabControl = CreateWindowEx(0, WC_TABCONTROL, L"",
			WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
			0, 30,  // Отступ сверху = высота панели кнопок
			rcClient.right, rcClient.bottom - 55, // Минус высота панели кнопок и статус бара
			hWnd, (HMENU)IDC_TAB_CONTROL,
			g_hInstance, NULL);

		if (!g_hTabControl) {
			MessageBox(hWnd, L"Не удалось создать Tab Control", L"Ошибка", MB_OK);
			return;
		}

		// Добавляем вкладки
		TCITEM tie;
		ZeroMemory(&tie, sizeof(TCITEM));
		tie.mask = TCIF_TEXT;

		wchar_t tabProcesses[] = L"Процессы";
		wchar_t tabModules[] = L"Модули (DLL)";

		tie.pszText = tabProcesses;
		TabCtrl_InsertItem(g_hTabControl, 0, &tie);

		tie.pszText = tabModules;
		TabCtrl_InsertItem(g_hTabControl, 1, &tie);

		// Создаем ListView для процессов ВНУТРИ Tab Control
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
			MessageBox(hWnd, L"Не удалось создать список процессов", L"Ошибка", MB_OK);
			return;
		}

		ApplyListViewStyle(g_hProcessList);

		// Настраиваем колонки для списка процессов
		LVCOLUMN lvc;
		ZeroMemory(&lvc, sizeof(LVCOLUMN));
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

		// Создаем заголовки для 6 колонок
		wchar_t* columnTitles[] = {
			const_cast<wchar_t*>(L"PID"),
			const_cast<wchar_t*>(L"Имя процесса"),
			const_cast<wchar_t*>(L"Пользователь"),
			const_cast<wchar_t*>(L"Память (MB)"),
			const_cast<wchar_t*>(L"Потоки"),
			const_cast<wchar_t*>(L"Путь")
		};

		int columnWidths[] = { 80, 200, 150, 100, 80, 350 };

		// Вставляем 6 колонок
		for (int i = 0; i < 6; i++) {
			lvc.iSubItem = i;
			lvc.pszText = columnTitles[i];
			lvc.cx = columnWidths[i];
			lvc.fmt = LVCFMT_LEFT;
			ListView_InsertColumn(g_hProcessList, i, &lvc);
		}

		// Создаем ListView для модулей (скрытый пока)
		g_hModuleList = CreateWindowEx(0, WC_LISTVIEW, L"",
			WS_CHILD | WS_BORDER | LVS_REPORT,
			rcTab.left, rcTab.top,
			rcTab.right - rcTab.left,
			rcTab.bottom - rcTab.top,
			g_hTabControl, (HMENU)IDC_MODULE_LIST,
			g_hInstance, NULL);

		if (!g_hModuleList) {
			MessageBox(hWnd, L"Не удалось создать список модулей", L"Ошибка", MB_OK);
			return;
		}

		ApplyListViewStyle(g_hModuleList);

		// Настраиваем колонки для модулей (2 колонки)
		wchar_t colModuleName[] = L"Имя модуля";
		wchar_t colModulePath[] = L"Путь";

		lvc.iSubItem = 0;
		lvc.pszText = colModuleName;
		lvc.cx = 250;
		ListView_InsertColumn(g_hModuleList, 0, &lvc);

		lvc.iSubItem = 1;
		lvc.pszText = colModulePath;
		lvc.cx = 500;
		ListView_InsertColumn(g_hModuleList, 1, &lvc);

		// Скрываем модули изначально
		ShowWindow(g_hModuleList, SW_HIDE);

		// Создаем статус бар
		g_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
			WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
			0, 0, 0, 0, hWnd, NULL, g_hInstance, NULL);

		if (!g_hStatusBar) {
			MessageBox(hWnd, L"Не удалось создать статус бар", L"Ошибка", MB_OK);
			return;
		}

		int parts[] = { 300, 600, -1 };
		SendMessage(g_hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
	}

	//Применение стилей к ListView
	void ApplyListViewStyle(HWND hListView) {
		ListView_SetExtendedListViewStyle(hListView,
			LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

	}

	//Получение списка процессов
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

				// Получаем дополнительную информацию
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ,
					FALSE, info.pid);

				if (hProcess) {
					// Полный путь
					wchar_t path[MAX_PATH];
					if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) {
						info.fullPath = path;
					}

					// Использование памяти
					PROCESS_MEMORY_COUNTERS pmc;
					if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
						info.workingSetSize = pmc.WorkingSetSize / (1024 * 1024); // MB
					}

					// Приоритет
					info.priority = GetPriorityClass(hProcess);

					// Имя пользователя (добавлено)
					info.userName = GetProcessUserName(info.pid);

					CloseHandle(hProcess);
				}
				else {
					// Если не удалось открыть процесс, все равно получаем имя пользователя
					info.userName = GetProcessUserName(info.pid);
				}

				processes.push_back(info);
			} while (Process32NextW(snapshot, &processEntry));
		}

		CloseHandle(snapshot);

		// Сортируем по имени процесса
		std::sort(processes.begin(), processes.end(),
			[](const ProcessInfo& a, const ProcessInfo& b) {
				return a.name < b.name;
			});

		return processes;
	}

	// ============ ФУНКЦИЯ ДЛЯ ПОЛУЧЕНИЯ ИМЕНИ ПОЛЬЗОВАТЕЛЯ ПРОЦЕССА ============

	std::wstring GetProcessUserName(DWORD pid) {
		// Специальные системные процессы
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

		// Пытаемся открыть токен процесса
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
			DWORD tokenInfoSize = 0;

			// 1. Сначала получаем размер буфера
			GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);

			if (tokenInfoSize > 0) {
				// 2. Выделяем память для информации о токене
				PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(tokenInfoSize);
				if (pTokenUser) {
					// 3. Получаем информацию о пользователе токена
					if (GetTokenInformation(hToken, TokenUser, pTokenUser,
						tokenInfoSize, &tokenInfoSize)) {

						wchar_t name[256] = { 0 };
						wchar_t domain[256] = { 0 };
						DWORD nameSize = 256;
						DWORD domainSize = 256;
						SID_NAME_USE sidType;

						// 4. Преобразуем SID в читаемое имя
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
							// Не удалось преобразовать SID в имя
							username = L"SYSTEM";
						}
					}
					free(pTokenUser);
				}
			}
			else {
				// Не удалось получить информацию о токене
				username = L"SYSTEM";
			}

			CloseHandle(hToken);
		}
		else {
			// Не удалось открыть токен
			username = L"SYSTEM";
		}

		CloseHandle(hProcess);
		return username;
	}


	// Обновление списка процессов в ListView
	void RefreshProcessList(HWND hList) {
		// Очищаем список
		ListView_DeleteAllItems(hList);

		// Получаем актуальный список процессов
		g_processes = GetProcessesList();

		// Заполняем ListView
		for (size_t i = 0; i < g_processes.size(); i++) {
			const ProcessInfo& proc = g_processes[i];

			LVITEM lvi;
			ZeroMemory(&lvi, sizeof(LVITEM));  // Важно: обнуляем структуру
			lvi.mask = LVIF_TEXT | LVIF_PARAM;
			lvi.iItem = (int)i;
			lvi.iSubItem = 0;
			lvi.pszText = (LPWSTR)std::to_wstring(proc.pid).c_str();
			lvi.lParam = proc.pid;  // Сохраняем PID в lParam
			ListView_InsertItem(hList, &lvi);

			// Колонка 1: Имя процесса
			ListView_SetItemText(hList, i, 1, (LPWSTR)proc.name.c_str());

			// Колонка 2: Имя пользователя (используем новую функцию)
			std::wstring username = GetProcessUserName(proc.pid);
			ListView_SetItemText(hList, i, 2, (LPWSTR)username.c_str());

			// Колонка 3: Память (MB)
			wchar_t memoryStr[32];
			if (proc.workingSetSize > 0) {
				swprintf_s(memoryStr, L"%llu", proc.workingSetSize);
			}
			else {
				wcscpy_s(memoryStr, L"0");
			}
			ListView_SetItemText(hList, i, 3, memoryStr);

			// Колонка 4: Потоки
			wchar_t threadsStr[32];
			swprintf_s(threadsStr, L"%lu", proc.threadCount);
			ListView_SetItemText(hList, i, 4, threadsStr);

			// Колонка 5: Путь
			ListView_SetItemText(hList, i, 5, (LPWSTR)proc.fullPath.c_str());
		}

		// Авто-подгонка ширины колонок
		for (int i = 0; i < 6; i++) {  // 6 колонок
			ListView_SetColumnWidth(hList, i, LVSCW_AUTOSIZE_USEHEADER);
		}

		std::wstring status = L"Загружено процессов: " + std::to_wstring(g_processes.size());
		UpdateStatusBar(status.c_str());  // <-- Используем .c_str() для преобразования
	}

	//Показ модулей выбранного процесса
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

	//Отображение детальной информации о процессе
	void DisplayProcessDetails(DWORD pid) {
		//Здесь можно добавить вывод в третью вкладку
	}

	// Завершение выбранного процесса
	void KillSelectedProcess() {
		int selected = ListView_GetNextItem(g_hProcessList, -1, LVNI_SELECTED);
		if (selected == -1) {
			MessageBox(g_hMainWnd, L"Выберите процесс для завершения",
				L"Ошибка", MB_ICONWARNING);
			return;
		}

		wchar_t name[256];
		ListView_GetItemText(g_hProcessList, selected, 1, name, 256);

		wchar_t message[512];
		swprintf_s(message, L"Завершить процесс \"%s\"?", name);

		if (MessageBox(g_hMainWnd, message, L"Подтверждение",
			MB_YESNO | MB_ICONQUESTION) == IDYES) {
			// Правильное получение PID из ListView
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
						swprintf_s(statusBuffer, L"Процесс завершен: %s", name);
						UpdateStatusBar(statusBuffer);  // Правильно
						RefreshProcessList(g_hProcessList);
					}
					else {
						DWORD error = GetLastError();
						wchar_t errorMsg[256];
						swprintf_s(errorMsg, L"Не удалось завершить процесс. Код ошибки: %lu", error);
						MessageBox(g_hMainWnd, errorMsg,
							L"Ошибка", MB_ICONERROR);
					}
					CloseHandle(hProcess);
				}
				else {
					DWORD error = GetLastError();
					wchar_t errorMsg[256];
					swprintf_s(errorMsg, L"Не удалось открыть процесс. Код ошибки: %lu", error);
					MessageBox(g_hMainWnd, errorMsg,
						L"Ошибка", MB_ICONERROR);
				}
			}
		}
	}

	//Включаем привелегии отладки
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

	//Обновление статус бара
	void UpdateStatusBar(const wchar_t* text) {
		if (g_hStatusBar) {
			SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)text);
			SendMessage(g_hStatusBar, SB_SETTEXT, 1, (LPARAM)L"Windows Process Monitor v1.0");

			// Обновляем дату/время в третьей части
			SYSTEMTIME st;
			GetLocalTime(&st);
			wchar_t timeStr[64];
			swprintf_s(timeStr, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
			SendMessage(g_hStatusBar, SB_SETTEXT, 2, (LPARAM)timeStr);  // <-- ИСПРАВЛЕНО: g_hStatusBar
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
