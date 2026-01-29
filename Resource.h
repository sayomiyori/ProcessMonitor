// resource.h
#ifndef _RESOURCE_H_
#define _RESOURCE_H_

#ifndef IDC_STATIC
#define IDC_STATIC              (-1)
#endif

// Основные ID команд меню
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

// Дополнительные функции
#define IDM_OPENFILELOCATION     2110
#define IDM_SEARCHONLINE         2111
#define IDM_CREATEDUMP           2112
#define IDM_GOTOSERVICES         2113
#define IDM_SETPRIORITY          2114
#define IDM_AFFINITY             2115
#define IDM_UACVIRTUALIZATION    2116
#define IDM_CREATENEWTASK        2117
#define IDM_RUNASADMIN           2118

// Настройки приложения
#define IDM_ALWAYSONTOP          2119
#define IDM_MINIMIZEONCLOSE      2120
#define IDM_SHOWALLUSERS         2121
#define IDM_ABOUT                2122
#define IDM_EXIT                 2123

// Приоритеты процессов
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

// Элементы диалога свойств
#define IDC_PROP_NAME            3001
#define IDC_PROP_PID             3002
#define IDC_PROP_PARENT_PID      3003
#define IDC_PROP_PATH            3004
#define IDC_PROP_CMD_LINE        3005
#define IDC_PROP_USER            3006
#define IDC_PROP_PRIORITY        3007
#define IDC_PROP_THREADS         3008
#define IDC_PROP_MEMORY          3009
#define IDC_PROP_CPU_USAGE       3010
#define IDC_PROP_START_TIME      3011
#define IDC_PROP_SESSION_ID      3012
#define IDC_PROP_INTEGRITY       3013
#define IDC_CLOSE_BTN            3014

// Элементы диалога экспорта
#define IDC_EXPORT_CSV           3101
#define IDC_EXPORT_TXT           3102
#define IDC_EXPORT_PATH          3103
#define IDC_EXPORT_BROWSE        3104

// Элементы диалога запуска задачи
#define IDC_TASK_PATH            3201
#define IDC_TASK_BROWSE          3202
#define IDC_TASK_ARGS            3203
#define IDC_TASK_RUNASADMIN      3204

// Элементы диалога привязки процессоров
#define IDC_AFFINITY_CPU0        3300
#define IDC_AFFINITY_CPU1        3301
#define IDC_AFFINITY_CPU2        3302
#define IDC_AFFINITY_CPU3        3303
#define IDC_AFFINITY_CPU4        3304
#define IDC_AFFINITY_CPU5        3305
#define IDC_AFFINITY_CPU6        3306
#define IDC_AFFINITY_CPU7        3307
#define IDC_AFFINITY_CPU8        3308
#define IDC_AFFINITY_CPU9        3309
#define IDC_AFFINITY_CPU10       3310
#define IDC_AFFINITY_CPU11       3311
#define IDC_AFFINITY_CPU12       3312
#define IDC_AFFINITY_CPU13       3313
#define IDC_AFFINITY_CPU14       3314
#define IDC_AFFINITY_CPU15       3315
#define IDC_AFFINITY_ALL         3316
#define IDC_AFFINITY_CUSTOM      3317

// Иконки
#define IDI_APP_ICON             4001
#define IDI_APP_ICON_SMALL       4002

// Меню
#define IDR_MAIN_MENU            4003

#endif // _RESOURCE_H_
