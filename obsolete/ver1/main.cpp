
#include <Windows.h>
#include "common.h"
#pragma comment(lib,"E:\\WDK\\lib\\wxp\\i386\\ntdll.lib")

#define BASE_NT		0x7C920000
#define BASE_K32	0x7C800000

DWORD* g_dwLastErrorToBreakOn;
BYTE* LdrpShutdownInProgress;
HANDLE GlobalKeyedEventHandle;

void NTEXT_Init()
{
	DWORD dwNtBaseNow=(DWORD)FindDllBase(L"ntdll.dll");
	LdrpShutdownInProgress=(BYTE*)(0x7C99B0C4-BASE_NT+dwNtBaseNow);
	DWORD dwK32BaseNow=(DWORD)FindDllBase(L"kernel32.dll");
	g_dwLastErrorToBreakOn=(DWORD*)(0x7C8856C4-BASE_K32+dwK32BaseNow);
	//出于各种考虑，使用新句柄
	GlobalKeyedEventHandle=OpenGlobalKeyedEvent();
}

void NtEXT_Uninit()
{
	CloseGlobalKeyedEvent(GlobalKeyedEventHandle);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			OutputDebugString(L"ntext loaded: ver 1.0\r\n");
			NTEXT_Init();
			break;
		case DLL_PROCESS_DETACH:
			NtEXT_Uninit();
			OutputDebugString(L"ntext unload: ver 1.0\r\n");
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}
	return TRUE;
}
