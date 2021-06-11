
#include "common.h"
#pragma comment(lib,"E:\\WDK\\lib\\wxp\\i386\\ntdll.lib")

//发布时记得注明系统dll版本，每个版本的dll偏移都不一样
#define BASE_NT		0x7C920000
#define BASE_K32	0x7C800000

//进程退出时，将此值设为TRUE，阻止退出期间进行的各种新建行为
BYTE* LdrpShutdownInProgress;
//由RtlCreateTagHeap创建的堆，用来分配临时数据
//BaseDllTag=RtlCreateTagHeap(HeapHandle,0,"BASEDLL!","TMP");
//Win7中，此标记移至KernelBaseGlobalData+0x2c处
DWORD* BaseDllTag;
//XP的KeyedEvent需要用到句柄，出于各种考虑，这里用一个新的
HANDLE GlobalKeyedEventHandle;
//Win7使用RtlCreateUserStack，XP使用BaseCreateStack，但没有导出
TypeBaseCreateStack BaseCreateStack;

void XPEXT_InitDll()
{
	DWORD dwNtBaseNow=(DWORD)FindDllBase(L"ntdll.dll");
	LdrpShutdownInProgress=(BYTE*)(0x7C99B0C4-BASE_NT+dwNtBaseNow);
	DWORD dwK32BaseNow=(DWORD)FindDllBase(L"kernel32.dll");
	BaseDllTag=(DWORD*)(0x7C8856D4-BASE_K32+dwK32BaseNow);
	GlobalKeyedEventHandle=OpenGlobalKeyedEvent();
	BaseCreateStack=(TypeBaseCreateStack)(0x7C8102AC-BASE_K32+dwK32BaseNow);
	RtlpInitSRWLock(NtCurrentTeb()->ProcessEnvironmentBlock);
	RtlpInitConditionVariable(NtCurrentTeb()->ProcessEnvironmentBlock);
	LdrpInitializeFiber();
}

void XPEXT_UninitDll()
{
	CloseGlobalKeyedEvent(GlobalKeyedEventHandle);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugString(L"xpext loaded: ver 1.0\r\n");
		XPEXT_InitDll();
		break;
	case DLL_PROCESS_DETACH:
		XPEXT_UninitDll();
		OutputDebugString(L"xpext unload: ver 1.0\r\n");
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}