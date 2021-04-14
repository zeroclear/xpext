
#include "common.h"

//kernelbase.dll

DWORD WINAPI K32FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback)
{
	return 0;
}

BOOL WINAPI K32FlsFree(DWORD dwFlsIndex)
{
	return TRUE;
}

PVOID WINAPI K32FlsGetValue(DWORD dwFlsIndex)
{
	return NULL;
}

BOOL WINAPI K32FlsSetValue(DWORD dwFlsIndex,PVOID lpFlsData)
{
	return TRUE;
}

BOOL WINAPI K32IsThreadAFiber()
{
	return FALSE;
}

//差了这2个
//ConvertThreadToFiberEx
//IsThreadAFiber
//还有个没导出的BaseInitializeFiberContext(x,x,x,x)

//win7 kernel32.dll
//DeleteFiber(x)
//ConvertFiberToThread()
//CreateFiber(x,x,x)
//CreateFiberEx(x,x,x,x,x)
//ConvertThreadToFiber(x)
//ConvertThreadToFiberEx(x,x)
//IsThreadAFiber()
//SwitchToFiber(x)

//xp kernel32.dll
//SwitchToFiber(x)
//DeleteFiber(x)
//ConvertFiberToThread()
//ConvertThreadToFiber(x)
//CreateFiber(x,x,x)
//CreateFiberEx(x,x,x,x,x)