
#include "common.h"

/*
在XP下，内核会调用ExpKeyedEventInitialization创建KeyedEvent对象。
每次进程启动时，会调用RtlInitializeCriticalSectionAndSpinCount，
对RtlCriticalSectionLock进行初始化，这个函数还会顺带调用NtOpenKeyedEvent，
打开KeyedEvent对象的句柄。

但是Vista以后的系统对KeyedEvent做了改进，NtWaitForKeyedEvent和
NtReleaseKeyedEvent不再需要句柄，直接传递NULL就能生效。因此进程启动时，
不再需要打开KeyedEvent对象的句柄。

NTSTATUS ExpKeyedEventInitialization()
{
	...
	HANDLE Handle;
	UNICODE_STRING DestinationString;
	//前面必须有\\KernelObjects\\，否则返回STATUS_OBJECT_PATH_SYNTAX_BAD
	RtlInitUnicodeString(&DestinationString,L"\\KernelObjects\\CritSecOutOfMemoryEvent");
	OBJECT_ATTRIBUTES oa;
	oa.Length=0x18;
	oa.RootDirectory=NULL;
	oa.ObjectName=&DestinationString;
	oa.Attributes=0x10;	//OBJ_PERMANENT，如果在ring3，会返回STATUS_PRIVILEGE_NOT_HELD
	oa.SecurityDescriptor=NULL;
	oa.SecurityQualityOfService=NULL;
	NTSTATUS Error=ZwCreateKeyedEvent(&Handle,0xF0003,&oa,0);	//EVENT_ALL_ACCESS&(~SYNCHRONIZE)
	if (NT_SUCCESS(Error))
		Error=ZwClose(Handle);	//大概是永久对象的存在和引用计数无关了
	return Error;
}*/

HANDLE NTAPI OpenGlobalKeyedEvent()
{
	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name,L"\\KernelObjects\\CritSecOutOfMemoryEvent");
	OBJECT_ATTRIBUTES oa;
	oa.Length=0x18;
	oa.RootDirectory=NULL;
	oa.ObjectName=&Name;
	oa.Attributes=0;
	oa.SecurityDescriptor=NULL;
	oa.SecurityQualityOfService=NULL;
	HANDLE hKeyedEvent=NULL;
	NtOpenKeyedEvent(&hKeyedEvent,0x2000000,&oa);	//MAXIMUM_ALLOWED
	return hKeyedEvent;
}

void NTAPI CloseGlobalKeyedEvent(HANDLE hKeyedEvent)
{
	if (hKeyedEvent!=NULL)
		NtClose(GlobalKeyedEventHandle);
}

PVOID WINAPI FindDllBase(WCHAR* szName)
{
	UNICODE_STRING usName;
	RtlInitUnicodeString(&usName,szName);
	PEB* pPeb=NtCurrentTeb()->ProcessEnvironmentBlock;
	LIST_ENTRY* Head=&pPeb->Ldr->InLoadOrderModuleList;
	LIST_ENTRY* Curr=Head->Flink;
	while (Curr->Flink!=Head)
	{
		LDR_DATA_TABLE_ENTRY* Entry=CONTAINING_RECORD(Curr,LDR_DATA_TABLE_ENTRY,InLoadOrderLinks);
		if (RtlCompareUnicodeString(&Entry->BaseDllName,&usName,TRUE)==0)
			return Entry->DllBase;
		Curr=Curr->Flink;
	}
	return NULL;
}

BOOL NTAPI RtlpWaitCouldDeadlock()
{
	//byte_77F978A8极有可能是LdrpShutdownInProgress
	//进程退出时，各种资源即将被销毁，继续等待将会出现错误的结果
	return *LdrpShutdownInProgress!=0;
}

//通过延时来暂时退避竞争
void NTAPI RtlBackoff(DWORD* pCount)
{
	DWORD nBackCount=*pCount;
	if (nBackCount==0)
	{
		if (NtCurrentTeb()->ProcessEnvironmentBlock->NumberOfProcessors==1)
			return ;
		nBackCount=0x40;
		nBackCount*=2;
	}
	else
	{
		if (nBackCount<0x1FFF)
			nBackCount=nBackCount+nBackCount;
	}
	nBackCount=(__rdtsc()&(nBackCount-1))+nBackCount;
	//Win7原代码借用参数来计数，省去局部变量
	pCount=0;
	while ((DWORD)pCount<nBackCount)
	{
		_mm_pause();
		(DWORD)pCount++;
	}
}

void WINAPI K32SetLastError(DWORD dwErrCode)
{
	if (*g_dwLastErrorToBreakOn!=ERROR_SUCCESS && *g_dwLastErrorToBreakOn==dwErrCode)
		DbgBreakPoint();
	//原代码先判断LastErrorValue!=dwErrCode，但这没有意义
	NtCurrentTeb()->LastErrorValue=dwErrCode;
}

DWORD WINAPI BaseSetLastNTError(NTSTATUS NtStatus)
{
	DWORD dwErrCode=RtlNtStatusToDosError(NtStatus);
	//在Win7上，调用NTDLL.RtlSetLastWin32Error
	//XP上也有类似的NTDLL.RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	//但是没有使用g_dwLastErrorToBreakOn，还是Kernel32.SetLastError更好
	K32SetLastError(dwErrCode);
	return dwErrCode;
}

LARGE_INTEGER* WINAPI BaseFormatTimeOut(LARGE_INTEGER* pTimeOut,DWORD dwMilliseconds)
{
	if (dwMilliseconds==INFINITE)
		return NULL;
	pTimeOut->QuadPart=-10000*dwMilliseconds;
	return pTimeOut;
}



