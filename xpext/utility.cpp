
#include "common.h"

//自定义的便利功能

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

void SetReplaceHook(PVOID TargetAddr,PVOID NewAddr,DWORD* OldData)
{

}

void RecoverReplaceHook()
{

}

void SetFilterHook()
{

}

void RecoverFilterHook()
{

}