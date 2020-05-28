
#include "common.h"

HANDLE GlobalKeyedEventHandle=NULL;

_declspec(naked)
	int __stdcall GetProcessorCount()
{
	_asm
	{
		mov eax,dword ptr fs:[0x18];
		mov eax,dword ptr ds:[eax+0x30];
		mov eax,dword ptr ds:[eax+0x64];
		retn;
	}
}

/*
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

void __stdcall OpenGlobalKeyedEvent()
{
	UNICODE_STRING Name;
	if (GlobalKeyedEventHandle==NULL)
	{
		RtlInitUnicodeString(&Name,L"\\KernelObjects\\CritSecOutOfMemoryEvent");
		OBJECT_ATTRIBUTES oa;
		oa.Length=0x18;
		oa.RootDirectory=0;
		oa.ObjectName=&Name;
		oa.Attributes=0;
		oa.SecurityDescriptor=0;
		oa.SecurityQualityOfService=0;
		NtOpenKeyedEvent(&GlobalKeyedEventHandle,0x2000000,&oa);	//MAXIMUM_ALLOWED
	}
}

void __stdcall CloseGlobalKeyedEvent()
{
	if (GlobalKeyedEventHandle!=NULL)
	{
		NtClose(GlobalKeyedEventHandle);
		GlobalKeyedEventHandle=NULL;
	}
}

BOOL NTAPI RtlpWaitCouldDeadlock()
{
	//cmp     byte_77F978A8, 0
	//setnz   al
	//retn
	//byte_77F978A8与dll加载，线程、进程初始化和退出有关
	//进程初始化的时候设为0，进程结束时设为1
	//如果为1，会阻止调用dll的tls函数和入口函数
	//return (*(BYTE*)0x77F978A8!=0);
	return FALSE;
}

//通过延时来暂时退避竞争
void NTAPI RtlBackoff(DWORD *pCount)
{
	DWORD nBackCount=*pCount;
	if (nBackCount==0)
	{
		if (GetProcessorCount()==1)
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
