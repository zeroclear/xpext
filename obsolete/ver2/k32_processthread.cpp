
#include "common.h"

DWORD WINAPI K32GetThreadId(HANDLE Thread)
{
	THREAD_BASIC_INFORMATION ThreadInformation;
	NTSTATUS Result=NtQueryInformationThread(Thread,ThreadBasicInformation,&ThreadInformation,sizeof(ThreadInformation),NULL);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return 0;
	}
	return (DWORD)ThreadInformation.ClientId.UniqueThread;
}

DWORD WINAPI K32GetProcessId(HANDLE Process)
{
	PROCESS_BASIC_INFORMATION ProcessInformation;
	NTSTATUS Result=NtQueryInformationProcess(Process,ProcessBasicInformation,&ProcessInformation,sizeof(ProcessInformation),NULL);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return 0;
	}
	return (DWORD)ProcessInformation.UniqueProcessId;
}

DWORD WINAPI K32GetProcessIdOfThread(HANDLE Thread)
{
	THREAD_BASIC_INFORMATION ThreadInformation;
	NTSTATUS Result=NtQueryInformationThread(Thread,ThreadBasicInformation,&ThreadInformation,sizeof(ThreadInformation),NULL);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return 0;
	}
	return (DWORD)ThreadInformation.ClientId.UniqueProcess;
}

void WINAPI K32DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList)
{
	//Ô­º¯ÊýÕæµÄÊ²Ã´¶¼Ã»×ö
	return ;
}

BOOL WINAPI K32InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,DWORD dwAttributeCount,DWORD dwFlags,PSIZE_T lpSize)
{

	return TRUE;
}

BOOL WINAPI K32UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,DWORD dwFlags,
	DWORD_PTR Attribute,PVOID lpValue,SIZE_T cbSize,PVOID lpPreviousValue,PSIZE_T lpReturnSize)
{

	return TRUE;
}
