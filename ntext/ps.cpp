
#include "common.h"

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation=0
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation=0
} THREADINFOCLASS;

typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS  ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

extern "C"
{
	NTSTATUS WINAPI 
		NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	NTSTATUS WINAPI 
		NtQueryInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);
};


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

_declspec(naked)
DWORD WINAPI RtlGetCurrentProcessorNumber()
{
	_asm 
	{
		mov  ecx, 0x3B;
		lsl  eax, ecx;
		shr  eax, 0x0E;
		retn ;
	}
}

_declspec(naked)
void WINAPI K32GetCurrentProcessorNumberEx(PPROCESSOR_NUMBER ProcNumber)
{
	_asm
	{
		mov  edi, edi;
		push  ebp;
		mov  ebp, esp;
		mov  edx, dword ptr ss:[ebp+8];  //ProcNumber
		xor  eax, eax;
		mov  [edx], ax;  //ProcNumber->Group
		mov  ecx, 0x3B;
		lsl  eax, ecx;
		shr  eax, 0x0E;
		mov  [edx+2], al;  //ProcNumber->Number
		mov  byte ptr [edx+3], 0;  //ProcNumber->Reserved
		pop  ebp;
		retn 4;
	}
}