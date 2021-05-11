
#include "common.h"

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

BOOL NTAPI RtlIsAnyDebuggerPresent()
{
	KUSER_SHARED_DATA* pKuserSharedData=(KUSER_SHARED_DATA*)0x7FFE0000;
	return (NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged==TRUE) || 
		((pKuserSharedData->KdDebuggerEnabled&3)==3);	
}

int NTAPI RtlpTerminateFailureFilter(NTSTATUS ExceptionCode,EXCEPTION_POINTERS* ms_exc_ptr)
{
	//这个函数负责向系统报告异常并退出进程，由于太过复杂，这里不使用
	//RtlReportException(ms_exc_ptr->ExceptionRecord,ms_exc_ptr->ContextRecord,0);
	NtTerminateProcess((HANDLE)0xFFFFFFFF,ExceptionCode);
	return EXCEPTION_EXECUTE_HANDLER;
}

void NTAPI RtlReportCriticalFailure(DWORD ExceptionCode,ULONG_PTR ExceptionParam1)
{
	__try
	{
		if (RtlIsAnyDebuggerPresent())
		{
			//DPFLTR_DEFAULT_ID
			DbgPrintEx(0x65,0,"Critical error detected %lx\n",ExceptionCode);
			_asm int 3;
		}
	}
	__except(RtlpTerminateFailureFilter(GetExceptionCode(),GetExceptionInformation()))
	{
		return ;
	}
	EXCEPTION_RECORD ExceptionRecord;
	ExceptionRecord.ExceptionCode=ExceptionCode;
	ExceptionRecord.ExceptionFlags=EXCEPTION_NONCONTINUABLE;
	ExceptionRecord.ExceptionRecord=NULL;
	ExceptionRecord.ExceptionAddress=RtlRaiseException;
	ExceptionRecord.NumberParameters=1;
	ExceptionRecord.ExceptionInformation[0]=ExceptionParam1;
	RtlRaiseException(&ExceptionRecord);
}

/*
Windows XP：
kernel32.SetLastError={BreakPoint}+{LastErrorSet}
kernel32.BaseSetLastNTError=ntdll.RtlNtStatusToDosError+kernel32.SetLastError
sdk.SetLastError=ntdll.RtlRestoreLastWin32Error
ntdll.RtlRestoreLastWin32Error={LastErrorSet}
ntdll.RtlSetLastWin32ErrorAndNtStatusFromNtStatus=ntdll.RtlNtStatusToDosError+{LastErrorSet}
Windows 7：
kernel32.SetLastError=jmp ntdll.RtlRestoreLastWin32Error
kernel32.BaseSetLastNTError=ntdll.RtlNtStatusToDosError+ntdll.RtlSetLastWin32Error
sdk.SetLastError=kernel32.SetLastError
ntdll.RtlSetLastWin32Error=ntdll.RtlRestoreLastWin32Error={BreakPoint}+{LastErrorSet}
ntdll.RtlSetLastWin32ErrorAndNtStatusFromNtStatus=ntdll.RtlNtStatusToDosError+ntdll.RtlSetLastWin32Error

XP的SetLastError分两种，一种是kernel32内部使用的kernel32.SetLastError，具有断点功能
另一种是sdk里供开发者使用的，实际是ntdll.RtlRestoreLastWin32Error，没有断点功能
Win7则对此作出了统一，无论什么样的SetLastError，最后都调用ntdll.RtlSetLastWin32Error，总有断点功能

本来想模仿Win7，把kernel32.SetLastError给Hook了，令其跳转到我的xpext.RtlSetLastWin32Error
但是这样只能修改kernel32内部的调用，其它软件对ntdll.RtlRestoreLastWin32Error的调用还是没效果
更进一步的做法是令kernel32.SetLastError跳转到ntdll.RtlRestoreLastWin32Error
然后令ntdll.RtlRestoreLastWin32Error跳转到xpext.RtlSetLastWin32Error，统一使用我的函数
但是仔细想想，就这么个破断点，正常人八辈子用不到，没必要大费周章搞Hook，影响系统稳定性
最终的决定是，xpext内部的函数使用xpext.RtlSetLastWin32Error，其他软件不做修改，保持原来的调用
*/

DWORD g_dwLastErrorToBreakOn=0;

void NTAPI RtlSetLastWin32Error(DWORD Win32ErrorCode)
{
	if (g_dwLastErrorToBreakOn!=0 && Win32ErrorCode==g_dwLastErrorToBreakOn)
		_asm int 3;
	TEB* CurrentTeb=NtCurrentTeb();
	if (CurrentTeb->LastErrorValue!=Win32ErrorCode)		//这个判断有意义吗？
		CurrentTeb->LastErrorValue=Win32ErrorCode;
}

NTSTATUS NTAPI RtlInitAnsiStringEx(PANSI_STRING DestinationString,PCSTR szSourceString)
{
	DestinationString->Length=0;
	DestinationString->MaximumLength=0;
	DestinationString->Buffer=(PCHAR)szSourceString;
	if (szSourceString==NULL)
		return STATUS_SUCCESS;
	int Len=strlen(szSourceString);
	if (Len>65534)
		return STATUS_NAME_TOO_LONG;
	DestinationString->Length=Len;
	DestinationString->MaximumLength=Len+1;
	return STATUS_SUCCESS;
}
