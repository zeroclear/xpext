
#include "common.h"

typedef unsigned __int64 QWORD;

/*
系统开机到现在的时间=系统开机到现在的tick数*一个tick持续的时间
一个tick持续的时间可能不是整数，所以用TickCountMultiplier和Divisor联合表示
在我的XP上，TickCountMultiplier为0x0FA00000，Divisor则为固定的0x01000000，即15.625ms
因此GetTickCount的返回值总是15.625的倍数，这就是MSDN上说的误差的原因

GetTickCount返回的毫秒数上限为0xFFFFFFFF，约等于49.7天，但实际的计算结果可以多一些
以每个tick持续15.625毫秒为例，可以算出最大776.7天，接近36位，把这个值按__int64返回，可以满足大多数需求
实际上，一个tick持续的时间理论上是8位（Multiplier为32位，Divisor为24位）
假如Windows把一个tick的持续时间拉满（我是说假如，这种情况不可能出现），算出来的时间上限是40位

尽管如此，我还是没选择这个方案，而是在xpextk.sys里模仿Win7的做法，真正更新了KUserSharedData::TickCount

DWORD WINAPI GetTickCount_XP()
{
	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0x7FFE0000;
	QWORD TickCount=KUserSharedData->TickCountLow*KUserSharedData->TickCountMultiplier;
	return (DWORD)(TickCount>>24);
}

DWORD WINAPI GetTickCount_Win7x32()
{
	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0x7FFE0000;
	while (KUserSharedData->TickCount.High1Time!=KUserSharedData->TickCount.High2Time)		//同步
		_mm_pause();
	QWORD LowPart=(KUserSharedData->TickCount.LowPart*KUserSharedData->TickCountMultiplier)>>24;
	//High1Time是高32位，计算前应该先左移32位，但是后面tick转单位要右移24位，合起来就是左移8位
	//DWORD HighPart=(KUserSharedData->TickCount.High1Time<<32)*KUserSharedData->TickCountMultiplier>>24;
	DWORD HighPart=(KUserSharedData->TickCount.High1Time<<8)*KUserSharedData->TickCountMultiplier;
	return (DWORD)LowPart+HighPart;
}

ULONGLONG WINAPI GetTickCount64_Win7x32()
{
	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0x7FFE0000;
	while (KUserSharedData->TickCount.High1Time!=KUserSharedData->TickCount.High2Time)
		_mm_pause();
	QWORD LowPart=(KUserSharedData->TickCount.LowPart*KUserSharedData->TickCountMultiplier)>>24;
	QWORD HighPart=KUserSharedData->TickCount.High1Time*KUserSharedData->TickCountMultiplier;
	HighPart=HighPart*0x100;	//乘0x100等价于左移8位，原汇编调用了ntdll._allmul()
	return HighPart+LowPart;
}

ULONGLONG WINAPI GetTickCount64_Win7x64()
{
	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0x7FFE0000;
	QWORD TickCount=*(QWORD*)&KUserSharedData->TickCount;
	QWORD HighPart=(TickCount>>32)*KUserSharedData->TickCountMultiplier<<8;
	QWORD LowPart=(DWORD)TickCount*KUserSharedData->TickCountMultiplier>>24;
	return HighPart+LowPart;
}
*/

//需要xpextk.sys支持
ULONGLONG WINAPI K32GetTickCount64()
{
	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0x7FFE0000;
	QWORD LowPart=(KUserSharedData->TickCount.LowPart*KUserSharedData->TickCountMultiplier)>>24;
	QWORD HighPart=KUserSharedData->TickCount.High1Time*KUserSharedData->TickCountMultiplier<<8;
	return LowPart+HighPart;
}

//UINT GetErrorMode();
//GetErrorMode=0x7C80ACDD
//导出就可以了

VOID WINAPI K32RaiseFailFastException(PEXCEPTION_RECORD pExceptionRecord,PCONTEXT pContextRecord,DWORD dwFlags)
{
	EXCEPTION_RECORD ExceptionRecord;
	CONTEXT ContextRecord;
	DWORD MessageBoxResult;
	DWORD ReturnAddress;
	//参数1在栈上的地址是ebp+8，这个位置再-4就是函数返回地址在栈中的位置
	ReturnAddress=*((DWORD*)&pExceptionRecord-1);

	if (pExceptionRecord==NULL)
	{
		memset(&ExceptionRecord,0,sizeof(EXCEPTION_RECORD));	//sizeof(EXCEPTION_RECORD)==80
		ExceptionRecord.ExceptionCode=STATUS_FAIL_FAST_EXCEPTION;
		ExceptionRecord.ExceptionFlags=EXCEPTION_NONCONTINUABLE;
		ExceptionRecord.ExceptionAddress=(PVOID)ReturnAddress;		//[ebp+4]
		pExceptionRecord=&ExceptionRecord;
	}
	else
	{
		pExceptionRecord->ExceptionFlags|=EXCEPTION_NONCONTINUABLE;
		if (dwFlags&FAIL_FAST_GENERATE_EXCEPTION_ADDRESS)
			pExceptionRecord->ExceptionAddress=(PVOID)ReturnAddress;
	}

	if (pContextRecord==NULL)
	{
		memset(&ContextRecord,0,sizeof(CONTEXT));	//sizeof(CONTEXT)==0x2CC
		RtlCaptureContext(&ContextRecord);
		pContextRecord=&ContextRecord;
	}

	/*
	//这个函数调用了EtwEventWriteNoRegistration，GUID是{E46EEAD8-0C54-4489-9898-8FA79D059E0E}
	NTSTATUS Result=SignalStartWerSvc();
	if (NT_SUCCESS(Result))
	{
		//这个函数调用了NtWaitForSingleObject，Event是"\\KernelObjects\\SystemErrorPortReady"
		Result=WaitForWerSvc();
		if (NT_SUCCESS(Result) && Result!=STATUS_TIMEOUT)
		{
			if (*(BYTE*)0x7FFE02F0==1)	//KUSER_SHARED_DATA::DbgErrorPortPresent
			{
				NtRaiseException(pExceptionRecord,pContextRecord,FALSE);
				return ;
			}
		}
	}
	*/

	if (!(dwFlags&FAIL_FAST_NO_HARD_ERROR_DLG))
		NtRaiseHardError(pExceptionRecord->ExceptionCode|0x10000000,0,0,0,1,&MessageBoxResult);
	TerminateProcess(GetCurrentProcess(),pExceptionRecord->ExceptionCode);
}


DWORD WINAPI BaseSetLastNTError(NTSTATUS NtStatus)
{
	//xpext的所有函数使用xpext.BaseSetLastNTError
	//相比kernel32.BaseSetLastNTError，可以转换的Status更全
	DWORD dwWin32Error=RtlNtStatusToDosError(NtStatus);
	//XP在此处使用KERNEL32.SetLastError，而Win7使用NTDLL.RtlSetLastWin32Error
	//原因参见xpext.RtlSetLastWin32Error，这里统一使用xpext.RtlSetLastWin32Error
	RtlSetLastWin32Error(dwWin32Error);
	return dwWin32Error;
}

LARGE_INTEGER* WINAPI BaseFormatTimeOut(LARGE_INTEGER* pTimeOut,DWORD dwMilliseconds)
{
	if (dwMilliseconds==INFINITE)
		return NULL;
	pTimeOut->QuadPart=-10000*dwMilliseconds;
	return pTimeOut;
}