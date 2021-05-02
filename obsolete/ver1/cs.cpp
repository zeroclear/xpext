
#include "common.h"

/*
NTSTATUS NTAPI RtlInitializeCriticalSectionExW7(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags)
{
	DWORD& RtlFailedCriticalDebugAllocations=*(DWORD*)0x77F9CCA8;
	CRITICAL_SECTION& RtlCriticalSectionLock=*(CRITICAL_SECTION*)0x77F97118;
	LIST_ENTRY& RtlCriticalSectionList=*(LIST_ENTRY*)0x77F97560;

	if (Flags&RTL_CRITICAL_SECTION_FLAG_RESERVED)
		return 0xC00000F1;	//STATUS_INVALID_PARAMETER_3
	if (dwSpinCount&0xFF000000!=0)	//dwSpinCount>0x00FFFFFF
		return 0xC00000F0;	//STATUS_INVALID_PARAMETER_2

	if (Flags&RTL_CRITICAL_SECTION_FLAG_STATIC_INIT)
		return STATUS_SUCCESS;

	lpCriticalSection->LockCount=-1;
	lpCriticalSection->RecursionCount=0;
	lpCriticalSection->OwningThread=NULL;
	lpCriticalSection->LockSemaphore=NULL;

	if (GetNumberOfProcessors()>1)
	{
		if (Flags&RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN)
			lpCriticalSection->SpinCount=dwSpinCount&0x00FFFFFF;
		//在Win7里，CRITICAL_SECTION::SpinCount前面几位可以带额外的标记，但XP不支持
		else
			lpCriticalSection->SpinCount=0x020007D0;
	}
	else
	{
		lpCriticalSection->SpinCount=0;
	}

	if (Flags&RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO)
	{
		lpCriticalSection->DebugInfo=(PRTL_CRITICAL_SECTION_DEBUG)-1;
	}
	else
	{
		PRTL_CRITICAL_SECTION_DEBUG info=RtlpAllocateDebugInfo();
		if (info==NULL)
		{
			lpCriticalSection->DebugInfo=(PRTL_CRITICAL_SECTION_DEBUG)-1;
			_InterlockedAdd(&RtlFailedCriticalDebugAllocations,1);
		}
		else
		{
			lpCriticalSection->DebugInfo=info;
			info->Type=RTL_CRITSECT_TYPE;
			info->ContentionCount=0;
			info->EntryCount=0;
			info->CriticalSection=lpCriticalSection;
			info->Flags=0;
			DWORD dwIndex=RtlLogStackBackTraceEx(1);
			info->CreatorBackTraceIndex=LOWORD(dwIndex);
			info->CreatorBackTraceIndexHigh=HIWORD(dwIndex);

			RtlEnterCriticalSection(&RtlCriticalSectionLock);
			LIST_ENTRY* pCur=&info->ProcessLocksList;
			pCur->Flink=&RtlCriticalSectionList;
			pCur->Blink=RtlCriticalSectionList.Blink;
			RtlCriticalSectionList.Blink->Flink=pCur;
			RtlCriticalSectionList.Blink=pCur;
			RtlLeaveCriticalSection(&RtlCriticalSectionLock);
		}
	}

	//这段代码不仅XP里没有，在Win7里我也不知道它是什么意思
	//KUSER_SHARED_DATA::UserModeGlobalLogger[1]
	HANDLE TraceHandle=(HANDLE)*(BYTE*)0x7FFE0382;
	if (TraceHandle!=NULL)
	{
		//PEB::TracingFlags.CritSecTracingEnabled
		if (GetPEB()->TracingFlags&2)
		{
			struct TRACEDATA
			{
				BYTE d1[6];
				WORD d2;
				BYTE d3[24];
				DWORD d4;
				DWORD d5;
			} td;
			td.d2=0x1723;
			td.d4=lpCriticalSection->SpinCount;
			td.d5=(DWORD)lpCriticalSection;
			NtTraceEvent(TraceHandle,0x00010402,8,&td);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCountXP(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount)
{
	HANDLE& GlobalKeyedEventHandle=*(HANDLE*)0x7C99B15C;
	CRITICAL_SECTION& RtlCriticalSectionLock=*(CRITICAL_SECTION*)0x7C99B140;
	BOOL& RtlpCritSectInitialized=*(BOOL*)0x7C99B160;
	LIST_ENTRY& RtlCriticalSectionList=*(LIST_ENTRY*)0x7C99B168;

	lpCriticalSection->LockCount=-1;
	lpCriticalSection->RecursionCount=0;
	lpCriticalSection->OwningThread=NULL;
	lpCriticalSection->LockSemaphore=NULL;

	if (GetNumberOfProcessors()>1)
		lpCriticalSection->SpinCount=dwSpinCount&0x00FFFFFF;
	else
		lpCriticalSection->SpinCount=0;

	if (GlobalKeyedEventHandle==NULL)
	{
		UNICODE_STRING name;
		RtlInitUnicodeString(&name,L"\\KernelObjects\\CritSecOutOfMemoryEvent");
		OBJECT_ATTRIBUTES oa;
		oa.Length=0x18;
		oa.RootDirectory=NULL;
		oa.ObjectName=&name;
		oa.Attributes=0;
		oa.SecurityDescriptor=NULL;
		oa.SecurityQualityOfService=NULL;
		//借用栈上的空间暂存返回值
		NTSTATUS result=NtOpenKeyedEvent((PHANDLE)&lpCriticalSection,0x02000000,&oa);
		if (!NT_SUCCESS(result))
			return result;
		DWORD old=InterlockedCompareExchange((DWORD*)&GlobalKeyedEventHandle,(DWORD)lpCriticalSection|1,0);
		if (old!=0)
			NtClose((HANDLE)lpCriticalSection);
	}

	PRTL_CRITICAL_SECTION_DEBUG info=RtlpAllocateDebugInfo();
	if (info==NULL)
		return 0xC0000017;	//STATUS_NO_MEMORY
	info->Type=RTL_CRITSECT_TYPE;
	info->ContentionCount=0;
	info->EntryCount=0;
	info->CriticalSection=lpCriticalSection;
	lpCriticalSection->DebugInfo=info;
	DWORD dwIndex=RtlLogStackBackTrace();
	info->CreatorBackTraceIndex=LOWORD(dwIndex);

	if (&RtlCriticalSectionLock!=NULL && RtlpCritSectInitialized==TRUE)
	{
		RtlEnterCriticalSection(&RtlCriticalSectionLock);
		LIST_ENTRY* pCur=&info->ProcessLocksList;
		pCur->Flink=&RtlCriticalSectionList;
		pCur->Blink=RtlCriticalSectionList.Blink;
		RtlCriticalSectionList.Blink->Flink=pCur;
		RtlCriticalSectionList.Blink=pCur;
		RtlLeaveCriticalSection(&RtlCriticalSectionLock);
	}
	else
	{
		//进程启动时，会调用RtlInitializeCriticalSectionAndSpinCount初始化RtlCriticalSectionLock
		//但是此时RtlCriticalSectionLock还没有初始化成功，于是就有了这段不加锁的代码
		LIST_ENTRY* pCur=&info->ProcessLocksList;
		pCur->Flink=&RtlCriticalSectionList;
		pCur->Blink=RtlCriticalSectionList.Blink;
		RtlCriticalSectionList.Blink->Flink=pCur;
		RtlCriticalSectionList.Blink=pCur;
	}

	return STATUS_SUCCESS;
}
*/

BOOL WINAPI K32InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags)
{
	NTSTATUS RtlStatus=STATUS_SUCCESS;
	if (Flags&RTL_CRITICAL_SECTION_FLAG_RESERVED)
		RtlStatus=0xC00000F1;	//STATUS_INVALID_PARAMETER_3
	if (dwSpinCount&0xFF000000)	//dwSpinCount>0x00FFFFFF
		RtlStatus=0xC00000F0;	//STATUS_INVALID_PARAMETER_2
	if (NT_SUCCESS(RtlStatus))
	{
		if (Flags&RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN)
			dwSpinCount=dwSpinCount&0x00FFFFFF;
		else
			dwSpinCount=2000;
		//RTL_CRITICAL_SECTION_FLAG_STATIC_INIT的效果是不初始化直接返回
		//RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO的效果是不分配DebugInfo的内存
		//由于不知道XP是否支持这些行为，稳妥起见不应用标记
		RtlStatus=RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection,dwSpinCount);
	}
	if (NT_SUCCESS(RtlStatus))
		return TRUE;
	BaseSetLastNTError(RtlStatus);
	return FALSE;
}



