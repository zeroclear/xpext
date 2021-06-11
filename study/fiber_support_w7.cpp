
#include "fiber_def_w7.h"

DWORD BaseDllTag=0;
BASE_STATIC_SERVER_DATA* BaseStaticServerData=NULL;
ULONG RtlpProcessECVDisabled=0xFFFFFFFF;
PVOID RtlpUnhandledExceptionFilter=NULL;

typedef LONG (NTAPI*FN_RtlUnhandledExceptionFilter)(EXCEPTION_POINTERS*);

EXCEPTION_REGISTRATION_RECORD* NTAPI RtlpGetRegistrationHead()
{
	return NtCurrentTeb()->NtTib.ExceptionList;
}

PVOID NTAPI RtlpGetExceptionFilter()
{
	PVOID fnRtlUnhandledExceptionFilter=RtlDecodePointer(RtlpUnhandledExceptionFilter);
	if (fnRtlUnhandledExceptionFilter==NULL)
		fnRtlUnhandledExceptionFilter=(PVOID)RtlUnhandledExceptionFilter;
	return fnRtlUnhandledExceptionFilter;
}

BOOL NTAPI FinalExceptionHandler(EXCEPTION_RECORD* ExceptionRecord,EXCEPTION_REGISTRATION_RECORD* RegistrationRecord,CONTEXT* ContextRecord,PVOID Unknown)
{
	BOOL Result=TRUE;
	EXCEPTION_POINTERS ExceptionInformation;
	if (RegistrationRecord==RtlpGetRegistrationHead())
	{
		ExceptionInformation.ExceptionRecord=ExceptionRecord;
		ExceptionInformation.ContextRecord=ContextRecord;
		FN_RtlUnhandledExceptionFilter fnRtlUnhandledExceptionFilter=(FN_RtlUnhandledExceptionFilter)RtlpGetExceptionFilter();
		if (fnRtlUnhandledExceptionFilter(&ExceptionInformation)==0xFFFFFFFF)
			Result=FALSE;
	}
	return Result;
}

VOID NTAPI RtlInitializeExceptionChain(EXCEPTION_REGISTRATION_RECORD* ExceptionRegistrationRecord)
{
	if (RtlpProcessECVDisabled!=1)
	{
		ExceptionRegistrationRecord->Next=(EXCEPTION_REGISTRATION_RECORD*)0xFFFFFFFF;
		ExceptionRegistrationRecord->Handler=(EXCEPTION_DISPOSITION*)FinalExceptionHandler;
		TEB* Teb=NtCurrentTeb();
		if (Teb->NtTib.ExceptionList==(EXCEPTION_REGISTRATION_RECORD*)0xFFFFFFFF)
		{
			Teb->NtTib.ExceptionList=ExceptionRegistrationRecord;
			Teb->RtlExceptionAttached=TRUE;
		}
	}
}

VOID NTAPI RtlpInitializeActivationContextStack(ACTIVATION_CONTEXT_STACK* ActivationContextStack)
{
	ActivationContextStack->Flags=0;
	ActivationContextStack->ActiveFrame=NULL;
	LIST_ENTRY* ListHead=&(ActivationContextStack->FrameListCache);
	ListHead->Blink=ListHead;
	ListHead->Flink=ListHead;
	ActivationContextStack->NextCookieSequenceNumber=1;
	ActivationContextStack->StackId=GetTickCount();
}

NTSTATUS NTAPI RtlAllocateActivationContextStack(ACTIVATION_CONTEXT_STACK** ActivationContextStackOut)
{
	if (*ActivationContextStackOut!=NULL)
		return STATUS_SUCCESS;
	ACTIVATION_CONTEXT_STACK* ActivationContextStack=(ACTIVATION_CONTEXT_STACK*)
		RtlAllocateHeap(RtlGetProcessHeap(),0,sizeof(ACTIVATION_CONTEXT_STACK));
	if (ActivationContextStack==NULL)
		return STATUS_NO_MEMORY;
	RtlpInitializeActivationContextStack(ActivationContextStack);
	*ActivationContextStackOut=ActivationContextStack;
	return STATUS_SUCCESS;
}

VOID NTAPI RtlFreeActivationContextStack(ACTIVATION_CONTEXT_STACK* ActivationContextStack)
{
	if (ActivationContextStack==NULL)
		return ;
	RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame=ActivationContextStack->ActiveFrame;
	if (ActiveFrame!=NULL)
	{
		do 
		{
			RTL_ACTIVATION_CONTEXT_STACK_FRAME* PreviousActiveFrame=ActiveFrame->Previous;
			if (ActiveFrame->Flags&1)
				RtlReleaseActivationContext(ActiveFrame->ActivationContext);
			if (ActiveFrame->Flags&8)
				RtlpFreeActivationContextStackFrame(ActivationContextStack,ActiveFrame);
			ActiveFrame=PreviousActiveFrame;
		} while (ActiveFrame!=NULL);
	}
	ActivationContextStack->ActiveFrame=NULL;

	LIST_ENTRY* CacheHead=&ActivationContextStack->FrameListCache;
	LIST_ENTRY* CacheEntry=CacheHead->Flink;
	if (CacheEntry!=CacheHead)
	{
		do 
		{
			BYTE* CacheBody=(BYTE*)CacheEntry-8;	//CONTAINING_RECORD
			LIST_ENTRY* NextEntry=CacheEntry->Flink;
			LIST_ENTRY* BackEntry=CacheEntry->Blink;
			BackEntry->Flink=NextEntry;
			NextEntry->Blink=BackEntry;
			RtlFreeHeap(RtlGetProcessHeap(),0,CacheBody);
			CacheEntry=NextEntry;
		} while (CacheEntry!=CacheHead);
	}
	RtlFreeHeap(RtlGetProcessHeap(),0,ActivationContextStack);
}

VOID NTAPI RtlReleaseActivationContext(PVOID ActivationContext)
{
	//ACTIVATION_CONTEXT* ActivationContext;

	//XP
	//RtlpUninitializeAssemblyStorageMap
	//RtlFreeHeap

	//Win7
	//g_SxsTrackReleaseStacks
	//RtlCaptureStackBackTrace
	//g_SxsKeepActivationContextsAlive
	//RtlpFreeActivationContext
	//RtlpMoveActCtxToFreeList
}

VOID NTAPI RtlpFreeActivationContextStackFrame(ACTIVATION_CONTEXT_STACK* ActivationContextStack,RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame)
{
	//显然，它和RtlpAllocateActivationContextStackFrame和RtlpInitializeActivationContextStackFrameList是一起的
	//ActivationContextStack->FrameListCache的结构无从得知

	//RtlRaiseException
	//RtlFreeHeap
}


/*
//loc_83E1ED4E:
NTSTATUS NTAPI NtSetInformationProcess41(HANDLE ProcessHandle,PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength)
{
	if (ProcessInformationClass!=ProcessThreadStackAllocation)
		return STATUS_INVALID_INFO_CLASS;

	//HANDLE var_34=ProcessHandle;
	//PVOID var_38=ProcessInformation;
	//PROCESSINFOCLASS var_edx=ProcessInformationClass;
	KPROCESSOR_MODE PreviousMode=KeGetCurrentThread()->PreviousMode;	//KTHREAD

	if (ProcessHandle!=(HANDLE)0xFFFFFFFF)
		return STATUS_INVALID_PARAMETER;

	PROCESS_STACK_ALLOCATION_INFORMATION* Info;		//esi
	PROCESS_STACK_ALLOCATION_INFORMATION_EX* InfoEx;	//esi
	PROCESS_STACK_ALLOCATION_INFORMATION_EX InfoExDup;	//var_220
	PVOID* StackBase=NULL;	//var_50
	ULONG ExtraType;	//edi

	if (ProcessInformationLength==sizeof(PROCESS_STACK_ALLOCATION_INFORMATION_EX))
	{
		InfoEx=(PROCESS_STACK_ALLOCATION_INFORMATION_EX*)ProcessInformation;	
		if (PreviousMode==UserMode)
		{
			__try
			{
				memcpy(&InfoExDup,InfoEx,sizeof(PROCESS_STACK_ALLOCATION_INFORMATION_EX));
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
			StackBase=&InfoEx->AllocInfo.StackBase;
			InfoEx=&InfoExDup;
		}
		ExtraType=InfoEx->ExtraType;
		if (ExtraType>0x10 || (InfoEx->Zero1|InfoEx->Zero2|InfoEx->Zero3)!=0)
			return STATUS_INVALID_PARAMETER;
		Info=&InfoEx->AllocInfo;
	}
	else if (ProcessInformationLength==sizeof(PROCESS_STACK_ALLOCATION_INFORMATION))
	{
		ExtraType=0;
		Info=(PROCESS_STACK_ALLOCATION_INFORMATION*)ProcessInformation;
		if (PreviousMode==UserMode)
		{
			__try
			{
				InfoExDup.AllocInfo.ReserveSize=Info->ReserveSize;;
				InfoExDup.AllocInfo.ZeroBits=Info->ZeroBits;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
			StackBase=&Info->StackBase;
			Info=&InfoExDup.AllocInfo;
		}
	}
	else
	{
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	if (Info->ReserveSize==0)
		return STATUS_INVALID_PARAMETER;

	LARGE_INTEGER CurrentTime;
	KeQuerySystemTime(&CurrentTime);
	ULONG64 tc=__rdtsc();
	ULONG Adjust=((tc+CurrentTime.QuadPart)&0x1F)+1;	//var_4C
	ULONG AllocationSize=Info->ReserveSize;		//var_160

	NTSTATUS Result;
	PKTHREAD Thread=KeGetCurrentThread();
	PKPROCESS Process=Thread->ApcState.Process;
	if (Process->Flags2&0x20000)	//StackRandomizationDisabled
	{
		Result=STATUS_UNSUCCESSFUL;
	}
	else if (Info->ZeroBits!=0 && Info->ZeroBits>21)
	{
		Result=STATUS_UNSUCCESSFUL;
	}
	else
	{
		//如果条件允许，寻找一块合适的区域，返回地址，以此地址为基分配内存
		Result=MiScanUserAddressSpace(0,AllocationSize,Adjust,Info->ZeroBits,&Info->StackBase);	//fastcall
		if (NT_SUCCESS(Result))
			Result=ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFF,&Info->StackBase,Info->ZeroBits,&Info->ReserveSize,ExtraType|MEM_RESERVE,PAGE_READWRITE);
	}

	//如果出现错误，随便分配一块内存
	if (!NT_SUCCESS(Result))
	{
		Info->StackBase=NULL;
		Result=ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFF,&Info->StackBase,Info->ZeroBits,&AllocationSize,ExtraType|MEM_RESERVE,PAGE_READWRITE);
	}

	if (NT_SUCCESS(Result))
	{
		if (PreviousMode==UserMode)
		{
			__try
			{
				*StackBase=Info->StackBase;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}	
		}
	}
	return Result;
}
*/

NTSTATUS NTAPI RtlCreateUserStack(ULONG StackCommitSize,ULONG StackReserveSize,ULONG ZeroBits,ULONG CommitAlign,ULONG ReserveAlign,INITIAL_TEB* InitialTeb)
{
	//应该是这个函数可以接受ExtraType，而不是BaseStaticServerData->SysInfo.PageSize自带
	BYTE ExtraType=(CommitAlign>>24)&0xFF;		//var_19
	CommitAlign=CommitAlign&0x00FFFFFF;	//ebx
	if (ExtraType>0x10)
		return STATUS_INVALID_PARAMETER;
	if (CommitAlign==0)
		return STATUS_INVALID_PARAMETER;
	if (ReserveAlign==0)
		return STATUS_INVALID_PARAMETER;
	if (ReserveAlign<CommitAlign)
		return STATUS_INVALID_PARAMETER;

	ULONG GuardSize=CommitAlign*2;
	PEB* Peb=NtCurrentTeb()->ProcessEnvironmentBlock;	//var_3C
	NTSTATUS Result;	//var_24
	if (StackCommitSize==0 || StackReserveSize==0)	//edi, esi
	{
		ULONG var_34;
		ULONG var_38;
		Result=STATUS_SUCCESS;
		__try
		{
			IMAGE_NT_HEADERS* ImageHeader=RtlImageNtHeader(Peb->ImageBaseAddress);
			if (ImageHeader==NULL)
			{
				Result=STATUS_INVALID_IMAGE_FORMAT;
			}
			else
			{
				var_34=ImageHeader->OptionalHeader.SizeOfStackCommit;
				var_38=ImageHeader->OptionalHeader.SizeOfStackReserve;
			}
		}
		__except(EXCEPTION_CONTINUE_SEARCH)
		{
			Result=GetExceptionCode();
		}
		if (!NT_SUCCESS(Result))
			return Result;
		if (StackCommitSize==0)
			StackCommitSize=var_34;
		if (StackReserveSize==0)
			StackReserveSize=var_38;
	}
	if (StackCommitSize==0)
		StackCommitSize=16*1024;
	if (StackCommitSize>=StackReserveSize)
		StackReserveSize=(StackCommitSize+0x000FFFFF)&0xFFF00000;

	StackCommitSize=StackCommitSize+CommitAlign-1;
	StackCommitSize=StackCommitSize & ~(CommitAlign-1);

	StackReserveSize=StackReserveSize+ReserveAlign-1;
	StackReserveSize=StackReserveSize & ~(ReserveAlign-1);

	ULONG MinimumStackCommit;	//var_48
	__try
	{
		MinimumStackCommit=Peb->MinimumStackCommit;
	}
	__except(EXCEPTION_CONTINUE_SEARCH)
	{
		return GetExceptionCode();
	}
	if (MinimumStackCommit!=0 && StackCommitSize<MinimumStackCommit)
	{
		StackCommitSize=MinimumStackCommit+CommitAlign-1;
		StackCommitSize=StackCommitSize & ~(CommitAlign-1);

		StackReserveSize=(StackCommitSize+0x000FFFFF)&0xFFF00000;
		StackReserveSize=StackReserveSize+ReserveAlign-1;
		StackReserveSize=StackReserveSize & ~(ReserveAlign-1);
	}

	PROCESS_STACK_ALLOCATION_INFORMATION_EX StackAllocationInfo;
	StackAllocationInfo.ExtraType=ExtraType;
	StackAllocationInfo.Zero1=0;
	StackAllocationInfo.Zero2=0;
	StackAllocationInfo.Zero3=0;
	StackAllocationInfo.AllocInfo.ReserveSize=StackReserveSize;
	StackAllocationInfo.AllocInfo.ZeroBits=ZeroBits;

	//XP不支持ProcessThreadStackAllocation，参考NtSetInformationProcess41
	Result=NtSetInformationProcess((HANDLE)0xFFFFFFFF,ProcessThreadStackAllocation,&StackAllocationInfo,sizeof(StackAllocationInfo));
	if (!NT_SUCCESS(Result))
		return Result;

	InitialTeb->OldInitialTeb.OldStackBase=NULL;
	InitialTeb->OldInitialTeb.OldStackLimit=NULL;
	//分配内存指针，从低地址到高地址
	InitialTeb->StackAllocationBase=StackAllocationInfo.AllocInfo.StackBase;
	//栈内存指针，从高地址到低地址
	InitialTeb->StackBase=(UCHAR*)StackAllocationInfo.AllocInfo.StackBase+StackReserveSize;

	//可以只提交一部分内存用做栈，剩下部分不实际使用
	PVOID CommitAddress=(UCHAR*)StackAllocationInfo.AllocInfo.StackBase+StackReserveSize-StackCommitSize;
	BOOL IsProtect;
	if (StackReserveSize-StackCommitSize<GuardSize)
		IsProtect=FALSE;
	else
	{
		//如果未提交部分够大，可以将栈顶的部分空间设为PAGE_GUARD，防止栈溢出
		CommitAddress=(UCHAR*)CommitAddress-GuardSize;
		StackCommitSize+=GuardSize;
		IsProtect=TRUE;
	}
	ULONG CommitSize=StackCommitSize;
	Result=NtAllocateVirtualMemory((HANDLE)0xFFFFFFFF,&CommitAddress,0,&CommitSize,MEM_COMMIT,PAGE_READWRITE);
	if (!NT_SUCCESS(Result))
	{
		RtlFreeUserStack(InitialTeb->StackAllocationBase);
		return Result;
	}

	InitialTeb->StackLimit=CommitAddress;
	if (IsProtect)
	{
		ULONG OldProtect;
		ULONG ProtectSize=GuardSize;
		Result=NtProtectVirtualMemory((HANDLE)0xFFFFFFFF,&CommitAddress,&ProtectSize,PAGE_GUARD|PAGE_READWRITE,&OldProtect);
		if (!NT_SUCCESS(Result))
		{
			RtlFreeUserStack(InitialTeb->StackAllocationBase);
			return Result;
		}
		//设为PAGE_GUARD的部分不能使用
		InitialTeb->StackLimit=(UCHAR*)InitialTeb->StackLimit+ProtectSize;
	}
	return STATUS_SUCCESS;
}

VOID NTAPI RtlFreeUserStack(PVOID Address)
{
	ULONG FreeSize=0;
	NtFreeVirtualMemory((HANDLE)0xFFFFFFFF,&Address,&FreeSize,MEM_RELEASE);
}

VOID NTAPI LdrShutdownThread()
{
/*
	FLS_DATA_INFO* FlsData=NtCurrentTeb()->FlsData;
	if (FlsData!=NULL)
		RtlProcessFlsData(FlsData);*/

	//RtlIsCurrentThreadAttachExempt
	//RtlEnterCriticalSection
	//LdrpImageHasTls
	//RtlActivateActivationContextUnsafeFast
	//LdrpCallTlsInitializers
	//LdrpCallInitRoutine
	//RtlDeactivateActivationContextUnsafeFast
	//RtlLeaveCriticalSection
	//LdrpFreeTls
	//RtlFreeHeap
	//RtlFreeThreadActivationContextStack
}

VOID NTAPI LdrShutdownProcess()
{
/*
	FLS_DATA_INFO* FlsData=NtCurrentTeb()->FlsData;
	if (FlsData!=NULL)
		RtlProcessFlsData(FlsData);*/

	//LdrpLogDbgPrint
	//RtlDecodeSystemPointer
	//RtlEnterCriticalSection
	//RtlpHeapIsLocked
	//RtlpInitializeActivationContextStack
	//RtlpInitializeActivationContextStackFrameList
	//LdrpImageHasTls
	//RtlActivateActivationContextUnsafeFast
	//LdrpCallTlsInitializers
	//LdrpCallInitRoutine
	//RtlDeactivateActivationContextUnsafeFast
	//SbtLogExeTerminating
	//RtlDetectHeapLeaks
	//SbCleanupTrace
	//EtwShutdownProcess
	//RtlLeaveCriticalSection
}

NTSTATUS NTAPI RtlExitUserThread(ULONG ExitCode)
{
	//XP
	//LdrShutdownThread
	//NtTerminateThread

	//Win7
	/*
	ULONG IsLastThread=FALSE;
	NTSTATUS Result=NtQueryInformationThread(NtCurrentThread(),ThreadAmILastThread,&IsLastThread,4);
	if (!NT_SUCCESS(Result) || IsLastThread==FALSE)
	{
		LdrShutdownThread();
		TpCheckTerminateWorker(NULL);
		NtTerminateThread((HANDLE)0,ExitCode);
	}
	RtlExitUserProcess(ExitStatus);
	*/
	_asm int 3;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlExitUserProcess(NTSTATUS ExitStatus)
{
	/*
	EtwShutdownProcess(0);
	RtlEnterCriticalSection(&LdrpLoaderLock);
	RtlEnterCriticalSection(&FastPebLock);
	RtlLockHeap(RtlGetProcessHeap());
	ExitStatus=NtTerminateProcess((HANDLE)0,ExitStatus);
	RtlUnlockHeap(RtlGetProcessHeap());
	RtlLeaveCriticalSection(&FastPebLock);
	RtlLeaveCriticalSection(&LdrpLoaderLock);
	if (NT_SUCCESS(ExitStatus))
	{
		RtlReportSilentProcessExit(NtCurrentProcess(),ExitStatus);
		LdrShutdownProcess();
		NtTerminateProcess(NtCurrentProcess(),ExitStatus);
	}
	else
	{
		NterminateThread(NtCurrentThread(),ExitStatus);
	}
	*/
	return STATUS_SUCCESS;
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