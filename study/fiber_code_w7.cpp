
#include "fiber_def_w7.h"

typedef struct _FIBER
{
	PVOID FiberUserData;	//+0 本来叫FiberData，和TEB字段重名了
	_EXCEPTION_REGISTRATION_RECORD* ExceptionList;	//+4
	PVOID StackBase;	//+8
	PVOID StackLimit;	//+C
	PVOID DeallocationStack;	//+10
	CONTEXT FiberContext;	//+14
	PVOID Wx86Tib;	//+2E0 Wx86TIB*
	ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;	//+2E4
	PVOID FlsData;		//+2E8 FLS_DATA_INFO*
	ULONG GuaranteedStackBytes;	//+2EC
	USHORT TebFlags;	//+2F0
	USHORT ReservedPad;	//+2F2
} FIBER, *PFIBER;

#define FLS_MAX_SLOT	128

typedef struct _FLS_DATA_INFO
{
	LIST_ENTRY FlsLink;
	PVOID FlsSlot[FLS_MAX_SLOT];
} FLS_DATA_INFO;

/*
typedef struct _FLS_CALLBACK_INFO
{
	PFLS_CALLBACK_FUNCTION CallbackFunc;
	RTL_SRWLOCK FlsCbLock;
} FLS_CALLBACK_INFO;*/

RTL_BITMAP FlsBitMap;
RTL_SRWLOCK RtlpFlsLock=RTL_SRWLOCK_INIT;

void WINAPI LdrpInitializeProcess()
{
	//PEB里FLS相关的几个字段，所有线程共用一份
	//Bitmap和ListHead由Loader初始化，剩下的字段只有用到时，才会分配内存
	//整个进程只允许分配128个FLS，且第一个Slot保留
	PEB* Peb=NtCurrentTeb()->ProcessEnvironmentBlock;
	Peb->FlsBitmap=&FlsBitMap;
	RtlInitializeBitMap(&FlsBitMap,Peb->FlsBitmapBits,FLS_MAX_SLOT);
	//RtlSetBit(&FlsBitMap,0); ntdll用的RtlSetBit没导出
	RtlSetBits(&FlsBitMap,0,1);
	Peb->FlsListHead.Blink=&Peb->FlsListHead;
	Peb->FlsListHead.Flink=&Peb->FlsListHead;
}

//Fiber和Fls与线程无关
//整个进程有128个Fls索引，所有Fiber共用，一个Fiber申请完，剩下的Fiber都无法申请
//每个Fls索引对应一个Callback，在释放Fls索引、删除Fiber，以及线程退出时调用
//（RtlFlsFree、DeleteFiber、LdrShutdownThread）
//但每个Fiber都有自己的一份FLS_DATA_INFO，各个Fiber的Fls相互独立
//Fls第一次用到时（RtlFlsAlloc或FlsSetValue）分配，同时也会加入进程的FlsListHead里

//理论上只有自己分配索引的Fls可用，实际上自己的128个槽都可以随便访问
//（另一个任务的一组Fiber分配了槽x，当前任务的这组Fiber仍然可以使用自己的槽x）
//虽然空着不少，浪费了空间，但是对效率有巨大的提升

//当需要通知时，进程横向遍历所有Fls中指定的索引，或纵向遍历单个Fiber中所有的索引
//从对应位置的槽中取出值，作为参数调用回调
//Func=Global.FlsCallback[i]
//Param=Thread.FlsData[i]
//XP没有RtlExitUserThread，主动调用ExitThread退出线程可能会丢失通知

NTSTATUS NTAPI RtlFlsAlloc(PFLS_CALLBACK_FUNCTION CallbackFunc,PULONG IndexOut)
{
	TEB* Teb=NtCurrentTeb();
	PEB* Peb=Teb->ProcessEnvironmentBlock;
	FLS_DATA_INFO* FlsDataBlock=NULL;
	FLS_CALLBACK_INFO* FlsCallbackBlock=NULL;

	if (Teb->FlsData==NULL)
	{
		//NtdllBaseTag+0x2C000
		FlsDataBlock=(FLS_DATA_INFO*)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(FLS_DATA_INFO));
		if (FlsDataBlock==NULL)
			return STATUS_NO_MEMORY;
		Teb->FlsData=FlsDataBlock;
	}

	if (Peb->FlsCallback==NULL)
	{
		//NtdllBaseTag+0x2C000
		FlsCallbackBlock=(FLS_CALLBACK_INFO*)RtlAllocateHeap(RtlGetProcessHeap(),0,FLS_MAX_SLOT*sizeof(FLS_CALLBACK_INFO));
		if (FlsCallbackBlock==NULL)
		{
			if (FlsDataBlock!=NULL)
			{
				Teb->FlsData=NULL;
				RtlFreeHeap(RtlGetProcessHeap(),0,FlsDataBlock);
			}
			return STATUS_NO_MEMORY;
		}
		for (int i=0;i<FLS_MAX_SLOT;i++)
		{
			FlsCallbackBlock[i].CallbackFunc=NULL;
			RtlInitializeSRWLock(&FlsCallbackBlock[i].FlsCbLock);
		}
	}

	NTSTATUS Result=STATUS_SUCCESS;
	RtlAcquireSRWLockExclusive(&RtlpFlsLock);
	if (FlsCallbackBlock!=NULL && Peb->FlsCallback==NULL)
	{
		Peb->FlsCallback=FlsCallbackBlock;
		FlsCallbackBlock=NULL;
	}
	if (FlsDataBlock!=NULL)
	{
		LIST_ENTRY* FlsListHead=&Peb->FlsListHead;
		LIST_ENTRY* Last=FlsListHead->Blink;
		FlsDataBlock->FlsLink.Flink=FlsListHead;
		FlsDataBlock->FlsLink.Blink=Last;
		Last->Flink=(LIST_ENTRY*)FlsDataBlock;
		FlsListHead->Blink=(LIST_ENTRY*)FlsDataBlock;
		FlsDataBlock=NULL;
	}
	ULONG Index=RtlFindClearBitsAndSet((RTL_BITMAP*)Peb->FlsBitmap,1,1);
	if (Index!=0xFFFFFFFF)
	{
		Peb->FlsCallback[Index].CallbackFunc=CallbackFunc;
		((FLS_DATA_INFO*)Teb->FlsData)->FlsSlot[Index]=NULL;
		if (Index>Peb->FlsHighIndex)
			Peb->FlsHighIndex=Index;
	}
	else
	{
		Result=STATUS_NO_MEMORY;
	}
	RtlReleaseSRWLockExclusive(&RtlpFlsLock);

	if (FlsCallbackBlock!=NULL)
		RtlFreeHeap(RtlGetProcessHeap(),0,FlsCallbackBlock);
	if (!NT_SUCCESS(Result))
	{
		if (FlsDataBlock!=NULL)
		{
			Teb->FlsData=NULL;
			RtlFreeHeap(RtlGetProcessHeap(),0,FlsDataBlock);
		}
	}
	else
	{
		*IndexOut=Index;
	}
	return Result;
}

NTSTATUS NTAPI RtlFlsFree(ULONG Index)
{
	PEB* Peb=NtCurrentTeb()->ProcessEnvironmentBlock;
	if (Index==0 || Index>=128)	//Index>127
		return STATUS_INVALID_PARAMETER;

	RtlAcquireSRWLockExclusive(&RtlpFlsLock);
	BOOL IsUse=RtlAreBitsSet(Peb->FlsBitmap,Index,1);
	if (IsUse)
	{
		RtlClearBits(Peb->FlsBitmap,Index,1);
		PFLS_CALLBACK_FUNCTION CallbackFunc=Peb->FlsCallback[Index].CallbackFunc;
		RtlAcquireSRWLockExclusive(&Peb->FlsCallback[Index].FlsCbLock);
		LIST_ENTRY* FlsListHead=&Peb->FlsListHead;
		LIST_ENTRY* Entry=FlsListHead->Flink;
		if (Entry!=FlsListHead)
		{
			ULONG Offset=sizeof(LIST_ENTRY)+sizeof(PVOID)*Index;
			do 
			{
				if (CallbackFunc!=NULL)
				{
					//FlsSlotValue=((FLS_DATA_INFO*)Entry)->FlsSlot[Index];
					PVOID FlsSlotValue=*(PVOID*)((UCHAR*)Entry+Offset);
					if (FlsSlotValue!=NULL)
						CallbackFunc(FlsSlotValue);
				}
				//((FLS_DATA_INFO*)Entry)->FlsSlot[Index]=NULL;
				*(PVOID*)((UCHAR*)Entry+Offset)=NULL;
				Entry=Entry->Flink;
			} while (Entry!=FlsListHead);
		}
		Peb->FlsCallback[Index].CallbackFunc=NULL;
		RtlReleaseSRWLockExclusive(&Peb->FlsCallback[Index].FlsCbLock);
	}
	RtlReleaseSRWLockExclusive(&RtlpFlsLock);

	if (IsUse==FALSE)
		return STATUS_INVALID_PARAMETER;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlProcessFlsData(FLS_DATA_INFO* FlsDataBlock)
{
	TEB* Teb=NtCurrentTeb();
	PEB* Peb=Teb->ProcessEnvironmentBlock;
	//为Fiber分配Fls，并插入到进程Fls链表
	//callback只有一份，在RtlFlsAlloc已经分配了，这里不再处理
	if (FlsDataBlock==NULL)
	{
		//NtdllBaseTag+0x2C000
		FlsDataBlock=(FLS_DATA_INFO*)RtlAllocateHeap(RtlGetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(FLS_DATA_INFO));
		if (FlsDataBlock==NULL)
			return STATUS_NO_MEMORY;
		Teb->FlsData=FlsDataBlock;
		RtlAcquireSRWLockExclusive(&RtlpFlsLock);
		LIST_ENTRY* FlsListHead=&Peb->FlsListHead;
		LIST_ENTRY* Last=FlsListHead->Blink;
		FlsDataBlock->FlsLink.Flink=FlsListHead;
		FlsDataBlock->FlsLink.Blink=Last;
		Last->Flink=(LIST_ENTRY*)FlsDataBlock;
		FlsListHead->Blink=(LIST_ENTRY*)FlsDataBlock;
		RtlReleaseSRWLockExclusive(&RtlpFlsLock);
		return STATUS_SUCCESS;
	}
	//通知Fiber的所有Slot，并从进程Fls链表移除Fls
	else
	{
		ULONG FlsHighIndex=Peb->FlsHighIndex;
		//for (Index=1,FlsSlot=&FlsDataBlock->FlsSlot[1];Index<=FlsHighIndex;Index++;FlsSlot++)
		ULONG Index=1;
		if (Index<=FlsHighIndex)
		{
			PVOID* FlsSlot=&FlsDataBlock->FlsSlot[1];
			do 
			{
				if (*FlsSlot!=NULL)
				{
					RtlAcquireSRWLockShared(&Peb->FlsCallback[Index].FlsCbLock);
					PFLS_CALLBACK_FUNCTION CallbackFunc=Peb->FlsCallback[Index].CallbackFunc;
					if (CallbackFunc!=NULL && *FlsSlot!=NULL)
					{
						CallbackFunc(*FlsSlot);
						*FlsSlot=NULL;
					}
					RtlReleaseSRWLockShared(&Peb->FlsCallback[Index].FlsCbLock);
				}
				Index++;
				FlsSlot++;
			} while (Index<=FlsHighIndex);
		}
		RtlAcquireSRWLockExclusive(&RtlpFlsLock);
		LIST_ENTRY* Next=FlsDataBlock->FlsLink.Flink;
		LIST_ENTRY* Back=FlsDataBlock->FlsLink.Blink;
		Back->Flink=Next;
		Next->Blink=Back;
		RtlReleaseSRWLockExclusive(&RtlpFlsLock);
		return STATUS_SUCCESS;
	}
}

DWORD WINAPI K32FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback)
{
	ULONG FlsIndex;
	NTSTATUS Result=RtlFlsAlloc(lpCallback,&FlsIndex);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		FlsIndex=FLS_OUT_OF_INDEXES;
	}
	return FlsIndex;
}

BOOL WINAPI K32FlsFree(DWORD dwFlsIndex)
{
	NTSTATUS Result=RtlFlsFree(dwFlsIndex);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}
	return TRUE;
}

PVOID WINAPI K32FlsGetValue(DWORD dwFlsIndex)
{
	FLS_DATA_INFO* FlsData=(FLS_DATA_INFO*)NtCurrentTeb()->FlsData;
	if (dwFlsIndex-1>126 || FlsData==NULL)	//dwFlsIndex==0 || dwFlsIndex>127
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return NULL;
	}
	NtCurrentTeb()->LastErrorValue=ERROR_SUCCESS;
	return FlsData->FlsSlot[dwFlsIndex];
}

BOOL WINAPI K32FlsSetValue(DWORD dwFlsIndex,PVOID lpFlsData)
{
	if (dwFlsIndex-1>126)	//dwFlsIndex==0 || dwFlsIndex>127
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}
	//FlsData为NULL时，需要RtlProcessFlsData分配完再获取
	if (NtCurrentTeb()->FlsData==NULL)
	{
		NTSTATUS Result=RtlProcessFlsData(NULL);
		if (!NT_SUCCESS(Result))
		{
			BaseSetLastNTError(Result);
			return FALSE;
		}
	}
	FLS_DATA_INFO* FlsData=(FLS_DATA_INFO*)NtCurrentTeb()->FlsData;
	FlsData->FlsSlot[dwFlsIndex]=lpFlsData;
	return TRUE;
}



//https://github.com/reactos/reactos/blob/3fa57b8ff7fcee47b8e2ed869aecaf4515603f3f/dll/win32/kernel32/client/i386/fiber.S
//https://github.com/reactos/reactos/blob/3fa57b8ff7fcee47b8e2ed869aecaf4515603f3f/dll/win32/kernel32/client/fiber.c

//FLDENV 965
//FNSTCW 995
//FSTSW 999
//LDMXCSR 1141
//STMXCSR 1829

#define fstsw(FPU_status_word_out)		_asm mov edi,edi
#define fnstcw(FPU_control_word_out)	_asm mov edi,edi
#define stmxcsr(MXCSR_out)				_asm mov edi,edi
#define fldenv(FPU_environment_in)		_asm mov edi,edi
#define ldmxcsr(MXCSR_in)				_asm mov edi,edi
#define RegGet(ptr,reg)					
#define RegSet(reg,ptr)					

//这个函数的功能必须用汇编实现，这里仅给出伪代码
void WINAPI K32SwitchToFiber(LPVOID lpFiber)
{
	TEB* Teb=NtCurrentTeb();
	FIBER* OldFiber=(FIBER*)Teb->NtTib.FiberData;
	RegGet(OldFiber->FiberContext.Ebx,ebx);
	RegGet(OldFiber->FiberContext.Edi,edi);
	RegGet(OldFiber->FiberContext.Esi,esi);
	RegGet(OldFiber->FiberContext.Ebp,ebp);

	if (OldFiber->FiberContext.ContextFlags==(CONTEXT_FULL|CONTEXT_FLOATING_POINT))
	{
		fstsw(&OldFiber->FiberContext.FloatSave.StatusWord);
		fnstcw(&OldFiber->FiberContext.FloatSave.ControlWord);
		if (*(BYTE*)0x7FFE027A==TRUE)
			stmxcsr(&OldFiber->FiberContext.Dr6);
	}
	//这一句是关键，调用SwitchToFiber时，将返回地址压入栈中
	//将esp保存到当前的FIBER结构体，就相当于保存了当前Fiber的回调函数
	//切换Fiber时，只要修改esp，就可以通过retn指令跳转到目标eip
	//XP中是显式的从栈中取出地址存到eip里，再通过jmp指令跳到目标eip
	RegGet(OldFiber->FiberContext.Esp,esp);

	OldFiber->FlsData=Teb->FlsData;
	OldFiber->ActivationContextStackPointer=Teb->ActivationContextStackPointer;
	OldFiber->ExceptionList=Teb->NtTib.ExceptionList;
	OldFiber->StackLimit=Teb->NtTib.StackLimit;
	OldFiber->GuaranteedStackBytes=Teb->GuaranteedStackBytes;

	FIBER* NewFiber=(FIBER*)lpFiber;
	Teb->NtTib.FiberData=NewFiber;
	Teb->NtTib.ExceptionList=NewFiber->ExceptionList;
	Teb->NtTib.StackBase=NewFiber->StackBase;
	Teb->NtTib.StackLimit=NewFiber->StackLimit;
	Teb->DeallocationStack=NewFiber->DeallocationStack;
	Teb->GuaranteedStackBytes=NewFiber->GuaranteedStackBytes;
	Teb->ActivationContextStackPointer=NewFiber->ActivationContextStackPointer;

	Teb->RtlExceptionAttached=FALSE;
	Teb->SameTebFlags=(Teb->SameTebFlags)|(NewFiber->TebFlags&0xFF00);

	if (NewFiber->FiberContext.ContextFlags==(CONTEXT_FULL|CONTEXT_FLOATING_POINT))
	{
		if (OldFiber->FiberContext.FloatSave.StatusWord!=NewFiber->FiberContext.FloatSave.StatusWord ||
			OldFiber->FiberContext.FloatSave.ControlWord!=NewFiber->FiberContext.FloatSave.ControlWord)
		{
			NewFiber->FiberContext.FloatSave.TagWord=0xFFFF;
			fldenv(NewFiber->FiberContext.FloatSave.ControlWord);
		}
		if (*(BYTE*)0x7FFE027A==TRUE)
			ldmxcsr(NewFiber->FiberContext.Dr6);
	}

	RegSet(edi,NewFiber->FiberContext.Edi);
	RegSet(esi,NewFiber->FiberContext.Esi);
	RegSet(ebp,NewFiber->FiberContext.Ebp);
	RegSet(ebx,NewFiber->FiberContext.Ebx);
	Teb->FlsData=NewFiber->FlsData;

	//esp保存着新Fiber的返回地址，返回到调用SwitchToFiber之前的位置
	RegSet(esp,NewFiber->FiberContext.Esp);
	return ;
}

void WINAPI _BaseFiberStart()
{
	TEB* Teb=NtCurrentTeb();
	FIBER* Fiber=(FIBER*)Teb->NtTib.FiberData;
	Fiber->TebFlags=Teb->SameTebFlags&0x200;	//RtlExceptionAttached
	LPFIBER_START_ROUTINE FiberRoutine=(LPFIBER_START_ROUTINE)Fiber->FiberContext.Eax;
	PVOID lpParameter=(PVOID)Fiber->FiberContext.Ebx;
	//原代码是ebp-4，因为没有push ebp和mov ebp,esp
	_asm and dword ptr [ebp+4], 0;	//call ret = 0
	FiberRoutine(lpParameter);
	RtlExitUserThread(0);
	_asm nop;
	_asm nop;
}

void WINAPI BaseFiberStart()
{
	//里面会设置Teb->RtlExceptionAttached
	EXCEPTION_REGISTRATION_RECORD ExceptionRegistrationRecord;
	RtlInitializeExceptionChain(&ExceptionRegistrationRecord);
	_BaseFiberStart();
	_asm int 3;
}

void WINAPI BaseInitializeFiberContext(CONTEXT* FiberContext,PVOID lpParameter,LPFIBER_START_ROUTINE lpStartAddress,PVOID StackBase)
{
	DWORD InputFlags=FiberContext->ContextFlags;
	FiberContext->Eax=(DWORD)lpStartAddress;
	FiberContext->Ebx=(DWORD)lpParameter;
	FiberContext->SegEs=0x20;
	FiberContext->SegDs=0x20;
	FiberContext->SegSs=0x20;
	FiberContext->SegGs=0;
	FiberContext->SegFs=0x38;
	FiberContext->SegCs=0x18;
	FiberContext->ContextFlags=CONTEXT_FULL;

	DWORD Adjust=0;	//eax
	if (NtCurrentTeb()->ProcessEnvironmentBlock->IsImageDynamicallyRelocated)
	{
		DWORD64 a=__rdtsc();	//随机
		DWORD64 b=BaseStaticServerData->SysInfo.PageSize/8;
		DWORD m=(DWORD)(a%b);	//__aullrem
		Adjust=m*4;				//对齐
	}

	//随机栈基址，并分配2个位置
	FiberContext->Esp=(DWORD)StackBase-Adjust-8;
	//XP下把BaseFiberStart设为FiberContext->Eip，使用jmp跳转，而Win7放在栈中通过retn跳转
	*(DWORD*)FiberContext->Esp=(DWORD)BaseFiberStart;
	FiberContext->ContextFlags|=InputFlags;
	if (InputFlags==CONTEXT_FLOATING_POINT)
	{
		FiberContext->FloatSave.ControlWord=0x27F;
		FiberContext->FloatSave.StatusWord=0;
		FiberContext->FloatSave.TagWord=0xFFFF;
		FiberContext->FloatSave.ErrorOffset=0;
		FiberContext->FloatSave.ErrorSelector=0;
		FiberContext->FloatSave.DataOffset=0;
		FiberContext->FloatSave.DataSelector=0;
		//Win8不再进行此判断，大概是默认新CPU都支持此特性（SIMD）
		//KUserSharedData->ProcessorFeatures[6]
		if (*(BYTE*)0x7FFE027A==TRUE)
			FiberContext->Dr6=0x1F80;	//The default MXCSR value at reset is 1F80H. LDMXCSR 1141页
	}
}

//返回FIBER::FiberUserData
//__inline PVOID GetFiberData( void )    { return *(PVOID *) (ULONG_PTR) __readfsdword (0x10);}
//返回FIBER*
//__inline PVOID GetCurrentFiber( void ) { return (PVOID) (ULONG_PTR) __readfsdword (0x10);}

//Win7新增
BOOL WINAPI K32IsThreadAFiber()
{
	return NtCurrentTeb()->HasFiberData;
}

//Win7新增 实际返回FIBER*
LPVOID WINAPI K32ConvertThreadToFiberEx(LPVOID lpParameter,DWORD dwFlags)
{
	if (dwFlags&(~FIBER_FLAG_FLOAT_SWITCH))
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	TEB* Teb=NtCurrentTeb();
	PEB* Peb=Teb->ProcessEnvironmentBlock;

	if (Teb->HasFiberData)
	{
		RtlSetLastWin32Error(ERROR_ALREADY_FIBER);
		return NULL;
	}

	FIBER* Fiber=(FIBER*)RtlAllocateHeap(RtlGetProcessHeap(),BaseDllTag,sizeof(FIBER));
	if (Fiber==NULL)
	{
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	//主Fiber使用线程的Routine，相关资源从TEB获取
	Fiber->FiberUserData=lpParameter;
	Fiber->StackBase=Teb->NtTib.StackBase;
	Fiber->StackLimit=Teb->NtTib.StackLimit;
	Fiber->DeallocationStack=Teb->DeallocationStack;
	Fiber->ExceptionList=Teb->NtTib.ExceptionList;
	Fiber->FlsData=Teb->FlsData;
	Fiber->GuaranteedStackBytes=Teb->GuaranteedStackBytes;
	Fiber->TebFlags=Teb->SameTebFlags&0x200; //RtlExceptionAttached
	Fiber->ActivationContextStackPointer=Teb->ActivationContextStackPointer;
	Fiber->FiberContext.ContextFlags=CONTEXT_FULL;
	if (dwFlags&FIBER_FLAG_FLOAT_SWITCH)
		Fiber->FiberContext.ContextFlags=CONTEXT_FULL|CONTEXT_FLOATING_POINT;
	Fiber->Wx86Tib=NULL;

	Teb->HasFiberData=TRUE;
	Teb->NtTib.FiberData=Fiber;
	return Fiber;
}

//实际返回FIBER*
LPVOID WINAPI K32ConvertThreadToFiber(LPVOID lpParameter)
{
	return ConvertThreadToFiberEx(lpParameter,0);
}

//实际返回FIBER*
LPVOID WINAPI K32CreateFiberEx(SIZE_T dwStackCommitSize,SIZE_T dwStackReserveSize,DWORD dwFlags,LPFIBER_START_ROUTINE lpStartAddress,LPVOID lpParameter)
{
	//XP
	//Fiber=RtlAllocateHeap
	//BaseCreateStack
	//BaseInitializeContext

	ACTIVATION_CONTEXT_STACK* ActivationContextStack=NULL;	//var_4
	if (dwFlags&(~FIBER_FLAG_FLOAT_SWITCH))
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return NULL;
	}
	NTSTATUS Result=RtlAllocateActivationContextStack(&ActivationContextStack);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return NULL;
	}

	FIBER* Fiber=(FIBER*)RtlAllocateHeap(RtlGetProcessHeap(),BaseDllTag,sizeof(FIBER));
	if (Fiber==NULL)
	{
		RtlFreeActivationContextStack(ActivationContextStack);
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	//XP是BaseCreateStack(0xFFFFFFFF,dwStackCommitSize,dwStackReserveSize,&InitialTeb);
	INITIAL_TEB InitialTeb;		//var_18
	Result=RtlCreateUserStack(dwStackCommitSize,dwStackReserveSize,0,BaseStaticServerData->SysInfo.PageSize,
		BaseStaticServerData->SysInfo.AllocationGranularity,&InitialTeb);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		RtlFreeActivationContextStack(ActivationContextStack);
		RtlFreeHeap(RtlGetProcessHeap(),0,Fiber);
		return NULL;
	}

	//新Fiber需要新建栈，初始化CONTEXT结构体，然后等待执行
	memset(&Fiber->FiberContext,0,sizeof(CONTEXT));
	Fiber->FiberUserData=lpParameter;
	Fiber->StackBase=InitialTeb.StackBase;
	Fiber->StackLimit=InitialTeb.StackLimit;
	Fiber->ExceptionList=(_EXCEPTION_REGISTRATION_RECORD*)(-1);
	Fiber->DeallocationStack=InitialTeb.StackAllocationBase;
	Fiber->Wx86Tib=NULL;
	Fiber->FlsData=NULL;
	Fiber->GuaranteedStackBytes=0;
	Fiber->TebFlags=0;
	Fiber->ActivationContextStackPointer=ActivationContextStack;
	//将FIBER_FLAG_FLOAT_SWITCH转换为CONTEXT_FLOATING_POINT
	//BaseInitializeFiberContext里，最终会额外加上CONTEXT_FULL
	Fiber->FiberContext.ContextFlags=(dwFlags&FIBER_FLAG_FLOAT_SWITCH)?CONTEXT_FLOATING_POINT:0;

	//XP是BaseInitializeContext(&Fiber->FiberContext,lpParameter,lpStartAddress,InitialTeb.StackBase,2);
	BaseInitializeFiberContext(&Fiber->FiberContext,lpParameter,lpStartAddress,InitialTeb.StackBase);
	return Fiber;
}

//实际返回FIBER*
LPVOID WINAPI K32CreateFiber(SIZE_T dwStackSize,LPFIBER_START_ROUTINE lpStartAddress,LPVOID lpParameter)
{
	return K32CreateFiberEx(dwStackSize,0,0,lpStartAddress,lpParameter);
}

//参数实际是FIBER*
void WINAPI K32DeleteFiber(LPVOID lpFiber)
{
	//XP
	//（Teb->NtTib.FiberData==Fiber时）
	//RtlFreeHeap(Fiber)
	//ExitThread
	//或（Teb->NtTib.FiberData!=Fiber时）
	//NtFreeVirtualMemory(Fiber->DeallocationStack)
	//RtlFreeHeap(Fiber)

	TEB* Teb=NtCurrentTeb();
	PEB* Peb=Teb->ProcessEnvironmentBlock;

	FIBER* Fiber=(FIBER*)lpFiber;
	//删除当前正在执行的Fiber将导致线程退出，FIBER结构体和TEB存储的一致
	if (Teb->HasFiberData && Teb->NtTib.FiberData==Fiber)
	{
		RtlExitUserThread(1);
		/*
		//RtlExitUserThread里调用LdrShutdownThread，最终进行了如下操作
		FLS_DATA_INFO* FlsData=Teb->FlsData;
		if (FlsData!=NULL)
			RtlProcessFlsData(FlsData);
		if (FlsData!=NULL)
		{
			Teb->FlsData=NULL;
			RtlFreeHeap(RtlGetProcessHeap(),0,FlsData);
		}
		if (Teb->HasFiberData)
		{
			Fiber=Teb->NtTib.FiberData;
			Teb->NtTib.FiberData=NULL;
			RtlFreeHeap(RtlGetProcessHeap(),0,Fiber);
		}
		*/
	}
	//由当前运行的Fiber删除其它Fiber，使用目标Fiber的FIBER结构体
	else
	{
		RtlFreeUserStack(Fiber->DeallocationStack);
		FLS_DATA_INFO* FlsData=(FLS_DATA_INFO*)Fiber->FlsData;
		if (FlsData!=NULL)
		{
			__try
			{
				RtlProcessFlsData(FlsData);
			}
			__finally
			{
				RtlFreeHeap(RtlGetProcessHeap(),0,FlsData);
			}
		}
		RtlFreeActivationContextStack(Fiber->ActivationContextStackPointer);
		RtlFreeHeap(RtlGetProcessHeap(),0,Fiber);
	}
}

BOOL WINAPI K32ConvertFiberToThread()
{
	TEB* Teb=NtCurrentTeb();
	if (Teb->HasFiberData==FALSE)
	{
		RtlSetLastWin32Error(ERROR_ALREADY_THREAD);
		return FALSE;
	}
	Teb->HasFiberData=FALSE;
	FIBER* FiberData=(FIBER*)Teb->NtTib.FiberData;
	Teb->NtTib.FiberData=NULL;
	RtlFreeHeap(RtlGetProcessHeap(),0,FiberData);
	return TRUE;
}