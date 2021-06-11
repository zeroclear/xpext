
#include "common.h"

extern "C"
{
	VOID NTAPI
		RtlInitializeBitMap(
		IN PRTL_BITMAP  BitMapHeader,
		IN PULONG  BitMapBuffer,
		IN ULONG  SizeOfBitMap
		); 

	VOID NTAPI
		RtlSetBits(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  StartingIndex,
		IN ULONG  NumberToSet
		); 

	VOID NTAPI
		RtlClearBits(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  StartingIndex,
		IN ULONG  NumberToClear
		); 

	ULONG NTAPI
		RtlFindClearBitsAndSet(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  NumberToFind,
		IN ULONG  HintIndex
		); 

	BOOLEAN NTAPI
		RtlAreBitsSet(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  StartingIndex,
		IN ULONG  Length
		); 
};


/*
注：因为线程和纤程拼音相同，以下Thread叫线程，Fiber直接叫Fiber
而全大写的FIBER指struct FIBER

概述：
Windows的Fiber是协程的一种实现，在一个线程里同时只有一个Fiber能够执行
当前Fiber执行完毕后，将执行权交给其它Fiber，通过轮流执行的方式模拟并发
切换的时机由开发者控制，切换的过程由系统实现，完全在用户层完成

Fiber实现的总体策略是将当前线程作为容器，装载不同Fiber模块执行具体代码
指定一个Fiber，就取出其数据和状态，设置到当前线程的环境中，然后执行
指定另一个Fiber，则将当前Fiber的数据和状态保存，环境换成另一个Fiber的
每个Fiber看到的数据和执行的代码都是自己的，尽管共用一个线程却相互独立

实现：
一个Fiber必须有用于执行的回调函数，运行上下文（寄存器状态），以及存储局部变量的栈
各种相关数据组成一个FIBER结构体，Teb的FiberData指向当前执行的Fiber的FIBER结构体

由于一个线程本身就带有执行函数、上下文和栈，第一个启动的Fiber比较特殊
它使用ConvertThreadToFiber借用了线程的资源，而不是另外创建一份
（实际使用中，第一个Fiber往往负责初始化和调度，可以把它理解为主Fiber）
后续的Fiber则必须使用CreateFiberEx创建相关资源，然后等待执行
这两个函数都返回FIBER结构体，代表一个可执行的Fiber

当一个Fiber完成自己的任务后，会调用SwitchToFiber，让其它Fiber接替自己继续执行
系统会将当前Fiber的相关数据保存到FIBER结构体，并装载新Fiber的数据到Teb
最终，把CPU核心的EIP设为新Fiber的，准备执行新Fiber的代码
如果这个Fiber之前经历过切换，将会从切换的位置继续执行，看上去好像什么也没发生
如果是CreateFiberEx新创建的Fiber，之前没有运行过，它的EIP会初始化为BaseFiberStart
SwitchToFiber返回时，执行函数、上下文和栈都切换成了新Fiber的，而上一个Fiber进入等待

DeleteFiber是与CreateFiberEx相反的操作，它释放一个Fiber的资源
如果删除的Fiber是当前正在运行的Fiber，会导致线程退出
（线程退出时会释放当前Fiber的资源，但如果其它Fiber还没有删除，将会内存泄漏）
相比之下，ConvertFiberToThread是更友好的退出方式

与直觉不一样的是，Fiber并不是绑定在一个线程的子Fiber
任何一个转换为Fiber的线程，都可以执行任意FIBER结构体描述的Fiber
任意Fiber也可以放在任何线程上执行，只要这个线程的Teb->HasFiberData为TRUE
理论上这允许开发者使用多个线程来实现真正并行的协程，但为什么不直接用线程呢？


纤程局部存储：
类似TLS，Fiber也有局部存储机制（Fiber Local Storage，以下简称Fls）
考虑这种情况，几个Fiber共用一个执行函数，每个Fiber都要记录自己的ID
Fiber调用了几十个函数，这些函数都需要用到当前Fiber的ID，但你写参数写吐了
这时候就需要一个全局作用域，对每个Fiber独立的存储机制，即Fls

每个进程里，最多可以使用128个Fls槽，由所有Fiber共用，槽位用完就无法分配
而且，系统为每个Fiber都分配128个槽的内存，这保证了每个Fiber看到的内容都是独立的
（在实现上，是第一次FlsAlloc或FlsSetValue用到某个槽的时候，才真正分配内存）
需要申请一个Fls槽时，系统寻找一个空闲的槽，将此位置标记为已使用，然后返回索引
此后，所有Fiber都可以借助这个索引，定位到自己的Fls内存中对应的槽，存储自己的数据

其实在分配了Fls的内存之后，这128个槽位是可以随便访问的，甚至不需要申请索引
但是程序不应该假设底层的实现，应该遵循模型设计，仅使用属于自己的槽位

因为前面提到的Fiber的特性，Fls与线程无关，在哪个线程都能正常访问自己的Fls

按正常思路，一个函数应该释放完资源再退出，但是Fiber有很多无法预测的情况
如DeleteFiber删除了当前运行的Fiber，线程退出，或Fiber忙于切换，没有释放资源的时机
为了给Fls一个释放资源的机会，FlsAlloc允许提供一个回调函数
当FlsFree、DeleteFiber、RtlExitUserThread发生时，会调用Fls回调
这样可以把释放资源的代码统一到回调函数里，无论是否正常退出，都能释放资源

对于FlsFree，是遍历所有Fiber的这个索引，调用其Fls回调
（在实现上，系统会使用一个链表，记录所有已分配的的Fls内存块）
对于DeleteFiber和RtlExitUserThread，是遍历这个Fiber的所有索引，调用其Fls回调

特殊情况，若一个Fls槽的值为0，系统视为空，不调用回调

xpext的实现：
由于Win7中Fiber相关的函数都涉及到FlsData的切换，xpext重写了所有函数
以XP系统的实现为基础，增加了Win7的新特性，但去除了XP不支持的特性
Fls将相关数据存储在Teb中，而XP之前没有定义这些字段
xpext在TEB和PEB找到一些空闲的位置，用来存储Fls数据
可以在fiber_code_w7.cpp中找到Win7的实现
需要注意的是，XP的ExitThread并不会释放Fiber的内存，也不会调用Fls回调
xpext模拟RtlExitUserThread，在Fiber线程可能退出的地方，补充了相关代码
但如果Fiber直接调用ExitThread退出，或被TermanateThread结束，仍会导致内存泄漏
*/

typedef struct _FIBER
{
	PVOID FiberUserData;	//+0 本来叫FiberData，和TEB字段重名了
	_EXCEPTION_REGISTRATION_RECORD* ExceptionList;	//+4
	PVOID StackBase;	//+8
	PVOID StackLimit;	//+C
	PVOID DeallocationStack;	//+10
	CONTEXT FiberContext;	//+14
	PVOID Wx86Tib;	//+2E0 Wx86TIB*
	//Win7新增
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

RTL_BITMAP FlsBitMap;
RTL_SRWLOCK RtlpFlsLock=RTL_SRWLOCK_INIT;

LPVOID WINAPI K32ConvertThreadToFiberEx(LPVOID lpParameter,DWORD dwFlags)
{
	//Win7新增
	if (dwFlags&(~FIBER_FLAG_FLOAT_SWITCH))
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return NULL;
	}
	TEB* Teb=NtCurrentTeb();
	PEB* Peb=Teb->ProcessEnvironmentBlock;
	//Win7新增
	if (Teb->HasFiberData)
	{
		RtlSetLastWin32Error(ERROR_ALREADY_FIBER);
		return NULL;
	}

	FIBER* Fiber=(FIBER*)RtlAllocateHeap(RtlGetProcessHeap(),*BaseDllTag,sizeof(FIBER));
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
	Fiber->Wx86Tib=NULL;
	//Win7新增
	Fiber->FlsData=Teb->FlsData;
	Fiber->FiberContext.ContextFlags=CONTEXT_FULL;
	if (dwFlags&FIBER_FLAG_FLOAT_SWITCH)
		Fiber->FiberContext.ContextFlags=CONTEXT_FULL|CONTEXT_FLOATING_POINT;

	Teb->HasFiberData=TRUE;
	Teb->NtTib.FiberData=Fiber;
	return Fiber;
}

LPVOID WINAPI K32ConvertThreadToFiber(LPVOID lpParameter)
{
	return K32ConvertThreadToFiberEx(lpParameter,0);
}

//XP是_BaseThreadStart，这里融合了XP和Win7的代码
void WINAPI _BaseFiberStart()
{
	__try
	{
		TEB* Teb=NtCurrentTeb();
		FIBER* Fiber=(FIBER*)Teb->NtTib.FiberData;
		LPFIBER_START_ROUTINE FiberRoutine=(LPFIBER_START_ROUTINE)Fiber->FiberContext.Eax;
		PVOID lpParameter=(PVOID)Fiber->FiberContext.Ebx;
		//原代码是ebp-4，因为没有push ebp和mov ebp,esp
		_asm and dword ptr [ebp+4], 0;	//call ret = 0
		FiberRoutine(lpParameter);
		ExitFiberThread(0);
	}
	__except(UnhandledExceptionFilter(GetExceptionInformation()))
	{
		//新建的Fiber，其ExceptionList为-1，这个try是最顶层的SEH
		//UnhandledExceptionFilter是异常处理的保底屏障
		//如果返回EXCEPTION_CONTINUE_SEARCH，等价于默认行为，剩下的步骤将由Windows接管
		//如果返回EXCEPTION_CONTINUE_EXECUTION，回去重新执行出错的指令
		//而返回EXCEPTION_EXECUTE_HANDLER，将执行异常处理块中的代码
		//XP的方案是非服务进程直接退出进程，服务进程仅退出线程
		//Win7则是释放Fiber资源并退出线程
		//总的来说，Win7的方案能好一点
		ExitFiberThread(0);
		//ExitProcess(GetExceptionCode());
	}
	ExitProcess(-1);
}

void WINAPI BaseFiberStart()
{
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

	DWORD Adjust=0;	//Win7会对堆栈进行ASLR调整，XP删除相关代码
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
		//if (*(BYTE*)0x7FFE027A==TRUE)
		FiberContext->Dr6=0x1F80;	//The default MXCSR value at reset is 1F80H. LDMXCSR 1141页
	}
}

LPVOID WINAPI K32CreateFiberEx(SIZE_T dwStackCommitSize,SIZE_T dwStackReserveSize,DWORD dwFlags,LPFIBER_START_ROUTINE lpStartAddress,LPVOID lpParameter)
{
	//Win7新增
	if (dwFlags&(~FIBER_FLAG_FLOAT_SWITCH))
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	FIBER* Fiber=(FIBER*)RtlAllocateHeap(RtlGetProcessHeap(),*BaseDllTag,sizeof(FIBER));
	if (Fiber==NULL)
	{
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	INITIAL_TEB InitialTeb;	
	NTSTATUS Result=BaseCreateStack((HANDLE)0xFFFFFFFF,dwStackCommitSize,dwStackReserveSize,&InitialTeb);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
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
	//Win7新增
	Fiber->FlsData=NULL;
	//将FIBER_FLAG_FLOAT_SWITCH转换为CONTEXT_FLOATING_POINT
	//BaseInitializeFiberContext里，最终会额外加上CONTEXT_FULL
	Fiber->FiberContext.ContextFlags=(dwFlags&FIBER_FLAG_FLOAT_SWITCH)?CONTEXT_FLOATING_POINT:0;

	//XP使用BaseInitializeContext，Type为2，表示初始化Fiber
	BaseInitializeFiberContext(&Fiber->FiberContext,lpParameter,lpStartAddress,InitialTeb.StackBase);
	return Fiber;
}

LPVOID WINAPI K32CreateFiber(SIZE_T dwStackSize,LPFIBER_START_ROUTINE lpStartAddress,LPVOID lpParameter)
{
	return K32CreateFiberEx(dwStackSize,0,0,lpStartAddress,lpParameter);
}

void WINAPI K32DeleteFiber(LPVOID lpFiber)
{
	TEB* Teb=NtCurrentTeb();
	PEB* Peb=Teb->ProcessEnvironmentBlock;

	FIBER* Fiber=(FIBER*)lpFiber;
	//删除当前正在执行的Fiber将导致线程退出，FIBER结构体和TEB存储的一致
	if (Teb->HasFiberData && Teb->NtTib.FiberData==Fiber)
	{
		ExitFiberThread(1);
	}
	//由当前运行的Fiber删除其它Fiber，使用目标Fiber的FIBER结构体
	else
	{
		//Win7将这2行封装成RtlFreeUserStack
		ULONG FreeSize=0;
		NtFreeVirtualMemory(GetCurrentProcess(),&Fiber->DeallocationStack,&FreeSize,MEM_RELEASE);
		//Win7新增
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

BOOL WINAPI K32IsThreadAFiber()
{
	return NtCurrentTeb()->HasFiberData;
}


#define OFFSET_FIBER_CONTEXT_FLAGS	0x14
#define OFFSET_FIBER_CONTEXT_DR6	0x28
#define OFFSET_FIBER_CONTEXT_FPU_CTRL	0x30
#define OFFSET_FIBER_CONTEXT_FPU_STATUS	0x34
#define OFFSET_FIBER_CONTEXT_FPU_TAG	0x38
#define OFFSET_FIBER_CONTEXT_EDI	0xB0
#define OFFSET_FIBER_CONTEXT_ESI	0xB4
#define OFFSET_FIBER_CONTEXT_EBX	0xB8
#define OFFSET_FIBER_CONTEXT_EBP	0xC8
#define OFFSET_FIBER_CONTEXT_ESP	0xD8

#define OFFSET_FIBER_EXCEPTIONLIST	0x4
#define OFFSET_FIBER_STACKBASE	0x8
#define OFFSET_FIBER_STACKLIMIT	0xC
#define OFFSET_FIBER_DEALLOCSTACK	0x10
#define OFFSET_FIBER_FLSDATA	0x2E8

#define OFFSET_TEB_NTTIB_EXCEPTIONLIST	0x0
#define OFFSET_TEB_NTTIB_STACKBASE	0x4
#define OFFSET_TEB_NTTIB_STACKLIMIT	0x8
#define OFFSET_TEB_NTTIB_FIBERDATA	0x10
#define OFFSET_TEB_DEALLOCSTACK	0xE0C
#define OFFSET_TEB_FLSDATA	0xFB8

__declspec(naked)
	void WINAPI K32SwitchToFiber(LPVOID lpFiber)
{
	_asm
	{
		//TEB* Teb=NtCurrentTeb();
		mov     edx, fs:[0x18];
		//FIBER* OldFiber=(FIBER*)Teb->NtTib.FiberData;
		mov     eax, [edx+OFFSET_TEB_NTTIB_FIBERDATA];
		mov     [eax+OFFSET_FIBER_CONTEXT_EBX], ebx;
		mov     [eax+OFFSET_FIBER_CONTEXT_EDI], edi;
		mov     [eax+OFFSET_FIBER_CONTEXT_ESI], esi;
		mov     [eax+OFFSET_FIBER_CONTEXT_EBP], ebp;
		//if (OldFiber->FiberContext.ContextFlags==(CONTEXT_FULL|CONTEXT_FLOATING_POINT))
		cmp     dword ptr [eax+OFFSET_FIBER_CONTEXT_FLAGS], 0x1000F;
		jnz     NoFloatSave;
//FloatSave:
		fstsw   word ptr [eax+OFFSET_FIBER_CONTEXT_FPU_STATUS];
		fnstcw  word ptr [eax+OFFSET_FIBER_CONTEXT_FPU_CTRL];
		//Win8之后不再检查KUserSharedData->ProcessorFeatures[6]
		stmxcsr dword ptr [eax+OFFSET_FIBER_CONTEXT_DR6];
NoFloatSave:
		//关键步骤，当前栈的栈顶是返回地址，也就是当前Fiber的执行函数
		mov     [eax+OFFSET_FIBER_CONTEXT_ESP], esp;
		mov     ecx, [edx+OFFSET_TEB_FLSDATA];
		mov     [eax+OFFSET_FIBER_FLSDATA], ecx;
		mov     ecx, [edx+OFFSET_TEB_NTTIB_EXCEPTIONLIST];
		mov     [eax+OFFSET_FIBER_EXCEPTIONLIST], ecx;
		mov     ebx, [edx+OFFSET_TEB_NTTIB_STACKLIMIT];
		mov     [eax+OFFSET_FIBER_STACKLIMIT], ebx;
		//ActivationContextStackPointer、GuaranteedStackBytes、SameTebFlags在XP均不支持，这里省略
		//FIBER* NewFiber=(FIBER*)lpFiber;
		mov     ecx, [esp+4];
		mov     [edx+OFFSET_TEB_NTTIB_FIBERDATA], ecx;
		mov     esi, [ecx+OFFSET_FIBER_EXCEPTIONLIST];
		mov     [edx+OFFSET_TEB_NTTIB_EXCEPTIONLIST], esi;
		mov     ebx, [ecx+OFFSET_FIBER_STACKBASE];
		mov     [edx+OFFSET_TEB_NTTIB_STACKBASE], ebx;
		mov     esi, [ecx+OFFSET_FIBER_STACKLIMIT];
		mov     [edx+OFFSET_TEB_NTTIB_STACKLIMIT], esi;
		mov     ebx, [ecx+OFFSET_FIBER_DEALLOCSTACK];
		mov     [edx+OFFSET_TEB_DEALLOCSTACK], ebx;
		//if (NewFiber->FiberContext.ContextFlags==(CONTEXT_FULL|CONTEXT_FLOATING_POINT))
		cmp     dword ptr [ecx+OFFSET_FIBER_CONTEXT_FLAGS], 0x1000F;
		jnz     NoFloatLoad;
//FloatLoad:
		//if (OldFiber->FiberContext.FloatSave.StatusWord!=NewFiber->FiberContext.FloatSave.StatusWord ||
		//OldFiber->FiberContext.FloatSave.ControlWord!=NewFiber->FiberContext.FloatSave.ControlWord)
		mov     ebx, [eax+OFFSET_FIBER_CONTEXT_FPU_STATUS];
		cmp     bx, [ecx+OFFSET_FIBER_CONTEXT_FPU_STATUS];
		jnz     short FloatLoadEnv;
		mov     ebx, [eax+OFFSET_FIBER_CONTEXT_FPU_CTRL];
		cmp     bx, [ecx+OFFSET_FIBER_CONTEXT_FPU_CTRL];
		jz      short FloatNoLoadEnv;
FloatLoadEnv:
		mov     word ptr [ecx+OFFSET_FIBER_CONTEXT_FPU_TAG], 0xFFFF;
		fldenv  byte ptr [ecx+OFFSET_FIBER_CONTEXT_FPU_CTRL];
FloatNoLoadEnv:
		ldmxcsr dword ptr [ecx+OFFSET_FIBER_CONTEXT_DR6];
NoFloatLoad:
		mov     edi, [ecx+OFFSET_FIBER_CONTEXT_EDI];
		mov     esi, [ecx+OFFSET_FIBER_CONTEXT_ESI];
		mov     ebp, [ecx+OFFSET_FIBER_CONTEXT_EBP];
		mov     ebx, [ecx+OFFSET_FIBER_CONTEXT_EBX];
		mov     eax, [ecx+OFFSET_FIBER_FLSDATA];
		mov     [edx+OFFSET_TEB_FLSDATA], eax;
		//关键步骤，新栈的栈顶是新Fiber的返回地址，将跳转至此处执行
		mov     esp, [ecx+OFFSET_FIBER_CONTEXT_ESP];
		retn    4;
	}
}

void WINAPI LdrpInitializeFiber()
{
	//PEB里FLS相关的几个字段，所有线程共用一份
	//FlsBitmap和FlsListHead由Loader初始化
	//FlsCallback在第一次用到时分配内存
	//FlsCallback和FlsHighIndex没找到初始化代码，应该为0
	//整个进程只允许分配128个FLS，且第一个Slot保留
	//而FlsData每个Fiber一份，当前使用的在TEB里
	PEB* Peb=NtCurrentTeb()->ProcessEnvironmentBlock;
	Peb->FlsBitmap=&FlsBitMap;
	RtlInitializeBitMap(&FlsBitMap,Peb->FlsBitmapBits,FLS_MAX_SLOT);
	//RtlSetBit(&FlsBitMap,0); ntdll用的RtlSetBit没导出
	RtlSetBits(&FlsBitMap,0,1);
	Peb->FlsListHead.Blink=&Peb->FlsListHead;
	Peb->FlsListHead.Flink=&Peb->FlsListHead;

	Peb->FlsCallback=NULL;
	Peb->FlsHighIndex=0;
}

void WINAPI ExitFiberThread(DWORD dwExitCode)
{
	//在Win7线程退出调用RtlExitUserThread
	//内部会调用Fls回调，并最终释放当前线程的Fiber和Fls资源
	//而XP的ExitThread没有相关功能，使用这个函数补充
	TEB* Teb=NtCurrentTeb();
	FLS_DATA_INFO* FlsData=(FLS_DATA_INFO*)Teb->FlsData;
	if (FlsData!=NULL)
		RtlProcessFlsData(FlsData);
	if (FlsData!=NULL)
	{
		Teb->FlsData=NULL;
		RtlFreeHeap(RtlGetProcessHeap(),0,FlsData);
	}
	if (Teb->HasFiberData)
	{
		FIBER* Fiber=(FIBER*)Teb->NtTib.FiberData;
		Teb->HasFiberData=FALSE;
		Teb->NtTib.FiberData=NULL;
		RtlFreeHeap(RtlGetProcessHeap(),0,Fiber);
	}
	ExitThread(dwExitCode);
}

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

NTSTATUS NTAPI RtlProcessFlsData(PVOID FlsData)
{
	FLS_DATA_INFO* FlsDataBlock=(FLS_DATA_INFO*)FlsData;
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

