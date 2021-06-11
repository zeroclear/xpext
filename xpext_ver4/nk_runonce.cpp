
#include "common.h"

/*
Windows 7 SP1 32位 6.1.7601.17514
@清泠 2021.4.18

在kernel32里，这几个函数叫InitOnceXXX
在ntdll里，这几个函数叫RtlRunOnceXXX
不知道为什么，winnt.h里定义了RtlRunOnceXXX
我只好将它们重命名为RtlRunOnceXXX2

我认为没个十年脑血栓设计不出来这种接口
把简单的事情复杂化，提高了学习成本，还不一定好用
使用这几个函数，要仔细阅读MSDN上的文档，注意其中的各种限制

然而这几个函数做的事类似如下伪代码：

//同步模式
TYPE* g_obj=NULL;

TYPE* GetObject()
{
	EnterLock();
	if (g_obj==NULL)
		g_obj=CreateObject();
	LeaveLock();
	return g_obj;
}

void UseObject()
{
	TYPE* obj=GetObject();
	obj->DoWork();
}

//异步模式
TYPE* g_obj=NULL;

TYPE* GetObject()
{
	return g_obj;
}

void UpdateObject()
{
	TYPE* obj=CreateObject();
	EnterLock();
	if (g_obj==NULL)
		g_obj=obj;
	LeaveLock();
	if (g_obj!=obj)
		DestroyObject(obj);
}

void UseObject()
{
	TYPE* obj=GetObject();
	if (obj==NULL)
	{
		UpdateObject();
		obj=GetObject();
	}
	obj->DoWork();
}

简单的说，是在多线程环境下创建一个单例对象（Singleton Object）
如果对象不存在，就新建一个，此后所有线程都用这个对象
否则，对象已经被其它线程创建，就使用现存的对象
（这里说创建对象只是方便描述，实际上也可以是执行一些初始化代码）

这些函数有两种使用模式：同步模式和异步模式
同步模式下，第一个调用的线程执行创建，随后的线程等待
第一个线程创建完毕，其它线程被唤醒，取回已创建的对象
异步模式下，如果对象没有创建，所有线程一起创建对象
第一个创建完成的线程将对象指针更新，此后所有线程都使用这个对象
然后晚一步的线程需要销毁自己创建一半的对象

其中RtlRunOnceExecuteOnce是同步模式对
RtlRunOnceBeginInitialize和RtlRunOnceComplete的封装
具体使用方式与我的描述有所差异，可以参考微软给出的使用示例：
https://docs.microsoft.com/en-us/windows/win32/sync/using-one-time-initialization
*/

RUNONCESTATUS NTAPI RtlpRunOnceWaitForInit(RUNONCESTATUS OldStatus,RTL_RUN_ONCE* RunOnce)
{
	//栈上的数据都是按4字节对齐的，不需要__declspec(align(4))
	//因为item在栈上，且大小为4字节，编译器生成汇编时用了个优化
	//将OldStatus的值存在ecx里，将栈上的OldStatus的位置拿来当item
	RUNONCEITEM item;
	//将自己的节点插入链表，并进入等待
	//只有同步模式且未完成才需要等待，状态必然为sync+pend
	RUNONCESTATUS NewStatus=(((RUNONCESTATUS)&item)&(RUNONCEM_ITEM+RUNONCEF_SyncPend))|RUNONCEF_SyncPend;
	do 
	{
		item.next=(RUNONCEITEM*)(OldStatus&RUNONCEM_ITEM);
		RUNONCESTATUS CurrStatus=InterlockedCompareExchange((RUNONCESTATUS*)RunOnce,NewStatus,OldStatus);
		if (CurrStatus==OldStatus)
		{
			//XP不支持第一个参数传入NULL
			NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,NULL);
			CurrStatus=(RUNONCESTATUS)RunOnce->Ptr;
		}
		OldStatus=CurrStatus;
	} while ((OldStatus&RUNONCEM_FLAG)==RUNONCEF_SyncPend);
	return OldStatus;
}

void NTAPI RtlpRunOnceWakeAll(RTL_RUN_ONCE* RunOnce)
{
	//唤醒next链上的所有节点
	RUNONCEITEM* item=(RUNONCEITEM*)((RUNONCESTATUS)RunOnce->Ptr&RUNONCEM_ITEM);
	if (item!=NULL)
	{
		do 
		{
			//暂存next，防止唤醒后失效
			RUNONCEITEM* next=item->next;
			//XP不支持第一个参数传入NULL
			NtReleaseKeyedEvent(GlobalKeyedEventHandle,item,FALSE,NULL);
			item=next;
		} while (item!=NULL);
	}
}

//void WINAPI K32InitOnceInitialize(LPINIT_ONCE InitOnce)
void NTAPI RtlRunOnceInitialize2(RTL_RUN_ONCE* RunOnce)
{
	RunOnce->Ptr=NULL;
}

NTSTATUS NTAPI RtlRunOnceBeginInitialize2(RTL_RUN_ONCE* RunOnce,DWORD Flags,PVOID* Context)
{
	//Flags仅允许INIT_ONCE_CHECK_ONLY和INIT_ONCE_ASYNC
	if ((Flags&~(INIT_ONCE_CHECK_ONLY|INIT_ONCE_ASYNC))!=0)	//0xFFFFFFFC
		return STATUS_INVALID_PARAMETER_2;
	//flags为3时，flags&(flags-1)=3&2=2
	//flags为2时，flags&(flags-1)=2&1=0
	//flags为1时，flags&(flags-1)=1&0=0
	//flags为0时，and必为0
	//即不允许两种Flag同时出现
	//但MSDN上说This parameter can have a value of 0, or one or more of the following flags.
	if (Flags & (Flags-1))
		return STATUS_INVALID_PARAMETER_2;

	RUNONCESTATUS OldStatus=(RUNONCESTATUS)RunOnce->Ptr;
	//原汇编用栈上的Flags的位置存储Result
	NTSTATUS Result=STATUS_SUCCESS;
	//已有线程完成创建，返回现有的
	if ((OldStatus&RUNONCEM_FLAG)==RUNONCEF_Complete)
	{
		//强制更新内存缓存，令其它核心收到结果，避免无谓的等待
		//在Win7 x86下是xchg eax, [ebp+arg_0]，在x64下是lock or [rsp+0], 0
		//这一句没执行实际的更改，别被惯性思维骗了
		InterlockedExchange((size_t*)&RunOnce,Flags);
		if (Context!=NULL)
			*(size_t*)Context=OldStatus&RUNONCEM_ITEM;
		return Result;
	}
	//创建还没完成，取回失败
	if (Flags&RTL_RUN_ONCE_CHECK_ONLY)
		return STATUS_UNSUCCESSFUL;

	BOOL IsSyncMode=((Flags&RTL_RUN_ONCE_ASYNC)==0);

	while (1)
	{
		BYTE StatusFlag=OldStatus&RUNONCEM_FLAG;
		//自己是第一个调用的线程，根据Flags设置好sync或async，返回pending，允许进行创建
		if (StatusFlag==RUNONCEF_NoRequest)
		{
			//若指定了RTL_RUN_ONCE_ASYNC，设为Async+Pend，否则为Sync+Pend
			//这些反复横跳的迷惑行为可能是编译器基于位域生成的
			RUNONCESTATUS NewStatus=(((!IsSyncMode)<<1)|RUNONCEF_SyncPend)&RUNONCEM_FLAG;
			RUNONCESTATUS CurrStatus=InterlockedCompareExchange((RUNONCESTATUS*)RunOnce,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
			{
				Result=STATUS_PENDING;
				return Result;
			}
			OldStatus=CurrStatus;
		}
		//这一系列调用是sync模式，且已有线程进行创建，等待其完成
		//这种情况OldStatus可能含有等待的节点链表
		else if (StatusFlag==RUNONCEF_SyncPend)
		{
			//指定的async模式和之前的sync模式冲突
			if (IsSyncMode==FALSE)
			{
				Result=STATUS_INVALID_PARAMETER_2;
				return Result;
			}
			OldStatus=RtlpRunOnceWaitForInit(OldStatus,RunOnce);
		}
		//这一系列调用是async模式，返回pending允许进行创建
		else if (StatusFlag==RUNONCEF_AsyncPend)
		{
			//指定的sync模式和之前的async模式冲突
			if (IsSyncMode)
				Result=STATUS_INVALID_PARAMETER_2;
			else
				Result=STATUS_PENDING;
			return Result;
		}
		//已有线程完成创建，返回现有的
		//这种情况OldStatus含有context
		else if (StatusFlag==RUNONCEF_Complete)
		{
			if (Context!=NULL)
				*(size_t*)Context=OldStatus&RUNONCEM_ITEM;
			return Result;
		}
		//不知道为什么，原汇编代码使用OldStatus确定Async+Pend的情况
		//if (StatusFlag==RUNONCEF_NoRequest) ...
		//else if (StatusFlag==RUNONCEF_SyncPend) ...
		//else if (OldStatus==RUNONCEF_AsyncPend) ...
		//else ...
		//而Complete的情况，由于OldStatus含有context，没法直接比较
		//因此在判断完其它3种情况后，放在了else里
	}
	return Result;
}

NTSTATUS NTAPI RtlRunOnceComplete2(RTL_RUN_ONCE* RunOnce,DWORD Flags,PVOID Context)
{
	//Flags仅允许RTL_RUN_ONCE_ASYNC和RTL_RUN_ONCE_INIT_FAILED
	if ((Flags&~(RTL_RUN_ONCE_ASYNC|RTL_RUN_ONCE_INIT_FAILED))!=0)	//0xFFFFFFF9
		return STATUS_INVALID_PARAMETER_2;
	//flags为6时，flags&(flags-1)=6&5=4
	//flags为4时，flags&(flags-1)=4&3=0
	//flags为2时，flags&(flags-1)=2&1=0
	//flags为0时，and必为0
	//即不允许两种Flag同时出现
	if (Flags & (Flags-1))
		return STATUS_INVALID_PARAMETER_2;

	//原汇编代码是这样的：
	//DWORD NewFlags=((~(Flags>>1))^Flags)&3^Flags;
	//结构为(target ^ complement) & range ^ complement
	//意为以range中为1的位为准，保留target中对应的位，
	//剩下的位用complement中对应的位填充
	//由于后面的代码只用到最低2位，所以等价于我这几行代码
	//我想说，分开用两个变量能死么？看来不仅设计接口的人脑子不正常
	//写代码的人也是个脑瘫，或是说他们根本就是一个人？
	BOOL IsSuccess=!(Flags&RTL_RUN_ONCE_INIT_FAILED);
	BOOL IsSyncMode=!(Flags&RTL_RUN_ONCE_ASYNC);
	DWORD NewFlags=(IsSuccess<<1)|IsSyncMode;

	if (Context!=NULL)
	{
		//失败模式不允许设置Context
		if ((NewFlags & 2)==0)
			return STATUS_INVALID_PARAMETER_3;
		//Context必须DWORD对齐（或空出最后RTL_RUN_ONCE_CTX_RESERVED_BITS位）
		if (((size_t)Context & 3)!=0)
			return STATUS_INVALID_PARAMETER_3;
	}

	RUNONCESTATUS OldStatus=(RUNONCESTATUS)RunOnce->Ptr;
	//若是失败模式，NewFlags & 2为0，Context也为0，合成NoRequest状态
	//若是成功模式，NewFlags & 2为1，Context是结果，合成Complete状态
	RUNONCESTATUS NewStatus=(NewFlags & 2) | (size_t)Context;

	BYTE StatusFlag=OldStatus&RUNONCEM_FLAG;
	if (StatusFlag==RUNONCEF_SyncPend)
	{
		//指定的async模式和之前的sync模式冲突
		if ((NewFlags & 1)==0)
			return STATUS_INVALID_PARAMETER_2;
		RUNONCESTATUS CurrStatus=InterlockedExchange((RUNONCESTATUS*)RunOnce,NewStatus);
		//sync模式只能有一个线程操作，其他线程修改状态是出问题了
		if ((CurrStatus&RUNONCEM_FLAG)!=RUNONCEF_SyncPend)
			return STATUS_INVALID_OWNER;
		//借用栈上Flags的空间临时构建了一个RTL_RUN_ONCE
		//而在Win7 x64上，编译器直接展开RtlpRunOnceWakeAll，省去了这一步
		RTL_RUN_ONCE temp;
		temp.Ptr=(PVOID)CurrStatus;
		RtlpRunOnceWakeAll(&temp);
		return STATUS_SUCCESS;
	}
	else if (StatusFlag==RUNONCEF_AsyncPend)
	{
		//指定的sync模式和之前的async模式冲突
		if ((NewFlags & 1)!=0)
			return STATUS_INVALID_PARAMETER_2;
		RUNONCESTATUS CurrStatus=InterlockedCompareExchange((RUNONCESTATUS*)RunOnce,NewStatus,OldStatus);
		//其他线程已经提交成功，使用此结果
		if (CurrStatus!=OldStatus)
			return STATUS_OBJECT_NAME_COLLISION;
		//本线程提交成功
		return STATUS_SUCCESS;
	}
	else
	{
		//对RUNONCEF_NoRequest来说，禁止不申请直接提交结果
		//对RUNONCEF_Complete来说，结果已经提交，不允许覆盖
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS NTAPI RtlRunOnceExecuteOnce2(RTL_RUN_ONCE* RunOnce,RTL_RUN_ONCE_INIT_FN InitFn,PVOID Parameter,PVOID* Context)
{
	//原汇编代码将栈上的Context的最高字节拿来记录错误信息
	BYTE ErrorInfo;
	//如果本线程是第一个调用的，返回STATUS_PENDING，允许对象创建
	//如果本线程不是第一个调用的，会在函数内等待，直到第一个线程创建完成
	NTSTATUS Result=RtlRunOnceBeginInitialize2(RunOnce,0,Context);
	if (NT_SUCCESS(Result))
	{
		//本线程是第一个线程，调用回调函数创建对象，成功后提交对象指针
		if (Result==STATUS_PENDING)
		{
			if (InitFn(RunOnce,Parameter,Context)==TRUE)
			{
				//原汇编代码直接使用Context来存储ContextData
				PVOID ContextData=NULL;
				if (Context!=NULL)
					ContextData=*Context;
				//创建成功，参数2传入0，将状态设为Complete，并将结果存入status里
				Result=RtlRunOnceComplete2(RunOnce,0,ContextData);
				if (NT_SUCCESS(Result))
				{
					Result=STATUS_SUCCESS;
				}
				else
				{
					ErrorInfo=1;
					RtlReportCriticalFailure(Result,(ULONG_PTR)&ErrorInfo);
				}
			}
			else
			{
				//创建失败，参数2传递RTL_RUN_ONCE_INIT_FAILED
				//将导致状态设为NoRequest，并唤醒其它线程
				Result=RtlRunOnceComplete2(RunOnce,RTL_RUN_ONCE_INIT_FAILED,NULL);
				if (NT_SUCCESS(Result))
				{
					Result=STATUS_UNSUCCESSFUL;
				}
				else
				{
					ErrorInfo=2;
					RtlReportCriticalFailure(Result,(ULONG_PTR)&ErrorInfo);
				}
			}
		}
		else	//Result==STATUS_SUCCESS
		{
			//其它线程已经创建好了对象，放在Context里，返回直接使用
			Result=STATUS_SUCCESS;
		}
	}
	else
	{
		ErrorInfo=0;
		RtlReportCriticalFailure(Result,(ULONG_PTR)&ErrorInfo);
	}
	return Result;
}


BOOL WINAPI K32InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce,DWORD dwFlags,PBOOL fPending,LPVOID* lpContext)
{
	NTSTATUS Result=RtlRunOnceBeginInitialize2(lpInitOnce,dwFlags,lpContext);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}
	*fPending=(Result==STATUS_PENDING);
	return TRUE;
}

BOOL WINAPI K32InitOnceExecuteOnce(LPINIT_ONCE lpInitOnce,PINIT_ONCE_FN InitFn,LPVOID lpParameter,LPVOID* lpContext)
{
	NTSTATUS Result=RtlRunOnceExecuteOnce2(lpInitOnce,(PRTL_RUN_ONCE_INIT_FN)InitFn,lpParameter,lpContext);
	//返回值只有两种结果：STATUS_SUCCESS和STATUS_UNSUCCESSFUL
	//其余情况全部ZwTerminateProcess，就没必要SetLastError了
	return NT_SUCCESS(Result);
}

BOOL WINAPI K32InitOnceComplete(LPINIT_ONCE lpInitOnce,DWORD dwFlags,LPVOID lpContext)
{
	NTSTATUS Result=RtlRunOnceComplete2(lpInitOnce,dwFlags,lpContext);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}
	return TRUE;
}