
#include "common.h"
#pragma comment(lib,"E:\\WDK\\lib\\wxp\\i386\\ntdll.lib")

//Windows 7 SP1 32位
//@清泠

/*
基本分析

空闲状态，独占请求和共享请求都能获取锁
独占状态，独占请求和共享请求都不能获取锁
共享状态，仅共享请求能获取锁，独占请求不能获取锁

理论上，如果当前是共享锁，后续的所有共享请求都可以获取锁
但是为了防止写入线程出现饥饿状态，应用了相对公平的算法
一旦出现独占请求，后续的所有共享请求都要等待

SRWLOCK是一个容器，保存着这个锁的全部信息
SRWLOCK::Ptr的前28位保存了等待链表的头部（或共享计数）
后4位使用align(16)空出，用于保存状态
链表节点在栈上分配，函数休眠返回前一直有效
每次只允许一个线程编辑链表，用SRWST_Link标记控制

新线程进入等待状态时，把旧链表头设为自己的back节点
自身当做新的链表头，替换旧的链表头，完成插入
item->back=status;
status=&item;
所以顺着status的back一直向前查找，是按时间由近到远加入的节点

只有第一个等待的节点才有notify字段，指向自身
notify字段表示有空闲时，即将被唤醒的节点
按照时间顺序，notify->next记录了从开始到最近，所有被加入的节点
notify->next和status->back是整个链表的正反两面

刚开始链表没有next节点，在需要的时候会遍历并补全next字段
item->back->next=item;
item=item->back;
随着这个遍历过程，还会寻找非空的notify节点
找到后将其移到最近的位置，省去之后链表查找的时间，称为优化
status->notify=find->notify;
每次都会找最近的notify节点，在这之前的notify链接将不会再用到
因为遍历过程是从当前节点向前，在后面新增节点并没有影响

如果只唤醒一个节点，会从链表中删除这个节点，并断开next链接
temp=item->notify;
item->notify=item->notify->next;
temp->next=NULL;
尽管back链接还存在，但是没有影响
因为唤醒只用notify和notify->next，优化只到最近的notify

如果notify节点是共享请求，其后面的共享请求也可以同时获取锁
这时候就会将状态设为空闲，依次唤醒notify和后面全部的notify->next
开始的几个共享请求一起获取锁，直到出现独占请求
这个独占请求和剩下的请求一起，再次进入等待状态
相当于让所有线程重新抢锁，链表节点重新初始化，再次构建链表
*/

typedef struct _SYNCITEM
{
	_SYNCITEM* back;	//上个等待的节点
	_SYNCITEM* notify;	//即将被唤醒的节点
	_SYNCITEM* next;	//下个节点
	DWORD count;	//共享计数
	DWORD flag;		//SRWFG_XXX组合，或0
} SYNCITEM;

//这些flag可能和cv共用，最好将前缀改成SYNC
//srw status
#define SRWST_FREE	0	//空闲
#define SRWST_Hold	1	//有线程拥有了锁
#define SRWST_Wait	2	//有线程正在等待
#define SRWST_Link	4	//修改链表的操作进行中
#define SRWST_Many	8	//独占请求之前有多个共享锁并存
#define SRW_DATAMASK	0xFFFFFFF0
#define SRW_DATA_ONE	(1<<4)
//srw flag
#define SRWFG_Exclusive	1	//表示当前是独占锁在等待，否则是共享锁
#define SRWFG_Conscious	2	//当前线程处于自旋状态，否则进入睡眠状态

DWORD SRWLockSpinCount=0x400;

void NTAPI RtlpInitSRWLock(void* PEB)
{
	DWORD NumberOfProcessors=((DWORD)PEB+0x64);
	if (NumberOfProcessors==1)
		SRWLockSpinCount=0;
}

void NTAPI RtlpWakeSRWLock(SRWLOCK* pSRWLock,DWORD dwStatus)
{
	DWORD dwCurStatus;
	SYNCITEM* item;
	SYNCITEM* notify;
	while (1)
	{
		//已经有线程抢先获取了锁，取消唤醒操作
		if (dwStatus&SRWST_Hold)
		{
			do 
			{
				dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwStatus-SRWST_Link,dwStatus);	//清除链表操作标记
				//状态被其它线程更新，设置状态失败
				//本次分析失效，更新状态重新分析
				//下面有大量类似代码，不再重复说明
				if (dwCurStatus==dwStatus)
					return ;
				dwStatus=dwCurStatus;
			} while (dwStatus&SRWST_Hold);
		}

		item=(SYNCITEM*)(dwStatus&SRW_DATAMASK);
		notify=item->notify;
		if (notify==NULL)
		{
			SYNCITEM* cur=item;
			do 
			{
				cur->back->next=cur;	//补全链表
				cur=cur->back;			//遍历链表
				notify=cur->notify;		//更新当前节点
			} while (notify==NULL);		//找一个非空的notify
			//如果找到的notify不在当前节点，就复制到当前节点
			//优化链表里没有这个判断，大概是再次插入节点时，notify一定不在当前节点
			if (item!=cur)	
				item->notify=notify;
		}

		//如果后续还有节点等待，且这个是独占请求
		if ((notify->next!=NULL) && (notify->flag&SRWFG_Exclusive))
		{
			//从链表中删除这个节点，并断开next链接
			item->notify=notify->next;
			notify->next=NULL;
			_InterlockedAnd((long*)pSRWLock,(~SRWST_Link));	//链表操作全部完成，去掉标记
			break;
		}
		//否则，可能只有这一个节点等待，或这个是共享请求
		else
		{
			dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,0,dwStatus);	//将状态重置为空闲
			if (dwStatus==dwCurStatus)
				break;
			item->notify=notify;	//尽管设置状态失败，查找节点还是成功的，就当是一次优化操作了
			dwStatus=dwCurStatus;
		}
	}

	//依次唤醒线程，根据前面的判断，可能仅有1个，也可能是全部
	//如果是全部唤醒，接下来线程会再次争夺锁，抢不到的再次循环，构建链表并阻塞
	do 
	{
		//抢到锁的线程会返回，栈上的notify失效，必须先保存next
		SYNCITEM* next=notify->next;
		//清除SRWFG_Conscious标记（节点初始化时，它的值为1），并唤醒线程
		//如果等待线程看到的值为1，就将其设为0，并进入休眠；否则不修改它，不进入休眠
		//如果唤醒线程看到的值为1，说明还没进行休眠，就将其置0，跳过唤醒，也阻止了线程休眠
		//如果唤醒线程看到的值为0，说明线程已经休眠（或即将休眠），就将其唤醒
		//需要注意的是，NtReleaseKeyedEvent发现key并没有休眠时，会阻塞当前线程
		//直到有线程用此key调用了NtWaitForKeyedEvent，才会唤醒，因此不会丢失通知
		if (InterlockedBitTestAndReset((long*)&(notify->flag),1)==0)
			NtReleaseKeyedEvent(GlobalKeyedEventHandle,notify,FALSE,NULL);
		notify=next;	//遍历链表
	} while (notify!=NULL);
}

void NTAPI RtlpOptimizeSRWLockList(SRWLOCK* pSRWLock,DWORD dwStatus)
{
	if (dwStatus&SRWST_Hold)
	{
		do 
		{
			SYNCITEM* item=(SYNCITEM*)(dwStatus&SRW_DATAMASK);
			if (item!=NULL)
			{
				SYNCITEM* cur=item;
				while (cur->notify==NULL)
				{
					cur->back->next=cur;	//补全链表
					cur=cur->back;			//遍历链表
				}
				item->notify=cur->notify;	//找到非空notify，将其位置提前
			}
			//链表操作结束，清除标记
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwStatus-SRWST_Link,dwStatus);
			if (dwCurStatus==dwStatus)
				return ;
			dwStatus=dwCurStatus;
		} while (dwStatus&SRWST_Hold);
	}
	//有人释放了锁，取消优化，改为唤醒
	RtlpWakeSRWLock(pSRWLock,dwStatus);
}

void NTAPI RtlInitializeSRWLock(SRWLOCK* SRWLock)
{
	*(DWORD*)(&SRWLock->Ptr)=0;
}

void NTAPI RtlAcquireSRWLockExclusive(SRWLOCK* pSRWLock)
{
	__declspec(align(16)) SYNCITEM item;
	BOOL bOptimize;
	DWORD dwNewStatus;
	DWORD dwBackOffCount=0;

	//如果当前状态为空闲，直接获取锁
	//甚至某个线程刚释放锁，仅清除了Hold标记，其它线程还没来得及获取锁
	//本线程也可以趁机获取锁，设置标记，令唤醒操作取消或唤醒后再次进入等待
	if (InterlockedBitTestAndSet((long*)pSRWLock,0)==0)
		return ;

	DWORD dwStatus=(DWORD)(pSRWLock->Ptr);
	while (1)
	{
		//如果当前有线程持有锁，本线程将构建节点，将自己加入链表
		if (dwStatus&SRWST_Hold)
		{
			if (RtlpWaitCouldDeadlock())
			{
				//GetCurrentProcess(),STATUS_THREAD_IS_TERMINATING
				ZwTerminateProcess((HANDLE)0xFFFFFFFF,0xC000004B);
			}

			item.flag=SRWFG_Exclusive|SRWFG_Conscious;
			item.next=NULL;
			bOptimize=FALSE;

			//如果有线程已经在前面等待了，就把之前的节点设为back
			if (dwStatus&SRWST_Wait)
			{
				item.notify=NULL;
				item.count=0;
				item.back=(SYNCITEM*)(dwStatus&SRW_DATAMASK);
				dwNewStatus=((DWORD)&item)|(dwStatus&SRWST_Many)|(SRWST_Link|SRWST_Wait|SRWST_Hold);

				if (!(dwStatus&SRWST_Link))	//当前没人操作链表，就优化链表
					bOptimize=TRUE;
			}
			//如果本线程是第一个等待的线程，back无意义
			//同时负责建立notify链表，也将是第一个接收通知的线程
			else
			{
				item.notify=&item;
				//如果当前是独占锁，共享计数为0
				//如果当前是共享锁，共享计数为1或更多
				item.count=dwStatus>>4;
				if (item.count>1)
					dwNewStatus=((DWORD)&item)|(SRWST_Many|SRWST_Wait|SRWST_Hold);
				else
					dwNewStatus=((DWORD)&item)|(SRWST_Wait|SRWST_Hold);
			}
			//提交新状态
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
			if (dwCurStatus==dwStatus)
			{
				if (bOptimize)
					RtlpOptimizeSRWLockList(pSRWLock,dwNewStatus);
				//进入内核的代价太高，先进行一段自旋等待
				for (int i=SRWLockSpinCount;i>0;i--)
				{
					if (!(item.flag&SRWFG_Conscious))	//其它线程可能唤醒本线程，清除标记
						break;
					_mm_pause();
				}
				//如果一直没能等到唤醒，就进入内核休眠
				if (InterlockedBitTestAndReset((long*)(&item.flag),1)==1)	//SRWFG_Conscious
					NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,0,0);
				//被唤醒后再次循环检测条件
				dwStatus=dwCurStatus;
			}
			else
			{
				//线程处于激烈的竞争中，退避一段时间
				RtlBackoff(&dwBackOffCount);
				dwStatus=(DWORD)(pSRWLock->Ptr);
			}
		}
		//无论如何，现在没有线程持有锁了，尝试获取锁
		else
		{
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwStatus+SRWST_Hold,dwStatus);
			if (dwCurStatus==dwStatus)
				return ;
			RtlBackoff(&dwBackOffCount);
			dwStatus=(DWORD)(pSRWLock->Ptr);
		}
	}
}

void NTAPI RtlAcquireSRWLockShared(SRWLOCK* pSRWLock)
{
	__declspec(align(16)) SYNCITEM item;
	BOOL bOptimize;
	DWORD dwNewStatus;
	DWORD dwBackOffCount=0;

	DWORD dwStatus=InterlockedCompareExchange((DWORD*)pSRWLock,SRW_DATA_ONE|SRWST_Hold,0);
	//如果当前状态为空闲，直接获取锁
	if (dwStatus==0)
		return ;

	while (1)
	{
		//因独占锁需要等待的情况
		//出于公平性考虑，只要有独占锁请求，后续的所有共享锁请求都要排队（即使当前正处于共享状态）
		//有了wait标记，说明：1.当前是独占锁，后续无论什么类型的请求都要排队
		//2.当前是共享锁，但是队列里有独占锁请求，后来的共享锁也应该排队
		//作为对比，若当前是共享锁，紧接着的共享请求可以直接获取锁，不会阻塞和添加wait标记
		//另有一种特殊情况，当前是独占锁，后续没有线程请求锁，也就没有wait标记
		//但是这种情况的share count为0（作为对比，只有单个共享锁时share count为1）
		//一旦后续有请求，请求者就会等待，变成有wait标记的情况
		if ((dwStatus&SRWST_Hold) && ((dwStatus&SRWST_Wait) || ((dwStatus&SRW_DATAMASK)==0)))
		{
			if (RtlpWaitCouldDeadlock())
				ZwTerminateProcess((HANDLE)0xFFFFFFFF,0xC000004B);

			item.flag=SRWFG_Conscious;
			item.count=0;
			bOptimize=FALSE;
			item.next=NULL;

			if (dwStatus&SRWST_Wait)
			{
				item.back=(SYNCITEM*)(dwStatus&SRW_DATAMASK);
				//前面已经检测了SRWST_Hold为1，但是原汇编代码非要拆开
				dwNewStatus=((DWORD)&item)|(dwStatus&(SRWST_Many|SRWST_Hold))|(SRWST_Link|SRWST_Wait);
				item.notify=NULL;

				if (!(dwStatus&SRWST_Link))
					bOptimize=TRUE;
			}
			else
			{
				item.notify=&item;
				//当前一定是独占锁，所以不用考虑SRWST_Many
				dwNewStatus=((DWORD)&item)|(SRWST_Wait|SRWST_Hold);
			}

			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
			if (dwCurStatus==dwStatus)
			{
				if (bOptimize)
					RtlpOptimizeSRWLockList(pSRWLock,dwNewStatus);

				for (int i=SRWLockSpinCount;i>0;i--)
				{
					if (!(item.flag&SRWFG_Conscious))
						break;
					_mm_pause();
				}

				if (InterlockedBitTestAndReset((long*)&(item.flag),1)==1)	//SRWFG_Conscious
					NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,NULL);
				dwStatus=dwCurStatus;
			}
			else
			{
				RtlBackoff(&dwBackOffCount);
				dwStatus=(DWORD)pSRWLock->Ptr;
			}
		}
		else
		{
			//某个线程刚释放锁，仅清除了Hold标记，其它线程还没来得及获取锁
			//本线程可以趁机获取锁，设置标记，令唤醒操作取消或唤醒后再次抢占锁
			//这里有点小问题，如果刚刚是独占锁释放，即使后续是共享请求
			//也有可能取消唤醒操作，而不是和当前的共享线程一起获取锁
			if (dwStatus&SRWST_Wait)
				dwNewStatus=dwStatus+SRWST_Hold;
			//当前处于共享状态，可以获取锁，增加共享计数
			else
				dwNewStatus=(dwStatus+SRW_DATA_ONE)|SRWST_Hold;
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
			if (dwCurStatus==dwStatus)
				return ;
			RtlBackoff(&dwBackOffCount);
			dwStatus=(DWORD)pSRWLock->Ptr;
		}
	}
}

void NTAPI RtlReleaseSRWLockExclusive(SRWLOCK* pSRWLock)
{
	//去掉Hold标记
	DWORD dwStatus=InterlockedExchangeAdd((DWORD*)pSRWLock,-SRWST_Hold);
	if (!(dwStatus&SRWST_Hold))
		RtlRaiseStatus(0xC0000264);	//STATUS_RESOURCE_NOT_OWNED
	//有线程在等待，且没有线程正在操作链表，执行唤醒操作
	//否则当前操作链表的线程检测到状态改变，执行唤醒操作
	if ((dwStatus&SRWST_Wait) && !(dwStatus&SRWST_Link))
	{
		dwStatus-=SRWST_Hold;
		DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwStatus+SRWST_Link,dwStatus);
		if (dwStatus==dwCurStatus)
			RtlpWakeSRWLock(pSRWLock,dwStatus+SRWST_Link);
	}
}


void NTAPI RtlReleaseSRWLockShared(SRWLOCK* pSRWLock)
{
	DWORD dwStatus=InterlockedCompareExchange((DWORD*)pSRWLock,0,(SRW_DATA_ONE|SRWST_Hold));
	//如果共享计数为1，且标记仅为Hold
	//说明仅有一个共享锁，恢复至空闲状态就可以了
	if (dwStatus==(SRW_DATA_ONE|SRWST_Hold))
		return ;

	if (!(dwStatus&SRWST_Hold))
		RtlRaiseStatus(0xC0000264);

	//只存在共享锁
	if (!(dwStatus&SRWST_Wait))
	{
		do 
		{
			DWORD dwShareCount=dwStatus&SRW_DATAMASK;
			DWORD dwNewStatus;
			//共享计数为1，清空为空闲状态
			if (dwShareCount<=SRW_DATA_ONE)
				dwNewStatus=0;
			//共享计数大于0，将其-1
			else
				dwNewStatus=dwStatus-0x10;
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
			if (dwCurStatus==dwStatus)
				return ;
			dwStatus=dwCurStatus;
		} while (!(dwStatus&SRWST_Wait));
	}

	//有独占请求等待时
	//如果有多个共享锁，计数-1
	if (dwStatus&SRWST_Many)
	{
		SYNCITEM* item=(SYNCITEM*)(dwStatus&SRW_DATAMASK);
		//寻找优化到最近处的notify节点，查询共享计数
		//共享锁接共享锁不会阻塞，也不会新增等待节点
		//共享锁接独占锁，独占锁会等待，并且其item记录共享计数
		//特殊的，独占锁接独占锁，或独占锁接共享锁，记录的共享计数为0
		while (item->notify==NULL)
			item=item->back;	
		item=item->notify;

		//共享计数-1，如果共享计数大于0，说明现在仍有线程占有共享锁
		DWORD count=InterlockedDecrement(&item->count);
		if (count>0)
			return ;
	}

	//共享锁完全释放，唤醒下个等待者
	while (1)
	{
		DWORD dwNewStatus=dwStatus&(~(SRWST_Many|SRWST_Hold));
		//有线程在操作链表，让它去唤醒吧
		if (dwStatus&SRWST_Link)
		{
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
			if (dwCurStatus==dwStatus)
				return ;
			dwStatus=dwCurStatus;
			continue;
		}
		else
		{
			dwNewStatus|=SRWST_Link;
			DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
			if (dwCurStatus==dwStatus)
			{
				dwStatus=dwCurStatus;
				continue;
			}
			RtlpWakeSRWLock(pSRWLock,dwNewStatus);
			return ;
		}
	}
}

BOOL NTAPI RtlTryAcquireSRWLockExclusive(SRWLOCK* pSRWLock)
{
	DWORD dwLockFlag=InterlockedBitTestAndSet((long*)pSRWLock,0);
	return (dwLockFlag!=1);
}

BOOL NTAPI RtlTryAcquireSRWLockShared(SRWLOCK* pSRWLock)
{
	DWORD dwBackOffCount=0;
	DWORD dwStatus=InterlockedCompareExchange((DWORD*)pSRWLock,SRW_DATA_ONE|SRWST_Hold,0);
	if (dwStatus==0)
		return TRUE;
	while (1) 
	{
		if ((dwStatus&SRWST_Hold) && ((dwStatus&SRWST_Wait) || (dwStatus&SRW_DATAMASK)==0))
			return FALSE;
		DWORD dwNewStatus;
		if (dwStatus&SRWST_Wait)
			dwNewStatus=dwStatus+SRWST_Hold;
		else
			dwNewStatus=dwStatus+SRW_DATA_ONE;
		DWORD dwCurStatus=InterlockedCompareExchange((DWORD*)pSRWLock,dwNewStatus,dwStatus);
		if (dwCurStatus==dwStatus)
			return TRUE;
		RtlBackoff(&dwBackOffCount);
		dwStatus=(DWORD)pSRWLock->Ptr;
	}
}
