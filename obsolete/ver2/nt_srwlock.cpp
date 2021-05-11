
#include "common.h"

/*
Windows 7 SP1 32位 6.1.7601.17514
@清泠 2020.6.5

SRW的分析
空闲状态，独占请求和共享请求都能获取锁
独占状态，独占请求和共享请求都不能获取锁
共享状态，仅共享请求能获取锁，独占请求不能获取锁
理论上，如果当前是共享锁，后续的所有共享请求都可以获取锁
但是为了防止写入线程出现饥饿状态，应用了相对公平的算法
一旦出现独占请求，后续的所有共享请求都要等待

SRWLOCK是一个容器，保存着这个锁的全部信息
SRWLOCK::Ptr的前28位保存了等待链表的头部（或共享计数）
后4位使用align(16)空出，用于保存状态
链表节点在栈上分配，函数休眠返回前一直有效，返回时自动释放
每次只允许一个线程编辑链表，用SRWF_Link标记控制
新线程进入等待状态时，把旧链表头部设为自己的back节点
自身当做新的链表头部，替换旧的链表头部，完成插入
newi->back=status;
status=&newi;
所以顺着status的back一直向前查找，是按时间由近到远加入的节点
即插入的一端为last，也是头部；另一端为first，是尾部
last沿back一直走能找到first，first沿next一直走能找到last

因为first节点足够重要，last节点会保存first指针，加速后续操作
第一个插入的节点，其first指针指向自身，它既是first也是last
之后插入的节点，会沿着back找之前的节点，把最近处的first指针复制过来
if (curr->first!=NULL)
last->first=curr->first;
刚开始链表没有next字段，在传递first指针的时候会遍历并补全next字段
curr->back->next=curr;
curr=curr->back;
这两个步骤合称优化，在插入新节点时执行

唤醒节点从first端开始，因为这边的线程等待时间最久
如果只唤醒一个线程，会从链表中删除这个节点，并断开next链接
删除作用在last节点的first字段上，因为删除时总从这里找first节点
优化会在这里停下，然后复制过去，也不会受到影响
wake=last->first;
last->first=last->first->next;
wake->next=NULL;
如果需要唤醒的情况比较复杂，就会唤醒所有节点
此时status置0，从first开始，沿next链依次唤醒线程
然后这些线程争夺锁，抢到锁的返回，抢不到的再次休眠

为方便理解，我还画了张图srw_cv.png
*/

DWORD SRWLockSpinCount=0x400;

void NTAPI RtlpInitSRWLock(PEB* pPEB)
{
	if (pPEB->NumberOfProcessors==1)
		SRWLockSpinCount=0;
}

void NTAPI RtlInitializeSRWLock(RTL_SRWLOCK* SRWLock)
{
	SRWLock->Ptr=NULL;
}

void NTAPI RtlpWakeSRWLock(RTL_SRWLOCK* SRWLock,SYNCSTATUS OldStatus)
{
	SYNCSTATUS CurrStatus;
	SYNCITEM* last;
	SYNCITEM* first;
	while (1)
	{
		//已经有线程抢先获取了锁，取消唤醒操作
		if (OldStatus&SRWF_Hold)	//编译器将while(...)编译成if (...) do {} while(...)
		{
			do 
			{
				CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,OldStatus-SRWF_Link,OldStatus);	//清除链表操作标记
				//状态被其它线程更新，设置状态失败
				//本次分析失效，更新状态重新分析
				//下面有大量类似代码，不再重复说明
				if (CurrStatus==OldStatus)
					return ;
				OldStatus=CurrStatus;
			} while (OldStatus&SRWF_Hold);
		}

		last=(SYNCITEM*)(OldStatus&SRWM_ITEM);
		first=last->first;
		if (first==NULL)
		{
			SYNCITEM* curr=last;
			do 
			{
				curr->back->next=curr;	//补全链表
				curr=curr->back;		//遍历链表
				first=curr->first;		//更新查找结果
			} while (first==NULL);		//找一个有效的first
			//first指针提前到最近的地方
			//优化链表里没有这个判断，大概是插入多个节点需要优化时，first一定不为last
			if (last!=curr)	
				last->first=first;
		}

		//如果后续还有节点等待，且这个是独占请求
		if ((first->next!=NULL) && (first->attr&SYNC_Exclusive))
		{
			last->first=first->next;	//从链表中删除这个节点（删除和优化每次都用最近的first指针）
			first->next=NULL;			//first从原链表脱离
			_InterlockedAnd((long*)SRWLock,(~SRWF_Link));	//链表操作全部完成，去掉标记
			break;
		}
		//否则，可能只有这一个节点等待，或这个是共享请求，全部唤醒
		else
		{
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,0,OldStatus);	//将状态重置为空闲
			if (OldStatus==CurrStatus)
				break;
			last->first=first;	//将找到的first放到最近的位置
			OldStatus=CurrStatus;
		}
	}

	//依次唤醒线程，可能仅有first一个，也可能是first链上的全部
	//如果是全部唤醒，接下来线程会再次争夺锁，抢不到的再次循环，构建链表并阻塞
	//好处是省掉了各种情况的分析，后面几个共享锁将成功获得锁，直到遇到独占锁
	do 
	{
		//抢到锁的线程会返回，栈上的item失效，必须先保存next
		SYNCITEM* next=first->next;
		//如果有SYNC_Spinning标记，表示还在自旋等待，即将进入休眠
		//下面的lock btr将其置0，目标线程发现后跳过休眠
		//如果没有SYNC_Spinning标记，说明目标线程清掉了此标记，正式进入休眠
		//下面的lock btr没有影响，本线程负责将目标线程唤醒
		//需要注意的是，NtReleaseKeyedEvent发现key并没有休眠时，会阻塞当前线程
		//直到有线程用此key调用了NtWaitForKeyedEvent，才会唤醒，因此不会丢失通知
		if (InterlockedBitTestAndReset((LONG*)&(first->attr),SYNC_SPIN_BIT)==0)
			NtReleaseKeyedEvent(GlobalKeyedEventHandle,first,FALSE,NULL);
		first=next;	//遍历链表
	} while (first!=NULL);
}

void NTAPI RtlpOptimizeSRWLockList(RTL_SRWLOCK* SRWLock,SYNCSTATUS OldStatus)
{
	if (OldStatus&SRWF_Hold)
	{
		do 
		{
			SYNCITEM* last=(SYNCITEM*)(OldStatus&SRWM_ITEM);
			if (last!=NULL)
			{
				SYNCITEM* curr=last;
				while (curr->first==NULL)
				{
					curr->back->next=curr;	//补全链表
					curr=curr->back;		//遍历链表
				}
				last->first=curr->first;	//将first放到离容器入口最近的位置，加速下次查找
			}
			//链表操作结束，清除标记
			SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,OldStatus-SRWF_Link,OldStatus);
			if (CurrStatus==OldStatus)
				return ;
			OldStatus=CurrStatus;
		} while (OldStatus&SRWF_Hold);
	}
	//有人释放了锁，停止优化，改为唤醒
	RtlpWakeSRWLock(SRWLock,OldStatus);
}

void NTAPI RtlAcquireSRWLockExclusive(RTL_SRWLOCK* SRWLock)
{
	//volatile
	__declspec(align(16)) SYNCITEM item;
	BOOL IsOptimize;
	SYNCSTATUS NewStatus;
	DWORD dwBackOffCount=0;

	//如果当前状态为空闲，直接获取锁
	//甚至某个线程刚释放锁，仅清除了Hold标记，其它线程还没来得及获取锁
	//本线程也可以趁机获取锁，设置标记，令唤醒操作取消或唤醒后再次进入等待
	if (InterlockedBitTestAndSet((LONG*)SRWLock,SRW_HOLD_BIT)==0)
		return ;

	SYNCSTATUS OldStatus=(SYNCSTATUS)(SRWLock->Ptr);
	SYNCSTATUS CurrStatus;
	while (1)
	{
		//如果当前已有线程持有锁，本线程将构建节点，将自己加入链表
		if (OldStatus&SRWF_Hold)
		{
			if (RtlpWaitCouldDeadlock())
			{
				//GetCurrentProcess(),STATUS_THREAD_IS_TERMINATING
				NtTerminateProcess((HANDLE)0xFFFFFFFF,0xC000004B);
			}

			item.attr=SYNC_Exclusive|SYNC_Spinning;
			item.next=NULL;
			IsOptimize=FALSE;

			//如果有线程已经在前面等待了，就把之前的节点设为back
			if (OldStatus&SRWF_Wait)
			{
				item.first=NULL;
				item.count=0;
				item.back=(SYNCITEM*)(OldStatus&SRWM_ITEM);
				NewStatus=((SYNCSTATUS)&item)|(OldStatus&SRWF_Many)|(SRWF_Link|SRWF_Wait|SRWF_Hold);

				if (!(OldStatus&SRWF_Link))	//当前没人操作链表，就优化链表
					IsOptimize=TRUE;
			}
			//如果本线程是第一个等待的线程，first指向自己
			//查找时以first指针为准，不需要设置back
			else
			{
				item.first=&item;
				//如果锁的拥有者以独占方式持有，共享计数为0
				//如果锁的拥有者以共享方式持有，共享计数为1或更多
				item.count=OldStatus>>SRW_COUNT_BIT;
				if (item.count>1)
					NewStatus=((SYNCSTATUS)&item)|(SRWF_Many|SRWF_Wait|SRWF_Hold);
				else
					NewStatus=((SYNCSTATUS)&item)|(SRWF_Wait|SRWF_Hold);
			}
			//提交新状态
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
			{
				if (IsOptimize)
					RtlpOptimizeSRWLockList(SRWLock,NewStatus);
				//进入内核的代价太高，先进行一段自旋等待
				for (int i=SRWLockSpinCount;i>0;i--)
				{
					if (!(item.attr&SYNC_Spinning))	//其它线程可能唤醒本线程，清除标记
						break;
					_mm_pause();
				}
				//如果一直没能等到唤醒，就进入内核休眠
				if (InterlockedBitTestAndReset((LONG*)(&item.attr),SYNC_SPIN_BIT))
					NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,NULL);
				//被唤醒后再次循环检测条件
				OldStatus=CurrStatus;
			}
			else
			{
				//线程处于激烈的竞争中，退避一段时间
				RtlBackoff(&dwBackOffCount);
				OldStatus=(SYNCSTATUS)(SRWLock->Ptr);
			}
		}
		//别的线程可能做了什么，反正现在没有线程持有锁了，尝试获取锁
		else
		{
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,OldStatus+SRWF_Hold,OldStatus);
			if (CurrStatus==OldStatus)
				return ;
			RtlBackoff(&dwBackOffCount);
			OldStatus=(SYNCSTATUS)(SRWLock->Ptr);
		}
	}
}

void NTAPI RtlAcquireSRWLockShared(RTL_SRWLOCK* SRWLock)
{
	//volatile
	__declspec(align(16)) SYNCITEM item;
	BOOL IsOptimize;
	DWORD dwBackOffCount=0;

	SYNCSTATUS NewStatus;
	SYNCSTATUS CurrStatus;
	SYNCSTATUS OldStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,(1<<SRW_COUNT_BIT)|SRWF_Hold,0);
	//如果当前状态为空闲，直接获取锁
	if (OldStatus==0)
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
		if ((OldStatus&SRWF_Hold) && ((OldStatus&SRWF_Wait) || ((OldStatus&SRWM_ITEM)==NULL)))
		{
			if (RtlpWaitCouldDeadlock())
				NtTerminateProcess((HANDLE)0xFFFFFFFF,0xC000004B);

			item.attr=SYNC_Spinning;
			item.count=0;
			IsOptimize=FALSE;
			item.next=NULL;

			if (OldStatus&SRWF_Wait)
			{
				item.back=(SYNCITEM*)(OldStatus&SRWM_ITEM);
				//原汇编就是这么写的，但是刚才SRWF_Hold已经检测到了
				NewStatus=((SYNCSTATUS)&item)|(OldStatus&(SRWF_Many|SRWF_Hold))|(SRWF_Link|SRWF_Wait);
				item.first=NULL;

				if (!(OldStatus&SRWF_Link))
					IsOptimize=TRUE;
			}
			else
			{
				item.first=&item;
				//当前一定是独占锁，所以不用考虑SRWF_Many
				NewStatus=((SYNCSTATUS)&item)|(SRWF_Wait|SRWF_Hold);
			}

			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
			{
				if (IsOptimize)
					RtlpOptimizeSRWLockList(SRWLock,NewStatus);

				for (int i=SRWLockSpinCount;i>0;i--)
				{
					if (!(item.attr&SYNC_Spinning))
						break;
					_mm_pause();
				}

				if (InterlockedBitTestAndReset((LONG*)&(item.attr),SYNC_SPIN_BIT))
					NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,NULL);
				OldStatus=CurrStatus;
			}
			else
			{
				RtlBackoff(&dwBackOffCount);
				OldStatus=(SYNCSTATUS)SRWLock->Ptr;
			}
		}
		else
		{
			//某个线程刚释放锁，仅清除了Hold标记，其它线程还没来得及获取锁
			//本线程可以趁机获取锁，设置标记，令唤醒操作取消或唤醒后再次抢占锁
			//这里有点小问题，如果刚刚是独占锁释放，即使后续是共享请求
			//也有可能取消唤醒操作，而不是和当前的共享线程一起获取锁
			if (OldStatus&SRWF_Wait)
				NewStatus=OldStatus+SRWF_Hold;
			//当前处于共享状态，可以获取锁，增加共享计数
			else
				NewStatus=(OldStatus+(1<<SRW_COUNT_BIT))|SRWF_Hold;
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
				return ;
			RtlBackoff(&dwBackOffCount);
			OldStatus=(SYNCSTATUS)SRWLock->Ptr;
		}
	}
}

void NTAPI RtlReleaseSRWLockExclusive(RTL_SRWLOCK* SRWLock)
{
	//去掉Hold标记
	SYNCSTATUS OldStatus=InterlockedExchangeAdd((SYNCSTATUS*)SRWLock,-SRWF_Hold);
	if (!(OldStatus&SRWF_Hold))
		RtlRaiseStatus(0xC0000264);	//STATUS_RESOURCE_NOT_OWNED
	//有线程在等待，且没有线程正在操作链表，执行唤醒操作
	//否则当前操作链表的线程检测到状态改变，执行唤醒操作
	if ((OldStatus&SRWF_Wait) && !(OldStatus&SRWF_Link))
	{
		OldStatus-=SRWF_Hold;
		SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,OldStatus+SRWF_Link,OldStatus);
		if (OldStatus==CurrStatus)
			RtlpWakeSRWLock(SRWLock,OldStatus+SRWF_Link);
	}
}

void NTAPI RtlReleaseSRWLockShared(RTL_SRWLOCK* SRWLock)
{
	SYNCSTATUS CurrStatus,NewStatus;
	SYNCSTATUS OldStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,0,((1<<SRW_COUNT_BIT)|SRWF_Hold));
	//如果共享计数为1，且标记仅为Hold
	//说明仅有一个共享锁，恢复至空闲状态就可以了
	if (OldStatus==((1<<SRW_COUNT_BIT)|SRWF_Hold))
		return ;

	if (!(OldStatus&SRWF_Hold))
		RtlRaiseStatus(0xC0000264);

	//只存在共享锁
	if (!(OldStatus&SRWF_Wait))
	{
		do 
		{
			//共享计数为1，清空为空闲状态
			if ((OldStatus&SRWM_COUNT)<=(1<<SRW_COUNT_BIT))
				NewStatus=0;
			//共享计数大于0，将其-1
			else
				NewStatus=OldStatus-(1<<SRW_COUNT_BIT);
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
				return ;
			OldStatus=CurrStatus;
		} while (!(OldStatus&SRWF_Wait));
	}

	//有独占请求等待时
	//如果有多个共享锁，计数-1
	if (OldStatus&SRWF_Many)
	{
		SYNCITEM* curr=(SYNCITEM*)(OldStatus&SRWM_ITEM);
		//寻找最近的first节点，查询共享计数
		//共享锁接共享锁不会阻塞，也不会新增等待节点
		//共享锁接独占锁，独占锁会等待，并且其item记录共享计数
		//特殊的，独占锁接独占锁，或独占锁接共享锁，记录的共享计数为0
		while (curr->first==NULL)
			curr=curr->back;	
		curr=curr->first;

		//共享计数-1，如果共享计数大于0，说明现在仍有线程占有共享锁
		DWORD count=InterlockedDecrement(&curr->count);
		if (count>0)
			return ;
	}

	//共享锁完全释放，唤醒下个等待者
	while (1)
	{
		NewStatus=OldStatus&(~(SRWF_Many|SRWF_Hold));
		//有线程在操作链表，让它去唤醒吧
		if (OldStatus&SRWF_Link)
		{
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
				return ;
		}
		else
		{
			NewStatus|=SRWF_Link;
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
			{
				RtlpWakeSRWLock(SRWLock,NewStatus);
				return ;
			}
		}
		OldStatus=CurrStatus;
	}
}

BOOL NTAPI RtlTryAcquireSRWLockExclusive(RTL_SRWLOCK* SRWLock)
{
	BOOL IsLocked=InterlockedBitTestAndSet((LONG*)SRWLock,SRW_HOLD_BIT);
	return !(IsLocked==TRUE);
}

BOOL NTAPI RtlTryAcquireSRWLockShared(RTL_SRWLOCK* SRWLock)
{
	DWORD dwBackOffCount=0;
	SYNCSTATUS OldStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,(1<<SRW_COUNT_BIT)|SRWF_Hold,0);
	if (OldStatus==0)
		return TRUE;
	while (1) 
	{
		if ((OldStatus&SRWF_Hold) && ((OldStatus&SRWF_Wait) || (OldStatus&SRWM_ITEM)==NULL))
			return FALSE;
		SYNCSTATUS NewStatus;
		if (OldStatus&SRWF_Wait)
			NewStatus=OldStatus+SRWF_Hold;
		else
			NewStatus=OldStatus+(1<<SRW_COUNT_BIT);
		SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
		if (CurrStatus==OldStatus)
			return TRUE;
		RtlBackoff(&dwBackOffCount);
		OldStatus=(SYNCSTATUS)SRWLock->Ptr;
	}
}


