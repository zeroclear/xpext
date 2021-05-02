
#include "common.h"

/*
Windows 7 SP1 32位 6.1.7601.17514
@清泠 2021.4.12

CV的分析
CV内部要做的事是：释放锁-休眠-（被唤醒）获取锁
基本的实现机制与SRW极为相似，都是以容器保存链表
前面28位是节点指针，后面4位是标记
调用SleepXXX时，就往链表的头部插入一个
依旧是插入的一端为last，另一端为first
last沿back一直走能找到first，first沿next一直走能找到last
当然也有类似的链表优化策略

最主要的不同在于唤醒
如果当前没有其他线程操作链表，直接调用唤醒函数即可
而有线程正在操作链表时，此线程会设置CVF_Link标记，阻止其他线程访问
若此时有唤醒请求，会在后3位的flag留下记录，然后立即返回
每个操作链表的函数，最后都会调用一次唤醒函数，按照请求执行唤醒
最后3位的flag实际是个count，唤醒1个就给这个count+1，3位最多能存7个请求
数量大于等于7时，视为全部唤醒（会导致spurious wakeup）

唤醒函数统计请求的数量，等于7全部唤醒，小于7则从链表取出对应的个数
如果数量不够，有多少就唤醒多少（但操作和全部唤醒有点不一样）
全部唤醒将status置0，并获取last节点，沿着back链唤醒所有节点
按数量唤醒会准备一个新的链表当collector，将旧链表移除的节点收集起来
移除从旧链表的first开始，沿next链，直到last为止（数量不够的话）
移除的节点从当前节点的的位置插入，成为back节点
oldcurr->next->back=NULL;
newcurr->back=oldcurr;
如果原链表从last到first，沿back链遇到的是54321
那么新链表从collector的head，到tail，沿back链，遇到的是12345
这么做保证了操作方式的一致性，最后，沿新链表的back链逐个唤醒

唤醒时采用了一个优化策略，（如果有SRW的话）检测SRW的状态
如果SRW被占用，此时唤醒是没有意义的，接着调用AcquireSRW又会进入休眠
所以CV的实现将SRW拆成了3部分，第一部分是SRW的状态判断
第二部分是SRW的休眠，第三部分是SRW唤醒后获取失败，又循环一次
唤醒函数实现了第一部分，将线程扔到SRW等待队列去，省去了第二部分的开销
SRW因释放变动时，线程才被唤醒，接下来的AcquireSRW尝试获取锁
成功则返回，失败则停在这里等待，就像SRW里又循环了一遍一样

与SRW不同，CV可能等待超时，自己主动醒来
此时只要将自身对应的节点从链表中删除，就可以返回了
但是因为唤醒的优化策略，节点可能不在链表里了，而是被扔到SRW里
所以需要寻找节点，分别处理两种情况
找到节点一切正常，删除自身节点并返回
找不到节点说明SRW被占用，还不是唤醒的时候，就继续休眠
*/

BOOL WINAPI K32SleepConditionVariableCS(PCONDITION_VARIABLE ConditionVariable,PCRITICAL_SECTION CriticalSection,DWORD dwMilliseconds)
{
	LARGE_INTEGER Timeout;
	NTSTATUS Result=RtlSleepConditionVariableCS(ConditionVariable,CriticalSection,BaseFormatTimeOut(&Timeout,dwMilliseconds));
	BaseSetLastNTError(Result);
	if (NT_SUCCESS(Result) && Result!=STATUS_TIMEOUT)
		return TRUE;
	return FALSE;
}

BOOL WINAPI K32SleepConditionVariableSRW(PCONDITION_VARIABLE ConditionVariable,PSRWLOCK SRWLock,DWORD dwMilliseconds,ULONG Flags)
{
	LARGE_INTEGER Timeout;
	NTSTATUS Result=RtlSleepConditionVariableSRW(ConditionVariable,SRWLock,BaseFormatTimeOut(&Timeout,dwMilliseconds),Flags);
	BaseSetLastNTError(Result);
	if (NT_SUCCESS(Result) && Result!=STATUS_TIMEOUT)
		return TRUE;
	return FALSE;
}

DWORD ConditionVariableSpinCount=0x400;

void NTAPI RtlpInitConditionVariable(PEB* pPeb)
{
	if (pPeb->NumberOfProcessors==1)
		ConditionVariableSpinCount=0; 
}

void NTAPI RtlInitializeConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable)
{
	ConditionVariable->Ptr=NULL;
}

//返回TRUE不唤醒，返回FALSE唤醒
BOOL RtlpQueueWaitBlockToSRWLock(SYNCITEM* Item,RTL_SRWLOCK* SRWLock,BOOL IsSharedLock)
{
	SYNCSTATUS OldStatus=(SYNCSTATUS)SRWLock->Ptr;
	DWORD dwBackOffCount=0;
	//没人持有锁，可获取，返回
	if ((OldStatus&SRWF_Hold)==0)
	{
		do 
		{
			if (IsSharedLock==FALSE)
				Item->attr|=SYNC_Exclusive;
			else
			{
				//如果无人等待，且共享计数大于0，说明是持有者是共享锁
				//本线程要获取共享锁，可获取，返回
				//否则前面有线程在等待，本线程也应该跟在后面等
				if (!(OldStatus&SRWF_Wait) && (OldStatus&CVM_ITEM)!=0)
					return FALSE;
			}
			//前面至少有一个独占锁在等待，导致后面排队
			//按独占锁的方式将自身节点插入
			Item->next=NULL;
			SYNCSTATUS NewStatus;
			if (OldStatus&SRWF_Wait)
			{
				Item->first=NULL;
				Item->count=0;
				Item->back=(SYNCITEM*)(OldStatus&CVM_ITEM);
				NewStatus=(OldStatus&SRWM_FLAG)|(SYNCSTATUS)Item;
			}
			else
			{
				Item->count=OldStatus>>SRW_COUNT_BIT;
				Item->first=Item;
				NewStatus=(SYNCSTATUS)Item;
				if (Item->count>1)
					NewStatus|=SRWF_Hold|SRWF_Wait|SRWF_Many;
				else
					NewStatus|=SRWF_Hold|SRWF_Wait;
			}
			SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)SRWLock,NewStatus,OldStatus);
			//插入SRW成功，返回TRUE不唤醒
			if (CurrStatus==OldStatus)
				return TRUE;
			RtlBackoff(&dwBackOffCount);
			OldStatus=(SYNCSTATUS)SRWLock->Ptr;
		} while (OldStatus&SRWF_Hold);
	}
	return FALSE;
}

void RtlpWakeConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable,SYNCSTATUS OldStatus,int WakeCount)
{
	SYNCITEM* notify=NULL;
	int CollectNum=0;
	SYNCSTATUS CurrStatus;
	SYNCITEM** InsertPos=&notify;

	while (1)
	{
		//登记的请求已满，全部唤醒，将last链移入通知链表，清空容器
		if ((OldStatus&CVF_Full)==CVF_Full)
		{
			CurrStatus=InterlockedExchange((SYNCSTATUS*)ConditionVariable,0);
			*InsertPos=(SYNCITEM*)(CurrStatus&CVM_ITEM);
			break;
		}
		//否则按请求数量唤醒，从first端开始
		SYNCITEM* curr=(SYNCITEM*)(OldStatus&CVM_ITEM);
		int RequestNum=(OldStatus&CVM_COUNT)+WakeCount;
		SYNCITEM** FirstPos=&curr->first;
		if (*FirstPos==NULL)
		{
			do 
			{
				SYNCITEM* temp=curr;
				curr=curr->back;
				curr->next=temp;
			} while (curr->first==NULL);
		}
		curr=curr->first;
		//将节点从等待链表移除，转移到通知链表
		if (CollectNum<RequestNum)
		{
			do 
			{
				SYNCITEM* next=curr->next;
				if (next==NULL)		//到达head，没有更多了
					break;
				CollectNum++;
				*InsertPos=curr;	//第一次是往notify头插入，后面都是往back链插入
				//curr成为新链表的端点，其back为NULL
				//实际旧链表每移除一个，后面的就会将back设为NULL，这里肯定为NULL
				//虽然新建的链表用不到next链，还不如把next设为NULL，缓解强迫症
				curr->back=NULL;
				*FirstPos=next;		//从first端移除一个后，当前的first会变为first->next，head处记录的first要同步更新
				next->back=NULL;	//curr从链表脱离，next成为新的first
				InsertPos=&curr->back;
				curr=next;			//从first向last遍历
			} while (CollectNum<RequestNum);
		}
		//如果数量不够，有多少通知多少
		if (CollectNum<RequestNum)
		{
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,0,OldStatus);
			if (CurrStatus==OldStatus)
			{
				//没有更多了，填上最后一个，开始通知，CollectNum已经用不到了
				*InsertPos=curr;
				curr->back=NULL;
				break;
			}
			else
			{
				//如果又有了新的等待节点，notify链表和CollectNum均保留，继续收集
				//这里没填上最后一个，因为数量本来就不够，希望再来一轮能够数
				OldStatus=CurrStatus;
				continue;
			}
		}
		//收集数量等于请求数量，将请求数清零，开始通知
		CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,OldStatus&CVM_ITEM,OldStatus);
		if (OldStatus==CurrStatus)
			break;
		OldStatus=CurrStatus;
	}
	//通知notify链表收集的节点，沿back链唤醒
	if (notify!=NULL)
	{
		do 
		{
			SYNCITEM* back=notify->back;
			if (InterlockedBitTestAndReset((LONG*)&notify->attr,SYNC_SPIN_BIT)==0)
			{
				//CV节点和SRW节点结构一样，拿来重复利用
				if (notify->lock!=NULL || 
					RtlpQueueWaitBlockToSRWLock(notify,notify->lock,(notify->attr&SYNC_SharedLock))==FALSE)
				{
					NtReleaseKeyedEvent(GlobalKeyedEventHandle,notify,FALSE,NULL);
				}
				notify=back;
			}
		} while (notify!=NULL);
	}
}

//返回TRUE准备完成，返回FALSE继续休眠
BOOL NTAPI RtlpWakeSingle(RTL_CONDITION_VARIABLE* ConditionVariable,SYNCITEM* Item)
{
	SYNCSTATUS CurrStatus,NewStatus;
	SYNCSTATUS OldStatus=(SYNCSTATUS)ConditionVariable->Ptr;
	//肯定找不到目标节点了
	if (OldStatus==0)
		return FALSE;
	while (1)
	{
		//大量申请没来得及处理，一定会发生竞争，还是继续休眠吧
		int Count=OldStatus&CVM_COUNT;
		if (Count==CVF_Full)
			return FALSE;
		//有人在操作链表，登记唤醒申请（为什么要全部唤醒而不是+1？）
		if (OldStatus&CVF_Link)
		{
			NewStatus=OldStatus|CVF_Full;
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
				return FALSE;
		}
		else
		{
			//准备操作链表
			NewStatus=OldStatus+CVF_Link;
			CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,NewStatus,OldStatus);
			if (CurrStatus==OldStatus)
				break;
		}
		OldStatus=CurrStatus;
		if (CurrStatus==0)
			return FALSE;
	}

	//设置成功，CurrStatus就是NewStatus
	SYNCITEM* curr=(SYNCITEM*)(NewStatus&CVM_ITEM);
	OldStatus=NewStatus;
	SYNCITEM* last=curr;
	SYNCITEM* next=NULL;
	int result=FALSE;

	//从last沿back遍历
	if (curr!=NULL)
	{
		do 
		{
			//没找到目标，沿back继续遍历
			if (curr!=Item)	
			{
				curr->next=next;	//顺路补全next链
				next=curr;			//保存curr，在下次循环中，curr=curr->back，next就是真正的next了
				curr=curr->back;
			}
			//找到目标，从链表移除，继续遍历（可能有重复节点）
			else
			{
				if (next==NULL)	//curr是last
				{
					SYNCITEM* back=curr->back;
					NewStatus=(SYNCSTATUS)back;
					if (back!=NULL)
					{
						//因为back是节点指针，所以最后4位为0
						//第一个异或，将OldStatus的后4位赋值给back后4位的0
						//接着是and，截断前面的结果，前28位为0，只留下后4位
						//第二个异或，将back前28位的指针部分赋值给中间结果前面的0
						//合起来就是dwNewStatus= (dwOldStatus & 0x0F) | (back & 0xFFFFFFF0)
						NewStatus=((NewStatus ^ OldStatus) & CVM_FLAG) ^ (SYNCSTATUS)back;
					}
					//移除curr，并将curr->back设为新的last
					CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,NewStatus,OldStatus);
					if (CurrStatus==OldStatus)
					{
						OldStatus=NewStatus;
						if (back==NULL)	//链表空了
							return TRUE;
						else
							result=TRUE;
					}
					else
					{
						//设置成功，CurrStatus就是NewStatus
						OldStatus=CurrStatus;
					}
					//更新指针，继续操作
					curr=(SYNCITEM*)(OldStatus&CVM_ITEM);
					last=curr;
					next=NULL;
				}
				else	//curr不是last
				{
					curr=curr->back;
					result=TRUE;
					next->back=curr;	//一边断开链接
					if (curr==NULL)		//到头了，first前面没有了
						break;
					curr->next=next;	//另一边断开链接
				}
			}
		} while (curr!=NULL);
		//搜索到头，curr为NULL，next为first
		if (last!=NULL)
			last->first=next;
	}

	RtlpWakeConditionVariable(ConditionVariable,NewStatus,0);
	return result;
}

void NTAPI RtlpOptimizeConditionVariableWaitList(RTL_CONDITION_VARIABLE* ConditionVariable,SYNCSTATUS OldStatus)
{
	do 
	{
		SYNCITEM* curr=(SYNCITEM*)(OldStatus&CVM_ITEM);
		SYNCITEM** FirstPos=&curr->first;
		if (*FirstPos==NULL)
		{
			do 
			{
				SYNCITEM* temp=curr;
				curr=curr->back;
				curr->next=temp;
			} while (curr->first==NULL);
		}
		curr=curr->first;
		*FirstPos=curr;
		SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,OldStatus&CVM_ITEM,OldStatus);
		if (CurrStatus==OldStatus)
			return ;
		OldStatus=CurrStatus;
	} while ((OldStatus&CVM_COUNT)==0);
	//如果在自己操作链表期间，有人提交了唤醒申请，就应该负责唤醒
	RtlpWakeConditionVariable(ConditionVariable,OldStatus,0);
}



NTSTATUS NTAPI RtlSleepConditionVariableCS(RTL_CONDITION_VARIABLE* ConditionVariable,RTL_CRITICAL_SECTION* CriticalSection,LARGE_INTEGER* Timeout)
{
	//volatile
	__declspec(align(16)) SYNCITEM item;
	item.next=NULL;
	item.lock=NULL;
	item.attr=SYNC_Spinning;

	SYNCSTATUS OldStatus=(SYNCSTATUS)ConditionVariable->Ptr;
	SYNCSTATUS NewStatus;

	while (1)
	{
		NewStatus=(OldStatus&CVM_FLAG)|((SYNCSTATUS)&item);
		item.back=(SYNCITEM*)(OldStatus&CVM_ITEM);
		if (item.back==NULL)
		{
			//链表内没有等待节点，自己是第一个
			item.first=&item;
		}
		else
		{
			//链表内已经有等待节点，将它们放到back
			item.first=NULL;
			NewStatus|=CVF_Link;
		}
		//将自身节点插入
		SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,NewStatus,OldStatus);
		if (CurrStatus==OldStatus)
			break;
		OldStatus=CurrStatus;
	}

	RtlLeaveCriticalSection(CriticalSection);

	//检测第3位（从0开始数），异或有4种情况
	//1.old有标记，new有标记，异或为false
	//别的线程正在操作链表，需要优化但无法进行
	//2.old有标记，new没标记，异或为true
	//别的线程正在操作链表，而且链表内只有一个，为什么要进行优化？
	//3.old没标记，new没标记，异或为false
	//无人操作链表，但链表内只有一个，不需要优化
	//4.old没标记，new有标记，异或为true
	//无人操作链表，需要优化，可以进行优化
	if ((OldStatus^NewStatus)&CVF_Link)
	{
		RtlpOptimizeConditionVariableWaitList(ConditionVariable,NewStatus);
	}

	for (int i=ConditionVariableSpinCount;i>0;i--)
	{
		if (!(item.attr&SYNC_Spinning))
			break;
		_mm_pause();
	}

	NTSTATUS result=STATUS_SUCCESS;
	if (InterlockedBitTestAndReset((long*)(&item.attr),SYNC_SPIN_BIT))
	{
		result=NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,Timeout);
		if (result==STATUS_TIMEOUT)
		{
			//如果主动醒来，去链表找自己的节点移除
			if (RtlpWakeSingle(ConditionVariable,&item)==FALSE)
			{
				NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,NULL);
				result=STATUS_SUCCESS;
			}
		}
	}
	RtlEnterCriticalSection(CriticalSection);
	return result;
}

NTSTATUS NTAPI RtlSleepConditionVariableSRW(RTL_CONDITION_VARIABLE* ConditionVariable,RTL_SRWLOCK* SRWLock,LARGE_INTEGER* Timeout,ULONG Flags)
{
	//volatile
	__declspec(align(16)) SYNCITEM item;
	if (Flags&(~CONDITION_VARIABLE_LOCKMODE_SHARED))	//0xFFFFFFFE
		return 0xC00000F0;	//STATUS_INVALID_PARAMETER_2
	SYNCSTATUS OldStatus=(SYNCSTATUS)ConditionVariable->Ptr;
	item.next=NULL;
	item.lock=SRWLock;
	item.attr=SYNC_Spinning;
	BOOL IsSharedLock=Flags&CONDITION_VARIABLE_LOCKMODE_SHARED;
	if (IsSharedLock)
		item.attr|=SYNC_SharedLock;

	SYNCSTATUS NewStatus;
	while (1)
	{
		NewStatus=(OldStatus&CVM_FLAG)|(SYNCSTATUS)&item;
		item.back=(SYNCITEM*)(OldStatus&CVM_ITEM);
		if (item.back==NULL)
		{
			item.first=&item;
		}
		else
		{
			item.first=NULL;
			NewStatus|=CVF_Link;
		}
		SYNCSTATUS CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,NewStatus,OldStatus);
		if (CurrStatus==OldStatus)
			break;
		OldStatus=CurrStatus;
	}

	if (IsSharedLock)
		RtlReleaseSRWLockShared(SRWLock);
	else
		RtlReleaseSRWLockExclusive(SRWLock);

	if ((OldStatus^NewStatus) & CVF_Link)
		RtlpOptimizeConditionVariableWaitList(ConditionVariable,NewStatus);

	for (int i=ConditionVariableSpinCount;i>0;i--)
	{
		if (!(item.attr&SYNC_Spinning))
			break;
		_mm_pause();
	}

	NTSTATUS result=STATUS_SUCCESS;
	if (InterlockedBitTestAndReset((LONG*)(&item.attr),SYNC_SPIN_BIT))
	{
		result=NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,Timeout);
		if (result==STATUS_TIMEOUT)
		{
			if (RtlpWakeSingle(ConditionVariable,&item)==FALSE)
			{
				NtWaitForKeyedEvent(GlobalKeyedEventHandle,&item,FALSE,NULL);
				result=STATUS_SUCCESS;
			}
		}
	}

	if (IsSharedLock)
		RtlAcquireSRWLockShared(SRWLock);
	else
		RtlAcquireSRWLockExclusive(SRWLock);
	return result;
}

void NTAPI RtlWakeConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable)
{
	SYNCSTATUS OldStatus=(SYNCSTATUS)ConditionVariable->Ptr;
	SYNCSTATUS CurrStatus;
	if (OldStatus!=0)
	{
		do 
		{
			//别的线程在操作链表
			if (OldStatus&CVF_Link)
			{
				//已经有全部唤醒的登记了，返回
				if ((OldStatus&CVF_Full)==CVF_Full)
					return ;
				//需要唤醒的个数+1
				CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,OldStatus+1,OldStatus);
				if (CurrStatus==OldStatus)
					return ;
			}
			else
			{
				//当前没有别的线程操作链表，进行唤醒
				CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,OldStatus+CVF_Link,OldStatus);
				if (CurrStatus==OldStatus)
				{
					RtlpWakeConditionVariable(ConditionVariable,OldStatus+CVF_Link,1);
					return ;
				}
			}
			OldStatus=CurrStatus;
		} while (OldStatus==0);
	}
}

void NTAPI RtlWakeAllConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable)
{
	SYNCSTATUS OldStatus=(SYNCSTATUS)ConditionVariable->Ptr;
	SYNCSTATUS CurrStatus;
	if (OldStatus!=0)
	{
		do 
		{
			//已经有全部唤醒的登记了，返回
			if ((OldStatus&CVF_Full)==CVF_Full)
				return ;
			//别的线程在操作链表，登记全部唤醒
			if ((OldStatus&CVF_Link))
			{
				CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,OldStatus|CVF_Full,OldStatus);
				if (OldStatus==CurrStatus)
					return ;
			}
			else
			{
				//将容器置空，从last端沿back链逐个唤醒
				CurrStatus=InterlockedCompareExchange((SYNCSTATUS*)ConditionVariable,0,OldStatus);
				if (OldStatus==CurrStatus)
				{
					SYNCITEM* curr=(SYNCITEM*)(OldStatus&CVM_ITEM);					
					if (curr!=NULL)
					{
						do 
						{
							SYNCITEM* back=curr->back;
							if (InterlockedBitTestAndReset((LONG*)&curr->attr,SYNC_SPIN_BIT)==0)
								NtReleaseKeyedEvent(GlobalKeyedEventHandle,curr,FALSE,NULL);
							curr=back;
						} while (curr!=NULL);
					}
					return ;
				}
			}
			OldStatus=CurrStatus;
		} while (OldStatus!=0);
	}
}
