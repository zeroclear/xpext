
#include <ntddk.h>

/*
Windows时间的最小单元是100ns，一个tick持续多个单元的时间
当时钟中断发生时，相对上一次中断又流逝了一些时间
系统从当前tick减去经过的时间，剩余的时间记录在KiTickOffset
如果剩余时间小于0，代表时间经过了一个tick，当前tick结束
此时需要更新tick数，统计线程工作时间，计算线程时间片（quantum）
环境允许的情况下，还会调用KiTimeUpdateNotifyRoutine（Win7不再支持）
最后，为KiTickOffset补充KeMaximumIncrement个时间单元，进入下个tick
（Win2003的代码里，会根据时间计算出经过了几个tick，而非总是加1个）
如果剩余时间大于0，会处理一些DPC的内容，这里就不管了

更新tick时，首先更新KeTickCount，这是个64位的值，足够记录数万年
但GetTickCount不使用这个值，而是KUSER_SHARED_DATA里的值
Win7下是偏移0x320的TickCount字段，同样也是64位
XP下是偏移0的TickCountLow，只有32位，系统运行一段时间后溢出归零
因为GetTickCount返回也是32位的，一个周期只有49.7天，系统会在溢出后略微调整

只要在KeUpdateSystemTime更新TickCountLow时，同时更新TickCount，就能实现功能
方案1是改ntoskrnl.exe的文件，效果稳定，但麻烦且通用性差
方案2是设置一个Timer，定时把KeTickCount复制过去，最简单但异步操作精度太差
方案3是使用KiTimeUpdateNotifyRoutine，但它只有一个位置，可能被某些特殊软件占用
（注意，判断函数非空和调用函数是分开的，而且没有加锁，清空回调指针有极低概率蓝屏）

尽管Windows通过一些算法，同一时间只允许一个核心执行KeUpdateSystemTime
但是仍有异步的情况发生，比如用户修改时间，也会调整KeTickCount
更新tick为了效率没有使用锁，可能导致KSYSTEM_TIME的Low和High1两个字段不同步
所以Win7 32位引入High2Time，值与High1Time相同，在最后写入
如果读取时，High2Time和High1Time不同，说明写入没有完成，或线程间覆盖写入
GetTickCount稍等一会，循环再次读取，两者相同时，就代表结果正常了
XP使用的计时器是老式的RTC，精度远不如新式的HPET计时器，没必要在意误差了
至于Win7 64位，64位的操作数可以一次性写完两个字段，不需要这种同步方式
*/

/*
VOID __fastcall KeUpdateSystemTime_Win7_32(KIRQL OldIrql,LONG Increment,KTRAP_FRAME* TrFrame)
{
	//...
	LONG MasterOffset=InterlockedExchangeAdd(&Kprcb->MasterOffset,-Increment);
	MasterOffset=MasterOffset-Increment;
	if (MasterOffset<=0)
	{
		ULONG SpinCount=0;
		while (KeTickCount.High1Time!=KeTickCount.High2Time)
		{
			SpinCount++;
			//HvlLongSpinCountMask=0xFFFFFFFF
			if ((SpinCount&HvlLongSpinCountMask)==0 && (HvlEnlightenments&0x40))
				HvlNotifyLongSpinWait(SpinCount);
			_mm_pause();
		}
		ULONGLONG TickCount=*(ULONGLONG*)&KeTickCount;
		TickCount++;
		KeTickCount.High2Time=(ULONG)(TickCount>>32);
		*(ULONGLONG*)&KeTickCount=TickCount;

		KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0xFFDF0000;
		KUserSharedData->TickCount.High2Time=(ULONG)(TickCount>>32);
		*(ULONGLONG*)&KUserSharedData->TickCount=TickCount;

		Kprcb->MasterOffset=KeMaximumIncrement+MasterOffset;
	}
	//...
}

VOID __stdcall KeUpdateSystemTime_XP(KIRQL OldIrql,ULONG Vector,KTRAP_FRAME* TrFramePtr)
{
	//XPSP1\NT\base\hals\halacpi\i386\ixclock.asm
	LONG TimeIncrement=eax;
	KTRAP_FRAME* TrFrame=ebp;
	LONG Zero=ebx;

	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0xFFDF0000;
	ULONGLONG InterruptTime=*(ULONGLONG*)&KUserSharedData->InterruptTime;
	InterruptTime=InterruptTime+TimeIncrement;
	KUserSharedData->InterruptTime.High2Time=(ULONG)(InterruptTime>>32);
	*(ULONGLONG*)&KUserSharedData->InterruptTime=InterruptTime;

	ULONG OldTime=KeTickCount->LowPart;
	KiTickOffset=KiTickOffset-TimeIncrement;
	if (KiTickOffset<=0)
	{
		ULONGLONG SystemTime=*(ULONGLONG*)&KUserSharedData->SystemTime;
		SystemTime=SystemTime+KeTimeAdjustment;
		KUserSharedData->SystemTime.High2Time=(ULONG)(SystemTime>>32);
		*(ULONGLONG*)&KUserSharedData->SystemTime=SystemTime;

		ULONGLONG TickCount=*(ULONGLONG*)&KeTickCount;
		TickCount++;
		KeTickCount.High2Time=(ULONG)(TickCount>>32);
		*(ULONGLONG*)&KeTickCount=TickCount;

		if (KUserSharedData->TickCountLowDeprecated+1==0)	//TickCountLow溢出
			ExpTickCountAdjustmentCount++;

		KUserSharedData->TickCountLowDeprecated=KeTickCount.LowPart+
			ExpTickCountAdjustment*ExpTickCountAdjustmentCount;
		//...
	}

	//中间的部分是做一些DPC相关的操作，可参考NT5代码，这里不写了
	//Win2K3\NT\base\ntos\ke\ia64\clock.c
	//XPSP1\NT\base\ntos\ke\ia64\clock.c

	if (KiTickOffset<=0)
	{
		KiTickOffset=KiTickOffset+KeMaximumIncrement;
		KeUpdateRunTime(OldIrql);
		_asm cli;
		HalEndSystemInterrupt();
	}
	else
	{
		KeGetCurrentPrcb()->InterruptCount++;
		_asm cli;
		HalEndSystemInterrupt();
	}
}

VOID __stdcall KeUpdateRunTime_XP(KIRQL OldIrql)
{
	KTRAP_FRAME* TrFrame=ebp;
	//KPRCB在KPCR偏移0x120处，这里直接用KPRCB
	KPRCB* Prcb=KeGetCurrentPrcb();
	Prcb->InterruptCount++;
	KTHREAD* Thread=Prcb->CurrentThread;
	KPROCESS* Process=Thread->ApcState.Process;
	if (TrFrame->EFlags&0x00020000 //Virtual 8086 Mode
		|| TrFrame->SegCs&1)	
	{
		//edx=1
		Prcb->UserTime++;
		Thread->UserTime++;
		InterlockedIncrement((LONG*)&Process->UserTime);
		//lea     ecx, [ecx+0]
		if (KiTimeUpdateNotifyRoutine!=NULL)
			KiTimeUpdateNotifyRoutine(PsGetCurrentThreadId());	//ecx=ETHREAD::UniqueThread
	}
	else
	{
		//edx=0
		Prcb->KernelTime++;
		if (OldIrql==DISPATCH_LEVEL && Prcb->DpcRoutineActive!=0)
		{
			Prcb->DpcTime++;
		}
		else if (OldIrql>DISPATCH_LEVEL)
		{
			Prcb->InterruptTime++;
		}
		else	//OldIrql<DISPATCH_LEVEL || (OldIrql==DISPATCH_LEVEL && Prcb->DpcRoutineActive==0)
		{
			Thread->KernelTime++;
			InterlockedIncrement((LONG*)&Process->KernelTime);
			if (KiTimeUpdateNotifyRoutine!=NULL)
				KiTimeUpdateNotifyRoutine(PsGetCurrentThreadId());
		}
	}
	//...
}
*/

typedef VOID (__fastcall*FNTIMEUPDATECALLBACK)(HANDLE ThreadId);
extern "C" NTSYSAPI VOID __fastcall KeSetTimeUpdateNotifyRoutine(FNTIMEUPDATECALLBACK TimeUpdateCallback);
KSYSTEM_TIME* KeTickCountAddr=NULL;

//测试阶段，先采用KiTimeUpdateNotifyRoutine
VOID __fastcall KeTimeUpdateCallback(HANDLE ThreadId)
{
	KUSER_SHARED_DATA* KUserSharedData=(KUSER_SHARED_DATA*)0xFFDF0000;
	ULONGLONG TickCount=*(ULONGLONG*)KeTickCountAddr;
	KUserSharedData->TickCount.High2Time=(ULONG)(TickCount>>32);
	*(ULONGLONG*)&KUserSharedData->TickCount=TickCount;
}

void InitTickCount64Helper()
{
	UNICODE_STRING SymbolName;
	RtlInitUnicodeString(&SymbolName,L"KeTickCount");
	KeTickCountAddr=(KSYSTEM_TIME*)MmGetSystemRoutineAddress(&SymbolName);
	DbgPrint("KeTickCount Address:%08X\n",KeTickCountAddr);
	KeSetTimeUpdateNotifyRoutine(KeTimeUpdateCallback);
}

void UninitTickCount64Helper()
{
	ULONG* AsmAddr=(ULONG*)((ULONG)KeSetTimeUpdateNotifyRoutine+2);
	ULONG* KiTimeUpdateNotifyRoutine=(ULONG*)*AsmAddr;
	DbgPrint("KiTimeUpdateNotifyRoutine:%08X\n",KiTimeUpdateNotifyRoutine);
	*KiTimeUpdateNotifyRoutine=NULL;
}