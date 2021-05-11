
#include <ntddk.h>

/*
想要知道线程当前运行在哪个CPU核心上，每个核心就需要一块关联的空间，用来记录和读取ID
可用的选择大概只有CPU的GDT、IDT、MSR，以及操作系统的KPCR，64个核心需要6bit存储
Win7在KPCR记录了CPU每个核心的编号以及组号，供内核相关API查询
但是KCPR在Ring0，Ring3想访问就要经过复杂的系统调用，Ring3需要寻找更高效的方案

与内核中的其它表不同，Ring3可以通过lsl指令获得段界限，于是Win7选择在GDT记录ID
如果一个段的长度很短，段界限就用不到更高的位，空出来的部分可以用来记录CPU编号
存放TEB的那个段就满足要求，它体积不大，索引固定，Ring3代码总是能访问到
在前面增加几位，让段界限比实际大一些，并没有什么问题，我们修改它就能完成目标
要做的就是在Ring0将GDT的第8项的14到19位设置上编号，在Ring3用lsl指令读取

Win7以后的64位系统将CPU编组，还需要记录组号（32位组号总为0）
组号是一个WORD，应该为16bit，可能是CPU总数也用WORD表示，组号=65536/64=1024个，需要10bit
Win7 x64将组号记录在段界限的低10位，再加上高6位的CPU编号，只剩下中间4位可用
不过64位CPU设计发生了变化，段地址默认从0开始，覆盖全部地址空间，不再检查段界限
得益于这项机制，Win7 x64的GDT总数减少，TEB所在段也进行调整，换到了索引10

我没能找到Win7内核实现的汇编代码，仅仅是从GetCurrentProcessorNumberEx的汇编推测而来
理论上是这样的，但是PCHunter对GDT的识别有问题，显示不正常
*/

#pragma pack(1)
typedef struct _GDTR
{
	USHORT Limit;
	ULONG Base;
} GDTR;

typedef struct _GDT
{
	USHORT Limit0_15;
	USHORT Base0_15;
	UCHAR Base16_23;
	UCHAR Type:4;
	UCHAR S:1;
	UCHAR DPL:2;
	UCHAR P:1;
	UCHAR Limit16_19:4;
	UCHAR AVL:1;
	UCHAR L:1;
	UCHAR D_B:1;
	UCHAR G:1;
	UCHAR Base24_31;
} GDT;

typedef struct _SELECTOR
{
	USHORT RPL:2;
	USHORT TI:1;
	USHORT Index:13;
} SELECTOR;
#pragma pack()

void InitProcessorIdHelper()
{
	ULONG core=KeNumberProcessors;
	if (core>32)
		core=32;
	for (ULONG i=0;i<core;i++)
	{
		KeSetSystemAffinityThread(1<<i);
		//KPCR的GDT字段也可以获得
		GDTR gdtr={0,0};
		_asm sgdt gdtr;
		GDT* gdt=(GDT*)gdtr.Base;
		DbgPrint("core%d GDT at:0x%08X\n",i,gdtr.Base);
		//14位到19位存储CPU核心号，limit可用上限从1MB变为16KB
		gdt[7].Limit0_15=((i&3)<<14)|gdt[7].Limit0_15;
		gdt[7].Limit16_19=(i>>2)&0x0F;
	}
	KeRevertToUserAffinityThread();
}

void UninitProcessorIdHelper()
{
	ULONG core=KeNumberProcessors;
	if (core>32)
		core=32;
	for (ULONG i=0;i<core;i++)
	{
		KeSetSystemAffinityThread(1<<i);
		GDTR gdtr={0,0};
		_asm sgdt gdtr;
		GDT* gdt=(GDT*)gdtr.Base;
		gdt[7].Limit0_15=gdt[7].Limit0_15&0x3FFF;
		gdt[7].Limit16_19=0;
	}
	KeRevertToUserAffinityThread();
}
