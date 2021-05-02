
#include "common.h"

/*
现代操作系统拥有设备热插拔的能力（plug and play），可以在运行时动态配置硬件
其中就包括CPU核心的增加和移除，禁用和启用
因此，系统启动时检测到的最大CPU个数，并不一定是绝对的上限
也不一定是现存的CPU个数，也不一定是可用的CPU个数，这些都可能在运行时变化
Win7对此提供了一定的支持，预留一些空间，在CPU可用核心增加时更新ActiveCount
而XP完全不支持，它的CPU核心总数=最大数量=可用数量

可以通过设置CPU亲和性（affinity）让线程只运行在指定的核心上
Windows使用一个DWORD_PTR表示核心的掩码，如二进制00000010仅允许运行在第1个核心上
而00001101表示允许运行在核心0、核心2和核心3上，这是一种高效实用的方案
但在32位系统上DWORD_PTR仅能表示32个核心，64位系统上也只能表示64个核心
为了解决这一问题，引入了CPU组的设定，将64个CPU核心编成一组，以组号+索引确定CPU
32位的和Win7以前的操作系统不支持CPU组，默认使用第0组，最多32个或64个核心
就此衍生出一批能指定CPU组的API，但旧API仍然兼容，只能操作默认的第0组

SetThreadGroupAffinity 
GetThreadGroupAffinity 
GetProcessGroupAffinity 
GetLogicalProcessorInformation 
GetLogicalProcessorInformationEx 
NtQuerySystemInformationEx
...
*/

WORD WINAPI K32GetActiveProcessorGroupCount()
{
	return 1;
}

WORD WINAPI K32GetMaximumProcessorGroupCount()
{
	return 1;
}

DWORD WINAPI K32GetActiveProcessorCount(WORD GroupNumber)
{
	if (GroupNumber!=0)
		return 0;
	SYSTEM_BASIC_INFORMATION SysInfo;
	NTSTATUS Result=NtQuerySystemInformation(SystemBasicInformation,&SysInfo,sizeof(SysInfo),NULL);
	if (!NT_SUCCESS(Result))
		return 0;
	DWORD CoreCount=0;
	for (int i=0;i<32;i++)
	{
		CoreCount+=(SysInfo.ActiveProcessorsAffinityMask&1);
		SysInfo.ActiveProcessorsAffinityMask>>=1;
	}
	return CoreCount;
}

DWORD WINAPI K32GetMaximumProcessorCount(WORD GroupNumber)
{
	if (GroupNumber!=0)
		return 0;
	SYSTEM_BASIC_INFORMATION SysInfo;
	NTSTATUS Result=NtQuerySystemInformation(SystemBasicInformation,&SysInfo,sizeof(SysInfo),NULL);
	if (!NT_SUCCESS(Result))
		return 0;
	return SysInfo.NumberOfProcessors;
}

//需要xpextk.sys支持
//编号被设置在GDT的第8项的14到19位上，在Ring3用lsl指令读取
//0x3B：索引=7，表=GDT，RPL=Ring3
_declspec(naked)
	DWORD WINAPI RtlGetCurrentProcessorNumber()
{
	_asm 
	{
		mov  ecx, 0x3B;
		lsl  eax, ecx;
		shr  eax, 0x0E;
		retn ;
	}
}

_declspec(naked)
	void WINAPI RtlGetCurrentProcessorNumberEx(PPROCESSOR_NUMBER ProcNumber)
{
	_asm
	{
		mov  edi, edi;
		push  ebp;
		mov  ebp, esp;
		mov  edx, dword ptr ss:[ebp+8];  //ProcNumber
		xor  eax, eax;
		mov  [edx], ax;  //ProcNumber->Group
		mov  ecx, 0x3B;
		lsl  eax, ecx;
		shr  eax, 0x0E;
		mov  [edx+2], al;  //ProcNumber->Number
		mov  byte ptr [edx+3], 0;  //ProcNumber->Reserved
		pop  ebp;
		retn 4;
	}
}




