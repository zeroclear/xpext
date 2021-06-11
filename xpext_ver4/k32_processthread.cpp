
#include "common.h"

DWORD WINAPI K32GetThreadId(HANDLE Thread)
{
	THREAD_BASIC_INFORMATION ThreadInformation;
	NTSTATUS Result=NtQueryInformationThread(Thread,ThreadBasicInformation,&ThreadInformation,sizeof(ThreadInformation),NULL);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return 0;
	}
	return (DWORD)ThreadInformation.ClientId.UniqueThread;
}

DWORD WINAPI K32GetProcessId(HANDLE Process)
{
	PROCESS_BASIC_INFORMATION ProcessInformation;
	NTSTATUS Result=NtQueryInformationProcess(Process,ProcessBasicInformation,&ProcessInformation,sizeof(ProcessInformation),NULL);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return 0;
	}
	return (DWORD)ProcessInformation.UniqueProcessId;
}

DWORD WINAPI K32GetProcessIdOfThread(HANDLE Thread)
{
	THREAD_BASIC_INFORMATION ThreadInformation;
	NTSTATUS Result=NtQueryInformationThread(Thread,ThreadBasicInformation,&ThreadInformation,sizeof(ThreadInformation),NULL);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return 0;
	}
	return (DWORD)ThreadInformation.ClientId.UniqueProcess;
}


/*
GetModuleFileNameEx
LDR_DATA_TABLE_ENTRY::FullDllName
"C:\Documents and Settings\Administrator\桌面\fullpath\Debug\fullpath.exe"

GetProcessImageFileName
NtQueryInformationProcess(ProcessImageFileName)
"\Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\fullpath\Debug\fullpath.exe"

QueryFullProcessImageName(0)
NtQueryInformationProcess(ProcessImageFileNameWin32)
"C:\Documents and Settings\Administrator\桌面\fullpath\Debug\fullpath.exe"

QueryFullProcessImageName(PROCESS_NAME_NATIVE)
NtQueryInformationProcess(ProcessImageFileName)
"\Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\fullpath\Debug\fullpath.exe"

结论：
QueryFullProcessImageName(0)等价于GetModuleFileNameEx
QueryFullProcessImageName(PROCESS_NAME_NATIVE)等价于GetProcessImageFileName

NtQueryInformationProcess(ProcessImageFileNameWin32)（Win7才有）
"C:\Documents and Settings\Administrator\桌面\fullpath\Debug\fullpath.exe"
NtQueryInformationProcess(ProcessImageFileName)（XP可使用）
"\Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\fullpath\Debug\fullpath.exe"

xpext当前采用Win7的逻辑，使用ProcessImageFileNameWin32，但是需要xpextk.sys的支持
其实使用GetModuleFileNameEx和GetProcessImageFileName更好些，毕竟内核patch容易造成系统不稳定
*/

BOOL WINAPI K32QueryFullProcessImageNameW(HANDLE hProcess,DWORD dwFlags,LPWSTR lpExeName,PDWORD lpdwSize)
{
	BOOL Result=FALSE;
	if (dwFlags& ~PROCESS_NAME_NATIVE)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_2);
		return Result;
	}
	//多此一举的重复检测
	dwFlags=dwFlags&PROCESS_NAME_NATIVE;
	if ((dwFlags-1) & dwFlags)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_2);
		return Result;
	}
	if (*lpdwSize>0x7FFFFFFB)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return Result;
	}
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
	DWORD AllocSize=*lpdwSize*sizeof(WCHAR)+sizeof(UNICODE_STRING);
	UNICODE_STRING* FullName=(UNICODE_STRING*)RtlAllocateHeap(HeapHandle,*BaseDllTag,AllocSize);
	if (FullName==NULL)
	{
		BaseSetLastNTError(STATUS_NO_MEMORY);
		return Result;
	}
	PROCESSINFOCLASS InfoClass=(dwFlags==PROCESS_NAME_NATIVE)?ProcessImageFileName:ProcessImageFileNameWin32;
	NTSTATUS Status=NtQueryInformationProcess(hProcess,InfoClass,FullName,AllocSize,NULL);
	if (Status==STATUS_INFO_LENGTH_MISMATCH)
		Status=STATUS_BUFFER_TOO_SMALL;
	if (!NT_SUCCESS(Status))
	{
		BaseSetLastNTError(Status);
	}
	else
	{
		//Win7和Win8原代码的谜之操作，先复制再检查长度，理论上会复制过度，造成缓冲区溢出
		//不过一旦遇到缓冲区大小不足，NtQueryInformationProcess会返回STATUS_INFO_LENGTH_MISMATCH
		//实际不会执行到这里，下面的判断又没什么用了
		memcpy(lpExeName,FullName->Buffer,FullName->Length);
		DWORD OutCharCount=FullName->Length/sizeof(WCHAR);
		if (OutCharCount>=*lpdwSize)
		{
			BaseSetLastNTError(STATUS_BUFFER_TOO_SMALL);
		}
		else
		{
			lpExeName[OutCharCount]='\0';
			*lpdwSize=OutCharCount;
			Result=TRUE;
		}
	}
	RtlFreeHeap(HeapHandle,0,FullName);
	return Result;
}

BOOL WINAPI K32QueryFullProcessImageNameA(HANDLE hProcess,DWORD dwFlags,LPSTR lpExeName,PDWORD lpdwSize)
{
	BOOL Result=FALSE;
	if (*lpdwSize>0x7FFFFFFF)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return Result;
	}
	DWORD dwSize=*lpdwSize;
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
	WCHAR* FullName=(WCHAR*)RtlAllocateHeap(HeapHandle,*BaseDllTag,dwSize*sizeof(WCHAR));
	if (FullName==NULL)
	{
		BaseSetLastNTError(STATUS_NO_MEMORY);
		return Result;
	}
	if (K32QueryFullProcessImageNameW(hProcess,dwFlags,FullName,&dwSize))
	{
		int cbConvert=WideCharToMultiByte(CP_ACP,0,FullName,dwSize+1,lpExeName,*lpdwSize,NULL,NULL);
		if (cbConvert!=0)
		{
			*lpdwSize=cbConvert-1;
			Result=TRUE;
		}
	}
	RtlFreeHeap(HeapHandle,0,FullName);
	return Result;
}

/*
ULONG NTAPI RtlGetThreadErrorMode()
{
	return NtCurrentTeb()->HardErrorMode;
}

NTSTATUS NTAPI RtlSetThreadErrorMode(ULONG NewNtMode,PULONG OldNtMode)
{
	if (NewNtMode&0xFFFFFF8F!=0)
		return STATUS_INVALID_PARAMETER_1;
	if (OldNtMode!=NULL)
		*OldNtMode=NtCurrentTeb()->HardErrorMode;
	NtCurrentTeb()->HardErrorMode=NewNtMode;
	return STATUS_SUCCESS;
}

虽然可以保存设置，但是没有效果
在UnhandledExceptionFilter和OpenFile会用到thread error mode
XP调用GetErrorMode，Win7调用RtlGetThreadErrorMode
除非能编辑kernel32.dll，导入xpext的函数，并修改这两处调用
*/

DWORD WINAPI K32GetThreadErrorMode()
{
	//DWORD NtErrorMode=RtlGetThreadErrorMode();
	DWORD NtErrorMode=NtCurrentTeb()->HardErrorMode;
	DWORD ErrorMode=0;
	if (NtErrorMode&0x10)
		ErrorMode=SEM_FAILCRITICALERRORS;
	if (NtErrorMode&0x20)
		ErrorMode|=SEM_NOGPFAULTERRORBOX;
	if (NtErrorMode&0x40)
		ErrorMode|=SEM_NOOPENFILEERRORBOX;
	return ErrorMode;
}

BOOL WINAPI K32SetThreadErrorMode(DWORD dwNewMode,LPDWORD lpOldMode)
{
	if ((dwNewMode&0xFFFF7FFC)!=0)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}
	DWORD TempMode=0;
	if (dwNewMode&SEM_FAILCRITICALERRORS)
		TempMode=0x10;
	if (dwNewMode&SEM_NOGPFAULTERRORBOX)
		TempMode|=0x20;
	if (dwNewMode&SEM_NOOPENFILEERRORBOX)
		TempMode|=0x40;

	/*NTSTATUS Result=RtlSetThreadErrorMode(TempMode,&dwNewMode);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}*/
	dwNewMode=NtCurrentTeb()->HardErrorMode;
	NtCurrentTeb()->HardErrorMode=TempMode;

	if (lpOldMode!=NULL)
	{
		TempMode=0;
		if (dwNewMode&0x10)
			TempMode=SEM_FAILCRITICALERRORS;
		if (dwNewMode&0x20)
			TempMode|=SEM_NOGPFAULTERRORBOX;
		if (dwNewMode&0x40)
			TempMode|=SEM_NOOPENFILEERRORBOX;
		*lpOldMode=TempMode;
	}
	return TRUE;
}

/*
ProcThreadAttribute这3个API仅在CreateProcess和CreateProcessAsUser传入EXTENDED_STARTUPINFO_PRESENT时有效
指定了此标记，将会应用STARTUPINFOEX结构体，其lpAttributeList字段为ThreadAttribute

InitializeProcThreadAttributeList(NULL, num, 0, &lpsize);
LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = malloc(lpsize);
InitializeProcThreadAttributeList(lpAttributeList, num, 0, &lpsize);
UpdateProcThreadAttribute(lpAttributeList, 0, Attribute, (PVOID)&Value, sizeof(Value), NULL, NULL);
UpdateProcThreadAttribute(lpAttributeList, 0, Attribute2, (PVOID)&Value2, sizeof(Value2), NULL, NULL);
STARTUPINFOEX six = {0, lpAttributeList};
six.lpAttributeList = lpAttributeList;
CreateProcess(... , EXTENDED_STARTUPINFO_PRESENT, (STARTUPINFO*)&six);
DeleteProcThreadAttributeList(lpAttributeList);
free(lpAttributeList);

CreateProcess在Win7调用NtCreateUserProcess，而在XP调用NtCreateProcessEx，因此XP不支持任何ProcThreadAttribute的请求
想实现这个机制，可能需要逆向重写CreateProcess和NtCreateUserProcess
*/

void WINAPI K32DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList)
{
	//原函数真的什么都没做
	return ;
}

typedef enum _PROC_THREAD_ATTRIBUTE_NUM_WIN8
{
	ProcThreadAttributeSecurityCapabilities=9,
	ProcThreadAttributeConsoleReference=10,
	ProcThreadAttributeProtectionLevel=11,
	ProcThreadAttributeMax_Win8=12,
} PROC_THREAD_ATTRIBUTE_NUM_WIN8;

#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES \
	ProcThreadAttributeValue (ProcThreadAttributeSecurityCapabilities, FALSE, TRUE, FALSE)
#endif

//https://github.com/microsoft/terminal/blob/fb597ed304ec6eef245405c9652e9b8a029b821f/src/server/winbasep.h
#define PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE \
	ProcThreadAttributeValue(ProcThreadAttributeConsoleReference, FALSE, TRUE, FALSE)

#ifndef PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL
#define PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL \
	ProcThreadAttributeValue (ProcThreadAttributeProtectionLevel, FALSE, TRUE, FALSE)
#endif

typedef struct _PROC_THREAD_ATTRIBUTE
{
	DWORD_PTR Attribute;
	SIZE_T cbSize;
	PVOID lpValue;
} PROC_THREAD_ATTRIBUTE;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
	DWORD AttributeFlags;
	DWORD MaxCount;
	DWORD Count;
	DWORD Pad4B;
	PROC_THREAD_ATTRIBUTE* ExtendedEntry;
	PROC_THREAD_ATTRIBUTE AttributeList[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST;

BOOL WINAPI K32InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,DWORD dwAttributeCount,DWORD dwFlags,PSIZE_T lpSize)
{
	if (dwFlags!=0)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_3);
		return FALSE;
	}
	if (dwAttributeCount>ProcThreadAttributeMax)	//Win7这个值为8，Win8则为12
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_2);
		return FALSE;
	}
	BOOL Result;
	SIZE_T RequiredSize=dwAttributeCount*sizeof(PROC_THREAD_ATTRIBUTE)+FIELD_OFFSET(PROC_THREAD_ATTRIBUTE_LIST,AttributeList);
	if (lpAttributeList==NULL || *lpSize<RequiredSize)
	{
		RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
		Result=FALSE;
	}
	else
	{
		lpAttributeList->AttributeFlags=0;
		lpAttributeList->ExtendedEntry=NULL;
		lpAttributeList->MaxCount=dwAttributeCount;
		lpAttributeList->Count=0;
		Result=TRUE;
	}
	*lpSize=RequiredSize;
	return Result;
}

//处理PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS时，若指定此标记，新ExtendedFlags会取代旧值
//否则将新旧两个ExtendedFlags合并；名字是我猜的
#define PROC_THREAD_ATTRIBUTE_FLAG_REPLACE_EXTENDEDFLAGS	1

/*
MSDN上公开的用法
UpdateProcThreadAttribute(lpAttributeList, 0, Attribute, (PVOID)&Value, sizeof(Value), NULL, NULL);
其中dwFlags和lpPreviousValue必须为0

隐藏的微软内部用法
UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS, 
	(PVOID)&dwExtendedFlags, sizeof(DWORD), (PVOID)&dwPreviousExtendedFlags, NULL);
其中dwFlags可以为0或PROC_THREAD_ATTRIBUTE_FLAG_REPLACE_EXTENDEDFLAGS，lpPreviousValue可以为NULL

未知的用法
当Attribute没有PROC_THREAD_ATTRIBUTE_INPUT时，lpReturnSize可以返回什么数据
*/
BOOL WINAPI K32UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,DWORD dwFlags,
	DWORD_PTR Attribute,PVOID lpValue,SIZE_T cbSize,PVOID lpPreviousValue,PSIZE_T lpReturnSize)
{
	if (dwFlags&(~PROC_THREAD_ATTRIBUTE_FLAG_REPLACE_EXTENDEDFLAGS))
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_2);
		return FALSE;
	}

	DWORD AttributeFlag=1<<(Attribute&PROC_THREAD_ATTRIBUTE_NUMBER);
	//只有PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS才带有PROC_THREAD_ATTRIBUTE_ADDITIVE
	if ((Attribute&PROC_THREAD_ATTRIBUTE_ADDITIVE)==0) 
	{
		if (lpAttributeList->Count==lpAttributeList->MaxCount)
		{
			BaseSetLastNTError(STATUS_UNSUCCESSFUL);
			return FALSE;
		}
		if (lpAttributeList->AttributeFlags&AttributeFlag)
		{
			BaseSetLastNTError(STATUS_OBJECT_NAME_EXISTS);
			return FALSE;
		}
		if (lpPreviousValue!=NULL)
		{
			BaseSetLastNTError(STATUS_INVALID_PARAMETER_6);
			return FALSE;
		}
		if (dwFlags&PROC_THREAD_ATTRIBUTE_FLAG_REPLACE_EXTENDEDFLAGS)
		{
			BaseSetLastNTError(STATUS_INVALID_PARAMETER_2);
			return FALSE;
		}
	}
	//已知的所有Attribute都带有PROC_THREAD_ATTRIBUTE_INPUT
	//也许微软内部的代码会利用lpReturnSize输出点什么
	if ((Attribute&PROC_THREAD_ATTRIBUTE_INPUT) && lpReturnSize!=NULL)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_7);
		return FALSE;
	}

	PROC_THREAD_ATTRIBUTE* Entry=(PROC_THREAD_ATTRIBUTE*)((BYTE*)lpAttributeList+
		lpAttributeList->Count*sizeof(PROC_THREAD_ATTRIBUTE)+FIELD_OFFSET(PROC_THREAD_ATTRIBUTE_LIST,AttributeList));

	switch (Attribute)	//Attribute = (Number | Thread | Input | Additive)
	{
	case PROC_THREAD_ATTRIBUTE_PARENT_PROCESS:	//0, 0, 0x20000, 0
		if (cbSize!=sizeof(HANDLE))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_HANDLE_LIST:		//2, 0, 0x20000, 0
		if (cbSize==0 || (cbSize&3))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_PREFERRED_NODE:	//4, 0, 0x20000, 0
		if (cbSize!=sizeof(USHORT))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY:	//7, 0, 0x20000, 0
		if (cbSize!=sizeof(DWORD) && cbSize!=sizeof(DWORD64))	//Win8开始允许DWORD64
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY:	//3, 0x10000, 0x20000, 0
		if (cbSize!=sizeof(GROUP_AFFINITY))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR:	//5, 0x10000, 0x20000, 0
		if (cbSize!=sizeof(PROCESSOR_NUMBER))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	//此标记及对应的函数CreateUmsThreadContext仅在64位系统才有，Win7和Win8都是如此
	//注意，在64位下，sizeof(UMS_CREATE_THREAD_ATTRIBUTES)为24，而在32位下为12
	case PROC_THREAD_ATTRIBUTE_UMS_THREAD:		//6, 0x10000, 0x20000, 0
		if (cbSize!=sizeof(UMS_CREATE_THREAD_ATTRIBUTES))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS:	//1, 0, 0x20000, 0x40000
		if (cbSize!=sizeof(DWORD))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	//下面3个仅Win8以上支持
	case PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES:	//9, 0, 0x20000, 0
		if (cbSize!=16)	//sizeof(SECURITY_CAPABILITIES)，32位是16，64位是24
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE:		//10, 0, 0x20000, 0
		if (cbSize!=sizeof(HANDLE))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	case PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL:		//11, 0, 0x20000, 0
		if (cbSize!=sizeof(DWORD))
		{
			BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
			return FALSE;
		}
		break;
	default:
		BaseSetLastNTError(STATUS_NOT_SUPPORTED);
		return FALSE;
		break;
	}
	//原代码中这段代码和检查大小放在一起
	if (Attribute==PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS)
	{
		DWORD dwPreviousExtendedFlags;
		//没有ExtendedEntry，就将当前Entry设为ExtendedEntry
		if (lpAttributeList->ExtendedEntry==NULL)
		{
			lpAttributeList->ExtendedEntry=Entry;
			dwPreviousExtendedFlags=0;
		}
		else	//存在ExtendedEntry，取出之前的ExtendedEntry
		{
			Entry=lpAttributeList->ExtendedEntry;
			dwPreviousExtendedFlags=(DWORD)Entry->lpValue;
			AttributeFlag=0;
		}
		//取出新的ExtendedFlags，根据dwFlags决定是替换原值还是保留并添加新值
		DWORD dwExtendedFlags=*(DWORD*)lpValue;
		if (dwExtendedFlags&0xFFFFFFFC)	//Win8是0xFFFFFFF8；Win7可用2位，Win8可用4位
		{
			BaseSetLastNTError(STATUS_INVALID_PARAMETER);
			return FALSE;
		}
		if ((dwFlags&PROC_THREAD_ATTRIBUTE_FLAG_REPLACE_EXTENDEDFLAGS)==0)
			dwExtendedFlags=dwExtendedFlags|dwPreviousExtendedFlags;
		if (lpPreviousValue!=NULL)
			*(DWORD*)lpPreviousValue=dwPreviousExtendedFlags;
		//Win7原代码借用lpAttributeList存储lpValue，这里直接修改lpValue
		lpValue=(PVOID)dwExtendedFlags;
	}
	//如果是ExtendedFlags，仅更新lpValue，否则添加新项
	Entry->lpValue=lpValue;
	if (AttributeFlag!=0)
	{
		Entry->Attribute=Attribute;
		Entry->cbSize=cbSize;
		lpAttributeList->Count++;
		lpAttributeList->AttributeFlags|=AttributeFlag;
	}
	return TRUE;
}