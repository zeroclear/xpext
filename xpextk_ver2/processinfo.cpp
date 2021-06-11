
//#include <ntddk.h>
#include <Ntifs.h>

//XP没有导出PsReferenceProcessFilePointer和MmGetFileObjectForSection
//这里使用XP的代码，Win7代码略有不同
_declspec(naked)
	PVOID __stdcall MmGetFileObjectForSection(PVOID SectionObject)
{
	_asm
	{
		mov     edi, edi;
		push    ebp;
		mov     ebp, esp;
		mov     eax, [ebp+8];	//SECTION_OBJECT* SectionObject;
		mov     eax, [eax+14h];	//SEGMENT_OBJECT* Segment;
		mov     eax, [eax];		//CONTROL_AREA* BaseAddress;
		mov     eax, [eax+24h];	//FILE_OBJECT* FilePointer;
		pop     ebp;
		retn    4;
	}
}

NTSTATUS
	NTAPI
	PsReferenceProcessFilePointer(
	PEPROCESS Process,
	FILE_OBJECT** OutFileObject
	)
{
	EX_RUNDOWN_REF* RundownProtect=(EX_RUNDOWN_REF*)((UCHAR*)Process+0x80);
	if (!ExAcquireRundownProtection(RundownProtect))
		return STATUS_UNSUCCESSFUL;
	PVOID SectionObject=*(PVOID*)((UCHAR*)Process+0x138);
	if (SectionObject==NULL)
	{
		ExReleaseRundownProtection(RundownProtect);
		return STATUS_UNSUCCESSFUL;
	}
	FILE_OBJECT* FileObject=(FILE_OBJECT*)MmGetFileObjectForSection(SectionObject);
	*OutFileObject=FileObject;
	ObfReferenceObject(FileObject);
	ExReleaseRundownProtection(RundownProtect);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueryInformationProcess43(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	)
{
	//ProcessImageFileName通过ObQueryNameString(FileObject)获得文件名
	//ProcessImageFileNameWin32通过IoQueryFileDosDeviceName(FileObject)获得文件名

	//PreviousMode在XP的偏移是0x140，在Win7的偏移是0x13A
	KPROCESSOR_MODE PreviousMode=*(KPROCESSOR_MODE*)((UCHAR*)KeGetCurrentThread()+0x140);
	PEPROCESS Process;
	//XP不支持PROCESS_QUERY_LIMITED_INFORMATION（0x1000），使用PROCESS_QUERY_INFORMATION（0x400）代替
	NTSTATUS Result=ObReferenceObjectByHandle(ProcessHandle,0x400,*PsProcessType,PreviousMode,(PVOID*)&Process,NULL);
	if (!NT_SUCCESS(Result))
		return Result;
	FILE_OBJECT* FileObject;
	Result=PsReferenceProcessFilePointer(Process,&FileObject);
	ObfDereferenceObject(Process);
	if (!NT_SUCCESS(Result))
		return Result;
	OBJECT_NAME_INFORMATION* FileName;
	Result=IoQueryFileDosDeviceName(FileObject,&FileName);
	ObfDereferenceObject(FileObject);
	if (!NT_SUCCESS(Result))
		return Result;
	//这里用MaximumLength而不是Length，可能是因为要复制结尾的\0
	ULONG RequireSize=FileName->Name.MaximumLength+sizeof(UNICODE_STRING);
	__try
	{
		if (ProcessInformationLength<RequireSize)
		{
			Result=STATUS_INFO_LENGTH_MISMATCH;
		}
		else
		{
			UNICODE_STRING* OutName=(UNICODE_STRING*)ProcessInformation;
			OutName->Length=FileName->Name.Length;
			OutName->MaximumLength=FileName->Name.MaximumLength;
			if (FileName->Name.MaximumLength>0)
			{
				OutName->Buffer=(WCHAR*)((UCHAR*)ProcessInformation+sizeof(UNICODE_STRING));
				memcpy(OutName->Buffer,FileName->Name.Buffer,FileName->Name.MaximumLength);
			}
			else
			{
				OutName->Buffer=NULL;
			}
		}
		if (ReturnLength!=NULL)
			*ReturnLength=RequireSize;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}
	ExFreePool(FileName);
	return Result;
}

typedef NTSTATUS (NTAPI* TypeNtQueryInformationProcess)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
TypeNtQueryInformationProcess NtQueryInformationProcessOld;

NTSTATUS NTAPI NtQueryInformationProcessExtend(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	)
{
	if (ProcessInformationClass!=ProcessImageFileNameWin32)
	{
		return NtQueryInformationProcessOld(ProcessHandle,ProcessInformationClass,
			ProcessInformation,ProcessInformationLength,ReturnLength);
	}
	else
	{
		return NtQueryInformationProcess43(ProcessHandle,ProcessInformationClass,
			ProcessInformation,ProcessInformationLength,ReturnLength);
	}
}

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PVOID* ServiceTable;	//函数地址表
	PULONG InvokeCountTable;
	ULONG ServiceLimit;		//函数的个数
	PUCHAR ParamSizeTable;	//栈中参数总长表
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

extern "C" KSERVICE_TABLE_DESCRIPTOR* KeServiceDescriptorTable;

void InitProcessInfoSsdtHook()
{
	NtQueryInformationProcessOld=(TypeNtQueryInformationProcess)KeServiceDescriptorTable[0].ServiceTable[154];
	KeServiceDescriptorTable[0].ServiceTable[154]=NtQueryInformationProcessExtend;
	DbgPrint("Original NtQueryInformationProcess:%08X\n",NtQueryInformationProcessOld);
}

void UninitProcessInfoSsdtHook()
{
	DbgPrint("Current NtQueryInformationProcess:%08X\n",KeServiceDescriptorTable[0].ServiceTable[154]);
	KeServiceDescriptorTable[0].ServiceTable[154]=NtQueryInformationProcessOld;
}