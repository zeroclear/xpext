
#include "common.h"
#include <strsafe.h>
#pragma warning(disable:4482)

/*
typedef struct _KERNELBASE_GLOBAL_DATA
{
	UNICODE_STRING* BaseDefaultPath;
	SRWLOCK* BaseDefaultPathLock;
	UNICODE_STRING* BaseDllDirectory;
	RTL_CRITICAL_SECTION* BaseDllDirectoryLock;
	DWORD* BaseSearchPathMode;
	SRWLOCK* BaseSearchPathModeLock;
	PVOID RtlAnsiStringToUnicodeString_Stub;
	PVOID RtlUnicodeStringToAnsiString_Stub;
	PVOID BasepAnsiStringToUnicodeSize;
	PVOID BasepUnicodeStringToAnsiSize;
	PVOID BasepConvertWin32AttributeList;
	DWORD BaseDllTag;
	BYTE IsCalledFromServer;
	DWORD BaseStaticServerData_0;
	DWORD BaseStaticServerData_4;
	DWORD BaseStaticServerData_8;
	DWORD BaseStaticServerData_C;
} KERNELBASE_GLOBAL_DATA;

KERNELBASE_GLOBAL_DATA* KernelBaseGlobalData;

KERNELBASE_GLOBAL_DATA* WINAPI KernelBaseGetGlobalData()
{
	return KernelBaseGlobalData;
}
*/


//Win8.1_x32_6.3.9600.17415，InformationByHandleClass从14到20是Win8新增的
BOOL WINAPI K32GetFileInformationByHandleEx(HANDLE hFile,FILE_INFO_BY_HANDLE_CLASS InformationByHandleClass,LPVOID lpFileInformation,DWORD dwBufferSize)
{
	FILE_INFORMATION_CLASS FileInformationClass;
	DWORD dwRequireSize;
	BOOL IsDirectoryInfo=FALSE;
	BOOL IsRestartScan=FALSE;
	BOOL IsVolumeInfo=FALSE;	//原汇编代码借用了IoStatusBlock.Information的位置

	//Win7原汇编代码编译器把条件对半分开，分别用if查找，而Win8直接用了switch
	//当FILE_INFO_BY_HANDLE_CLASS为FileRemoteProtocolInfo、FileIdInfo，以及FileIdExtdDirectoryInfo和FileIdExtdDirectoryRestartInfo时
	//底层的FILE_INFORMATION_CLASS分别对应FileRemoteProtocolInformation、FileIdInformation和FileIdExtdDirectoryInformation
	//XP不支持编号41以上的功能，底层将返回STATUS_INVALID_INFO_CLASS，本函数转换成ERROR_INVALID_PARAMETER，返回FALSE
	switch (InformationByHandleClass)
	{
	case FILE_INFO_BY_HANDLE_CLASS::FileBasicInfo:
		FileInformationClass=FileBasicInformation;
		dwRequireSize=0x28;	//sizeof(FILE_BASIC_INFO)
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileStandardInfo:
		FileInformationClass=FileStandardInformation;
		dwRequireSize=0x18;	//sizeof(FILE_STANDARD_INFO)
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileNameInfo:
		FileInformationClass=FileNameInformation;
		dwRequireSize=0x8;	//sizeof(FILE_NAME_INFO)
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileStreamInfo:
		FileInformationClass=FileStreamInformation;
		dwRequireSize=0x20;	//sizeof(FILE_STREAM_INFO)
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileCompressionInfo:
		FileInformationClass=FileCompressionInformation;
		dwRequireSize=0x10;	//sizeof(FILE_COMPRESSION_INFO)
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileAttributeTagInfo:
		FileInformationClass=FileAttributeTagInformation;
		dwRequireSize=0x8;	//sizeof(FILE_ATTRIBUTE_TAG_INFO)
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileIdBothDirectoryInfo:
		FileInformationClass=FileIdBothDirectoryInformation;
		dwRequireSize=0x70;	//sizeof(FILE_ID_BOTH_DIR_INFO)
		IsDirectoryInfo=TRUE;
		IsRestartScan=FALSE;
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileIdBothDirectoryRestartInfo:
		FileInformationClass=FileIdBothDirectoryInformation;
		dwRequireSize=0x70;	//sizeof(FILE_ID_BOTH_DIR_INFO)
		IsDirectoryInfo=TRUE;
		IsRestartScan=TRUE;
		break;
	case FILE_INFO_BY_HANDLE_CLASS::FileRemoteProtocolInfo:
		FileInformationClass=(FILE_INFORMATION_CLASS)55;	//FileRemoteProtocolInformation
		dwRequireSize=0x74;	//sizeof(FILE_REMOTE_PROTOCOL_INFO)
		break;
	case 14:	//FILE_INFO_BY_HANDLE_CLASS::FileFullDirectoryInfo
		FileInformationClass=FileFullDirectoryInformation;
		dwRequireSize=0x48;	//sizeof(FILE_FULL_DIR_INFO)
		IsDirectoryInfo=TRUE;
		IsRestartScan=FALSE;
		break;
	case 15:	//FILE_INFO_BY_HANDLE_CLASS::FileFullDirectoryRestartInfo
		FileInformationClass=FileFullDirectoryInformation;
		dwRequireSize=0x48;	//sizeof(FILE_FULL_DIR_INFO)
		IsDirectoryInfo=TRUE;
		IsRestartScan=TRUE;
		break;
	case 16:	//FILE_INFO_BY_HANDLE_CLASS::FileStorageInfo
		dwRequireSize=0x16;	//sizeof(FILE_STORAGE_INFO)
		IsVolumeInfo=TRUE;
		break;
	case 17:	//FILE_INFO_BY_HANDLE_CLASS::FileAlignmentInfo
		FileInformationClass=FileAlignmentInformation;
		dwRequireSize=0x4;	//sizeof(FILE_ALIGNMENT_INFO)
		break;
	case 18:	//FILE_INFO_BY_HANDLE_CLASS::FileIdInfo
		FileInformationClass=(FILE_INFORMATION_CLASS)59;	//FileIdInformation
		dwRequireSize=0x18;	//sizeof(FILE_ID_INFO)
		break;
	case 19:	//FILE_INFO_BY_HANDLE_CLASS::FileIdExtdDirectoryInfo
		FileInformationClass=(FILE_INFORMATION_CLASS)60;	//FileIdExtdDirectoryInformation
		dwRequireSize=0x60;	//sizeof(FILE_ID_EXTD_DIR_INFO)
		IsDirectoryInfo=TRUE;
		IsRestartScan=FALSE;
		break;
	case 20:	//FILE_INFO_BY_HANDLE_CLASS::FileIdExtdDirectoryRestartInfo
		FileInformationClass=(FILE_INFORMATION_CLASS)60;	//FileIdExtdDirectoryInformation
		dwRequireSize=0x60;	//sizeof(FILE_ID_EXTD_DIR_INFO)
		IsDirectoryInfo=TRUE;
		IsRestartScan=TRUE;
		break;
	default:
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (dwBufferSize<dwRequireSize)
	{
		RtlSetLastWin32Error(ERROR_BAD_LENGTH);
		return FALSE;
	}

	NTSTATUS Result;
	IO_STATUS_BLOCK IoStatusBlock;
	if (IsVolumeInfo)
	{
		//FS_INFORMATION_CLASS::FileFsSectorSizeInformation
		//XP不支持编号10以上的FS_INFORMATION_CLASS，会返回STATUS_INVALID_INFO_CLASS，这里不进行实际调用
		//Result=NtQueryVolumeInformationFile(hFile,&IoStatusBlock,lpFileInformation,dwBufferSize,(FS_INFORMATION_CLASS)11);
		Result=STATUS_INVALID_INFO_CLASS;
	}
	else if (IsDirectoryInfo)
	{
		Result=NtQueryDirectoryFile(hFile,NULL,NULL,NULL,&IoStatusBlock,lpFileInformation,dwBufferSize,FileInformationClass,FALSE,NULL,IsRestartScan);
		if (Result==STATUS_PENDING)
		{
			Result=NtWaitForSingleObject(hFile,FALSE,NULL);
			if (!NT_SUCCESS(Result))
			{
				//先RtlNtStatusToDosError转换，再RtlSetLastWin32Error设置
				BaseSetLastNTError(Result);
				return FALSE;
			}
			Result=IoStatusBlock.Status;
		}
	}
	else
	{
		Result=NtQueryInformationFile(hFile,&IoStatusBlock,lpFileInformation,dwBufferSize,FileInformationClass);
	}

	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}
	if (InformationByHandleClass==FileStreamInfo && IoStatusBlock.Information==0)
	{
		BaseSetLastNTError(STATUS_END_OF_FILE);
		return FALSE;
	}
	return TRUE;
}

BOOL WINAPI Win32Rename(HANDLE hFile,LPVOID lpFileInformation,DWORD dwBufferSize)
{
	UNICODE_STRING NtPathName={0,0,0};
	if (dwBufferSize<16)
	{
		RtlSetLastWin32Error(ERROR_BAD_LENGTH);
		return FALSE;
	}

	NTSTATUS Result;
	FILE_RENAME_INFO* pInputRenameInfo=(FILE_RENAME_INFO*)lpFileInformation;
	//不知道以冒号（0x3A）开头的路径是什么格式，大多数用到的文件名都不是这种格式，会进行转换
	//但这个转换函数没有用到pInputRenameInfo->FileNameLength，完全凭借\0判断字符串结尾
	//在实际使用SetFileInformationByHandle时，因为wcslen返回的长度不包含\0，很可能失误少复制这个\0
	//结果是设置一个缓冲区溢出的文件名，而且返回成功
	//另一种情况更奇葩，既然文件名的长度是0个或半个WCHAR，为什么还要继续转换？
	//尽管占位的FILE_RENAME_INFO::FileName[0]总是存在，却无法保证它的值是\0，同样会溢出，并返回成功
	if (pInputRenameInfo->FileNameLength<sizeof(WCHAR) || pInputRenameInfo->FileName[0]!=L':')
	{
		//Win7用的是RtlDosPathNameToNtPathName_U_WithStatus，但XP没有，只能用RtlDosPathNameToNtPathName_U代替
		//两者的区别在于，Win7版本的返回值是NTSTATUS，而XP版本返回BOOLEAN，没法BaseSetLastNTError
		//函数底层实现比较复杂，不深入分析了，失败就将Status视为STATUS_INTERNAL_ERROR
		if (!RtlDosPathNameToNtPathName_U(pInputRenameInfo->FileName,&NtPathName,NULL,NULL))
		{
			BaseSetLastNTError(STATUS_INTERNAL_ERROR);
			return FALSE;
		}
	}
	else
	{
		NtPathName.MaximumLength=(USHORT)pInputRenameInfo->FileNameLength;
		NtPathName.Length=(USHORT)pInputRenameInfo->FileNameLength;
		NtPathName.Buffer=pInputRenameInfo->FileName;
	}

	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
	ULONG AllocSize=NtPathName.Length+sizeof(FILE_RENAME_INFO);
	FILE_RENAME_INFO* RenameBuffer=(FILE_RENAME_INFO*)RtlAllocateHeap(HeapHandle,0,AllocSize);
	if (RenameBuffer==NULL)
	{
		BaseSetLastNTError(STATUS_NO_MEMORY);
		//如果没有调用转换函数，这里释放的是用户传入的参数，是个bug
		//下面的释放加了判断，才是正确的做法
		RtlFreeHeap(HeapHandle,0,NtPathName.Buffer);
		return FALSE;
	}

	memcpy(RenameBuffer->FileName,NtPathName.Buffer,NtPathName.Length);
	RenameBuffer->ReplaceIfExists=pInputRenameInfo->ReplaceIfExists;
	RenameBuffer->RootDirectory=pInputRenameInfo->RootDirectory;
	RenameBuffer->FileNameLength=NtPathName.Length;
	IO_STATUS_BLOCK IoStatusBlock;
	Result=NtSetInformationFile(hFile,&IoStatusBlock,RenameBuffer,AllocSize,FileRenameInformation);

	if (NtPathName.Buffer!=pInputRenameInfo->FileName)
		RtlFreeHeap(HeapHandle,0,NtPathName.Buffer);
	RtlFreeHeap(HeapHandle,0,RenameBuffer);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}
	return TRUE;
}

BOOL WINAPI K32SetFileInformationByHandle(HANDLE hFile,FILE_INFO_BY_HANDLE_CLASS InformationByHandleClass,LPVOID lpFileInformation,DWORD dwBufferSize)
{
	FILE_INFORMATION_CLASS FileInformationClass;
	DWORD dwRequireSize;
	if (InformationByHandleClass==FileBasicInfo)
	{
		FileInformationClass=FileBasicInformation;
		dwRequireSize=0x28;	//sizeof(FILE_BASIC_INFO)
	}
	else if (InformationByHandleClass==FileRenameInfo)
	{
		return Win32Rename(hFile,lpFileInformation,dwBufferSize);
	}
	else if (InformationByHandleClass==FileDispositionInfo)
	{
		FileInformationClass=FileDispositionInformation;
		dwRequireSize=1;	//sizeof(FILE_DISPOSITION_INFO)
	}
	else if (InformationByHandleClass==FileAllocationInfo)
	{
		FileInformationClass=FileAllocationInformation;
		dwRequireSize=8;	//sizeof(FILE_ALLOCATION_INFO)
	}
	else if (InformationByHandleClass==FileEndOfFileInfo)
	{
		FileInformationClass=FileEndOfFileInformation;
		dwRequireSize=8;	//sizeof(FILE_END_OF_FILE_INFO)
	}
	else if (InformationByHandleClass==FileIoPriorityHintInfo)
	{
		FileInformationClass=(FILE_INFORMATION_CLASS)43;	//FileIoPriorityHintInformation
		dwRequireSize=4;	//sizeof(FILE_IO_PRIORITY_HINT_INFO)
		//这里没检查dwBufferSize就直接用了lpFileInformation，可能会出现内存访问错误
		if (*(DWORD*)lpFileInformation>=3)	//FILE_IO_PRIORITY_HINT_INFO::PriorityHint>=PRIORITY_HINT::MaximumIoPriorityHintType
		{
			RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
	}
	else
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (dwBufferSize<dwRequireSize)
	{
		RtlSetLastWin32Error(ERROR_BAD_LENGTH);
		return FALSE;
	}

	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Result=NtSetInformationFile(hFile,&IoStatusBlock,lpFileInformation,dwBufferSize,FileInformationClass);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		return FALSE;
	}
	return TRUE;
}

//输入：C:\1.txt
//输出：\Device\HarddiskVolume1\1.txt
BOOL WINAPI BasepGetObjectNTName(HANDLE hFile,LPWSTR* pszNameOut)
{
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

	NTSTATUS Result;
	UNICODE_STRING* NameBuffer=NULL;
	int AllocSize=MAX_PATH*sizeof(WCHAR)+sizeof(UNICODE_STRING);	//528
	do 
	{
		if (NameBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,NameBuffer);
		NameBuffer=(UNICODE_STRING*)RtlAllocateHeap(HeapHandle,*BaseDllTag,AllocSize);
		if (NameBuffer==NULL)
		{
			Result=STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		ULONG ReturnLength;
		Result=NtQueryObject(hFile,ObjectNameInformation,NameBuffer,AllocSize,&ReturnLength);
		AllocSize=ReturnLength;
	} while (Result==STATUS_BUFFER_OVERFLOW);

	if (NT_SUCCESS(Result))
	{
		int NameCharNum=NameBuffer->Length/sizeof(WCHAR);
		memmove(NameBuffer,NameBuffer->Buffer,NameBuffer->Length);
		*pszNameOut=(WCHAR*)NameBuffer;
		(*pszNameOut)[NameCharNum]='\0';
		return TRUE;
	}
	else
	{
		BaseSetLastNTError(Result);
		if (NameBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,NameBuffer);
		return FALSE;
	}
}

//输入：C:\1.txt
//输出：\1.txt
//这个函数支持FileNameInformation和FileNormalizedNameInformation，但XP下FileNormalizedNameInformation不能用
BOOL WINAPI BasepGetFileNameInformation(HANDLE hFile,FILE_INFORMATION_CLASS FileInformationClass,LPWSTR* pszNameOut)
{
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

	NTSTATUS Result;
	FILE_NAME_INFORMATION* NameBuffer=NULL;
	int AllocSize=MAX_PATH*sizeof(WCHAR)+sizeof(FILE_NAME_INFORMATION);	//528
	do 
	{
		if (NameBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,NameBuffer);
		NameBuffer=(FILE_NAME_INFORMATION*)RtlAllocateHeap(HeapHandle,*BaseDllTag,AllocSize);
		if (NameBuffer==NULL)
		{
			Result=STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		IO_STATUS_BLOCK IoStatusBlock;
		Result=NtQueryInformationFile(hFile,&IoStatusBlock,NameBuffer,AllocSize,FileInformationClass);
		AllocSize=NameBuffer->FileNameLength+sizeof(FILE_NAME_INFORMATION);
	} while (Result==STATUS_BUFFER_OVERFLOW);

	if (NT_SUCCESS(Result))
	{
		int NameCharNum=NameBuffer->FileNameLength/sizeof(WCHAR);
		memmove(NameBuffer,NameBuffer->FileName,NameBuffer->FileNameLength);
		*pszNameOut=(WCHAR*)NameBuffer;
		(*pszNameOut)[NameCharNum]='\0';
		return TRUE;
	}
	else
	{
		BaseSetLastNTError(Result);
		if (NameBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,NameBuffer);
		return FALSE;
	}
}

#define MOUNTMGR_DOS_DEVICE_NAME                    L"\\\\.\\MountPointManager"
#define MOUNTMGRCONTROLTYPE                         0x0000006D // 'm'
#define IOCTL_MOUNTMGR_QUERY_POINTS                 CTL_CODE(MOUNTMGRCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)	//0x6D0008
#define IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH        CTL_CODE(MOUNTMGRCONTROLTYPE, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)	//0x6D0030

//IOCTL_MOUNTMGR_QUERY_POINTS Input
typedef struct _MOUNTMGR_MOUNT_POINT {
	ULONG   SymbolicLinkNameOffset;
	USHORT  SymbolicLinkNameLength;
	ULONG   UniqueIdOffset;
	USHORT  UniqueIdLength;
	ULONG   DeviceNameOffset;
	USHORT  DeviceNameLength;
} MOUNTMGR_MOUNT_POINT, *PMOUNTMGR_MOUNT_POINT;

//IOCTL_MOUNTMGR_QUERY_POINTS Output
typedef struct _MOUNTMGR_MOUNT_POINTS {
	ULONG                   Size;
	ULONG                   NumberOfMountPoints;
	MOUNTMGR_MOUNT_POINT    MountPoints[1];
} MOUNTMGR_MOUNT_POINTS, *PMOUNTMGR_MOUNT_POINTS;

//IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH Input
typedef struct _MOUNTMGR_TARGET_NAME {
	USHORT  DeviceNameLength;
	WCHAR   DeviceName[1];
} MOUNTMGR_TARGET_NAME, *PMOUNTMGR_TARGET_NAME;

//IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH Output
typedef struct _MOUNTMGR_VOLUME_PATHS {
	ULONG   MultiSzLength;
	WCHAR   MultiSz[1];
} MOUNTMGR_VOLUME_PATHS, *PMOUNTMGR_VOLUME_PATHS;

#define MOUNTMGR_IS_VOLUME_NAME(s) (                                          \
	((s)->Length == 96 || ((s)->Length == 98 && (s)->Buffer[48] == '\\')) && \
	(s)->Buffer[0] == '\\' &&                                                \
	((s)->Buffer[1] == '?' || (s)->Buffer[1] == '\\') &&                     \
	(s)->Buffer[2] == '?' &&                                                 \
	(s)->Buffer[3] == '\\' &&                                                \
	(s)->Buffer[4] == 'V' &&                                                 \
	(s)->Buffer[5] == 'o' &&                                                 \
	(s)->Buffer[6] == 'l' &&                                                 \
	(s)->Buffer[7] == 'u' &&                                                 \
	(s)->Buffer[8] == 'm' &&                                                 \
	(s)->Buffer[9] == 'e' &&                                                 \
	(s)->Buffer[10] == '{' &&                                                \
	(s)->Buffer[19] == '-' &&                                                \
	(s)->Buffer[24] == '-' &&                                                \
	(s)->Buffer[29] == '-' &&                                                \
	(s)->Buffer[34] == '-' &&                                                \
	(s)->Buffer[47] == '}'                                                   \
	)

//输入：\Device\HarddiskVolume1
//输出：\\?\C:
BOOL WINAPI BasepGetVolumeDosLetterNameFromNTName(WCHAR* NTName,LPWSTR* pszNameOut)
{
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

	WCHAR* NameOutBuffer=NULL;
	if (_wcsnicmp(NTName,L"\\Device\\MUP",11)==0)
	{
		NameOutBuffer=(WCHAR*)RtlAllocateHeap(HeapHandle,*BaseDllTag,8*sizeof(WCHAR));
		*pszNameOut=NameOutBuffer;
		if (NameOutBuffer==NULL)
		{
			RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
			return FALSE;
		}
		memcpy(NameOutBuffer,L"\\\\?\\UNC",7*sizeof(WCHAR));
		NameOutBuffer[7]='\0';
		return TRUE;
	}

	BOOL Result;	//借用栈上的NTName，NTName放在edi
	HANDLE hDevice=CreateFileW(MOUNTMGR_DOS_DEVICE_NAME,0,FILE_SHARE_READ|FILE_SHARE_WRITE,
		NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hDevice==INVALID_HANDLE_VALUE)
		return FALSE;

	WCHAR* QueryOutBuffer=NULL;
	int QueryInSize=wcslen(NTName)*sizeof(WCHAR)+sizeof(MOUNTMGR_TARGET_NAME);
	MOUNTMGR_TARGET_NAME* QueryInBuffer=(MOUNTMGR_TARGET_NAME*)RtlAllocateHeap(HeapHandle,*BaseDllTag,QueryInSize);
	if (QueryInBuffer==NULL)
	{
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		Result=FALSE;
		goto _Cleanup;
	}

	QueryInBuffer->DeviceNameLength=wcslen(NTName)*sizeof(WCHAR);
	memcpy(QueryInBuffer->DeviceName,NTName,QueryInBuffer->DeviceNameLength);
	int QueryOutSize=MAX_PATH*sizeof(WCHAR)+sizeof(MOUNTMGR_VOLUME_PATHS)+4*sizeof(WCHAR);	//536

	while (1)
	{
		if (QueryOutBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
		QueryOutBuffer=(WCHAR*)RtlAllocateHeap(HeapHandle,*BaseDllTag,QueryOutSize);
		if (QueryOutBuffer==NULL)
		{
			RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
			Result=FALSE;
			goto _Cleanup;
		}

		DWORD BytesReturned;
		MOUNTMGR_VOLUME_PATHS* QueryOutBody=(MOUNTMGR_VOLUME_PATHS*)(QueryOutBuffer+4);	//前面留出4个WCHAR
		Result=DeviceIoControl(hDevice,IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH,QueryInBuffer,QueryInSize,
			QueryOutBody,QueryOutSize-4*sizeof(WCHAR),&BytesReturned,NULL);
		QueryOutSize=QueryOutBody->MultiSzLength+sizeof(MOUNTMGR_VOLUME_PATHS)+4*sizeof(WCHAR);
		if (Result==TRUE)
		{
			UNICODE_STRING Comparator;
			RtlInitUnicodeString(&Comparator,QueryOutBody->MultiSz);
			if (!MOUNTMGR_IS_VOLUME_NAME(&Comparator))
			{
				int BodyStrLen=QueryOutBody->MultiSzLength;	//下面的memmove会覆盖MultiSzLength
				*pszNameOut=QueryOutBuffer;
				memcpy(QueryOutBuffer,L"\\\\?\\",4*sizeof(WCHAR));
				memmove(QueryOutBody,QueryOutBody->MultiSz,BodyStrLen);
				QueryOutBuffer[4+BodyStrLen]=0;
				QueryOutBuffer=NULL;
			}
			else
			{
				RtlSetLastWin32Error(ERROR_PATH_NOT_FOUND);
				Result=FALSE;
			}
			goto _Cleanup;
		}

		if (GetLastError()!=ERROR_MORE_DATA)
		{
			RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
			QueryOutBuffer=NULL;
			goto _Cleanup;
		}
	}

_Cleanup:
	CloseHandle(hDevice);
	if (QueryOutBuffer!=NULL)
		RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
	if (QueryInBuffer!=NULL)
		RtlFreeHeap(HeapHandle,0,QueryInBuffer);
	return Result;
}

//输入：\Device\HarddiskVolume1
//输出：\\?\Volume{7a077e11-c496-11e8-9489-806d6172696f}
BOOL WINAPI BasepGetVolumeGUIDFromNTName(WCHAR* NTName,LPWSTR* pszNameOut)
{
	HANDLE hDevice=CreateFileW(MOUNTMGR_DOS_DEVICE_NAME,0,FILE_SHARE_READ|FILE_SHARE_WRITE,
		NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hDevice==INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL Result;
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
	int QueryInSize=wcslen(NTName)*sizeof(WCHAR)+sizeof(MOUNTMGR_MOUNT_POINT);
	MOUNTMGR_MOUNT_POINT* QueryInBuffer=(MOUNTMGR_MOUNT_POINT*)RtlAllocateHeap(HeapHandle,*BaseDllTag,QueryInSize);
	if (QueryInBuffer==NULL)
	{
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		Result=FALSE;
		goto _Cleanup;
	}
	memset(QueryInBuffer,0,sizeof(MOUNTMGR_MOUNT_POINT));
	QueryInBuffer->DeviceNameOffset=sizeof(MOUNTMGR_MOUNT_POINT);
	QueryInBuffer->DeviceNameLength=wcslen(NTName)*sizeof(WCHAR);

	memcpy((PVOID)((DWORD)QueryInBuffer+sizeof(MOUNTMGR_MOUNT_POINT)),NTName,QueryInBuffer->DeviceNameLength);

	MOUNTMGR_MOUNT_POINTS* QueryOutBuffer=NULL;		//注意这个结构后面是POINTS而不是POINT
	int QueryOutSize=640+sizeof(MOUNTMGR_MOUNT_POINTS);	//672
	while (1)
	{
		if (QueryOutBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
		QueryOutBuffer=(MOUNTMGR_MOUNT_POINTS*)RtlAllocateHeap(HeapHandle,*BaseDllTag,QueryOutSize);
		if (QueryOutBuffer==NULL)
		{
			RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
			Result=FALSE;
			goto _Cleanup;
		}

		DWORD dwCounter;
		Result=DeviceIoControl(hDevice,IOCTL_MOUNTMGR_QUERY_POINTS,QueryInBuffer,QueryInSize,QueryOutBuffer,QueryOutSize,&dwCounter,NULL);
		QueryOutSize=QueryOutBuffer->Size+sizeof(MOUNTMGR_MOUNT_POINTS);
		if (Result==TRUE)
		{
			dwCounter=0;
			for (MOUNTMGR_MOUNT_POINT* MountPoint=QueryOutBuffer->MountPoints;dwCounter<QueryOutBuffer->NumberOfMountPoints;dwCounter++,MountPoint++)
			{
				UNICODE_STRING Comparator;
				Comparator.Length=MountPoint->SymbolicLinkNameLength;
				Comparator.Buffer=(WCHAR*)((DWORD)QueryOutBuffer+MountPoint->SymbolicLinkNameOffset);
				if (MOUNTMGR_IS_VOLUME_NAME(&Comparator))
				{
					WCHAR* FindGuid=(WCHAR*)RtlAllocateHeap(HeapHandle,*BaseDllTag,Comparator.Length+sizeof(WCHAR));
					*pszNameOut=FindGuid;
					if (FindGuid==NULL)
					{
						RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
						Result=FALSE;
						goto _Cleanup;
					}
					memcpy(FindGuid,Comparator.Buffer,Comparator.Length);
					FindGuid[Comparator.Length/sizeof(WCHAR)]='\0';
					FindGuid[1]=L'\\';
					RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
					QueryOutBuffer=NULL;
					goto _Cleanup;
				}
			}
			RtlSetLastWin32Error(ERROR_NOT_SUPPORTED);
			goto _Cleanup;
		}

		if (GetLastError()!=ERROR_MORE_DATA)
		{
			RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
			QueryOutBuffer=NULL;
			goto _Cleanup;
		}
	}

_Cleanup:
	CloseHandle(hDevice);
	if (QueryInBuffer!=NULL)
		RtlFreeHeap(HeapHandle,0,QueryInBuffer);
	if (QueryOutBuffer!=NULL)
		RtlFreeHeap(HeapHandle,0,QueryOutBuffer);
	return Result;
}

DWORD WINAPI K32GetFinalPathNameByHandleW(HANDLE hFile,LPWSTR lpszFilePath,DWORD cchFilePath,DWORD dwFlags)
{
	DWORD Result=0;
	WCHAR* VolumeName=NULL;
	WCHAR* PathName=NULL;
	WCHAR* ConvertName13=NULL;
	int FuncId=0;

	if (hFile==INVALID_HANDLE_VALUE)
	{
		RtlSetLastWin32Error(ERROR_INVALID_HANDLE);
		return 0;
	}

	int FlagNum=0;
	if (dwFlags&VOLUME_NAME_GUID)
	{
		FuncId=1;
		FlagNum=1;
	}
	if (dwFlags&VOLUME_NAME_NT)
	{
		FuncId=2;
		FlagNum++;
	}
	if (dwFlags&VOLUME_NAME_NONE)
	{
		FuncId=0;
		FlagNum++;
	}
	if (FlagNum>1)
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (FlagNum==0)
	{
		FuncId=3;
	}

	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
	//刚获取的VolumeName=VolumeName+PathName
	if (!BasepGetObjectNTName(hFile,&VolumeName))
		goto _Cleanup;
	if (!BasepGetFileNameInformation(hFile,FileNameInformation,&PathName))
		goto _Cleanup;
	if (PathName[0]!='\\')
	{
		RtlSetLastWin32Error(ERROR_ACCESS_DENIED);
		goto _Cleanup;
	}
	if (wcslen(PathName)>=wcslen(VolumeName))
		RtlSetLastWin32Error(ERROR_BAD_PATHNAME);
	//截断FullName，丢弃Path部分，只剩Volume
	VolumeName[wcslen(VolumeName)-wcslen(PathName)]='\0';

	if (FuncId==1)
	{
		if (!BasepGetVolumeGUIDFromNTName(VolumeName,&ConvertName13))
		{
			if (GetLastError()!=ERROR_INVALID_FUNCTION)
				RtlSetLastWin32Error(ERROR_PATH_NOT_FOUND);
			goto _Cleanup;
		}
	}
	else if (FuncId==2)
	{
		ConvertName13=VolumeName;
		VolumeName=NULL;
	}
	else if (FuncId==3)
	{
		if (!BasepGetVolumeDosLetterNameFromNTName(VolumeName,&ConvertName13))
			goto _Cleanup;
	}
	else //if (FuncId==0)
	{
		ConvertName13=NULL;
	}

	if ((dwFlags&FILE_NAME_OPENED)==0)	//FILE_NAME_NORMALIZED
	{
		WCHAR* NormalName=NULL;
		WCHAR* ConvertName02=NULL;	//Win7借用栈上的dwFlags
		//由于XP不支持FileNormalizedNameInformation，这里会失败，ERROR_INVALID_PARAMETER
		if (!BasepGetFileNameInformation(hFile,FileNormalizedNameInformation,&NormalName))
		{
			if (GetLastError()!=ERROR_INVALID_PARAMETER && 
				GetLastError()!=ERROR_INVALID_LEVEL && 
				GetLastError()!=ERROR_NOT_SUPPORTED)
				goto _Cleanup;
			//之前Func0和Func2没有转换，这里补上转换
			int ConvertNameLen;
			if (FuncId==2 || FuncId==0)
			{
				if (!BasepGetVolumeDosLetterNameFromNTName((VolumeName!=NULL)?VolumeName:ConvertName13,&ConvertName02) &&
					GetLastError()==ERROR_NOT_ENOUGH_MEMORY)
					goto _Cleanup;
				if (ConvertName02!=NULL)
				{
					ConvertNameLen=wcslen(ConvertName02);
				}
				else
				{
					if (!BasepGetVolumeGUIDFromNTName((VolumeName!=NULL)?VolumeName:ConvertName13,&ConvertName02))
						goto _Cleanup;
					if (ConvertName02!=NULL)
						ConvertNameLen=wcslen(ConvertName02);
					else
						ConvertNameLen=wcslen(ConvertName13);
				}
			}
			else //if (FuncId==1 || FuncId==3)
			{
				ConvertNameLen=wcslen(ConvertName13);
			}

			DWORD LongPathInputLen=ConvertNameLen+wcslen(PathName)+cchFilePath+1;
			NormalName=(WCHAR*)RtlAllocateHeap(HeapHandle,*BaseDllTag,LongPathInputLen*sizeof(WCHAR));
			if (NormalName==NULL)
			{
				if (ConvertName02!=NULL)
					RtlFreeHeap(HeapHandle,0,ConvertName02);
				RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
				goto _Cleanup;
			}
			//使用GetLongPathNameW代替FileNormalizedNameInformation
			StringCchCopyW(NormalName,LongPathInputLen,(ConvertName02!=NULL)?ConvertName02:ConvertName13);
			StringCchCatW(NormalName,LongPathInputLen,PathName);
			DWORD LongPathOutputLen=GetLongPathNameW(NormalName,NormalName,LongPathInputLen);
			if (LongPathOutputLen==0)
			{
				RtlFreeHeap(HeapHandle,0,NormalName);
				if (ConvertName02!=NULL)
					RtlFreeHeap(HeapHandle,0,ConvertName02);
				goto _Cleanup;
			}
			//用户输入缓冲区长度不够，返回需要的缓冲区大小
			if (LongPathOutputLen>=LongPathInputLen)
			{
				if (ConvertName02!=NULL)
				{
					LongPathOutputLen=LongPathOutputLen-wcslen(ConvertName02);
					LongPathOutputLen=LongPathOutputLen+((ConvertName13!=NULL)?wcslen(ConvertName13):0);
					RtlFreeHeap(HeapHandle,0,ConvertName02);			
				}
				Result=LongPathOutputLen+1;
				RtlFreeHeap(HeapHandle,0,NormalName);
				RtlSetLastWin32Error(ERROR_SUCCESS);
				goto _Cleanup;
			}
			else
			{
				//删去盘符
				ConvertNameLen=(ConvertName02!=NULL)?wcslen(ConvertName02):wcslen(ConvertName13);
				memmove(NormalName,NormalName+ConvertNameLen,(wcslen(NormalName)-ConvertNameLen+1)*sizeof(WCHAR));
				if (ConvertName02!=NULL)
					RtlFreeHeap(HeapHandle,0,ConvertName02);
			}
		}
		RtlFreeHeap(HeapHandle,0,PathName);
		PathName=NormalName;
	}
	//FILE_NAME_OPENED 注意这里三目运算符优先级
	Result=wcslen(PathName)+((ConvertName13!=NULL)?wcslen(ConvertName13):0);
	if (cchFilePath<Result+1)
	{
		Result++;
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		goto _Cleanup;
	}
	lpszFilePath[0]='\0';
	if (ConvertName13!=NULL)
		StringCchCopyW(lpszFilePath,cchFilePath,ConvertName13);
	StringCchCatW(lpszFilePath,cchFilePath,PathName);
	goto _Cleanup;

_Cleanup:
	if (VolumeName!=NULL)
		RtlFreeHeap(HeapHandle,0,VolumeName);
	if (PathName!=NULL)
		RtlFreeHeap(HeapHandle,0,PathName);
	if (ConvertName13!=NULL)
		RtlFreeHeap(HeapHandle,0,ConvertName13);
	return Result;
}

DWORD WINAPI K32GetFinalPathNameByHandleA(HANDLE hFile,LPSTR lpszFilePath,DWORD cchFilePath,DWORD dwFlags)
{
	ANSI_STRING AnsiPathName;
	AnsiPathName.Buffer=NULL;
	WCHAR* UnicodeBuffer=NULL;
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

	int cchTryNum;
	int cchNeedNum=MAX_PATH*4;
	do 
	{
		cchTryNum=cchNeedNum;
		if (UnicodeBuffer!=NULL)
			RtlFreeHeap(HeapHandle,0,UnicodeBuffer);
		UnicodeBuffer=(WCHAR*)RtlAllocateHeap(HeapHandle,*BaseDllTag,cchTryNum*sizeof(WCHAR));
		if (UnicodeBuffer==NULL)
		{
			RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
			return 0;
		}
		cchNeedNum=K32GetFinalPathNameByHandleW(hFile,UnicodeBuffer,cchTryNum,dwFlags);
		if (cchNeedNum==0)
		{
			RtlFreeHeap(HeapHandle,0,UnicodeBuffer);
			return 0;
		}
	} while (cchNeedNum>cchTryNum);

	UNICODE_STRING UnicodePathName;
	UnicodePathName.Buffer=UnicodeBuffer;
	UnicodePathName.Length=wcslen(UnicodeBuffer)*sizeof(WCHAR);
	UnicodePathName.MaximumLength=cchNeedNum*sizeof(WCHAR);
	//KernelBaseGetGlobalData()->RtlUnicodeStringToAnsiString_Stub
	NTSTATUS Result=RtlUnicodeStringToAnsiString(&AnsiPathName,&UnicodePathName,TRUE);
	DWORD ReturnLength;
	if (!NT_SUCCESS(Result))
	{
		ReturnLength=0;
	}
	else
	{
		if (cchFilePath>=(DWORD)AnsiPathName.Length+1)
		{
			memcpy(lpszFilePath,AnsiPathName.Buffer,AnsiPathName.Length);
			lpszFilePath[AnsiPathName.Length]='\0';
		}
		ReturnLength=AnsiPathName.Length;
		RtlFreeAnsiString(&AnsiPathName);
	}
	RtlFreeHeap(HeapHandle,0,UnicodeBuffer);
	return ReturnLength;
}

WCHAR* WINAPI GetFullPath(LPCWSTR lpFileName)
{
	WCHAR* FilePart=NULL;
	WCHAR* FullPathName=NULL;
	int FullPathLength=GetFullPathNameW(lpFileName,0,NULL,&FilePart);
	if (FullPathLength!=0)
	{
		PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
		FullPathName=(WCHAR*)RtlAllocateHeap(HeapHandle,0,FullPathLength*sizeof(WCHAR));
		if (FullPathName==NULL)
		{
			RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
			return NULL;
		}
		FullPathLength=GetFullPathNameW(lpFileName,FullPathLength,FullPathName,&FilePart);
		if (FullPathLength==0)
		{
			RtlFreeHeap(HeapHandle,0,FullPathName);
			FullPathName=NULL;
		}
	}
	return FullPathName;
}

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define SYMLINK_FLAG_RELATIVE   1

//Define the create disposition values
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

//wdm.h有全部定义，这里只列出用到的
#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_OPEN_REPARSE_POINT                 0x00200000

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

//需要注意，尽管XP可以创建有效的SymbolicLink，但无法使用，可能是因为底层驱动不完善
//关于符号链接可参阅https://docs.microsoft.com/en-us/windows/win32/fileio/symbolic-links
BOOLEAN WINAPI K32CreateSymbolicLinkW(LPCWSTR lpSymlinkFileName,LPCWSTR lpTargetFileName,DWORD dwFlags)
{
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

	NTSTATUS Result;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;

	HANDLE FileHandle=INVALID_HANDLE_VALUE;
	UNICODE_STRING NtFileName={0,0,0};
	UNICODE_STRING NtSymbolName={0,0,0};
	//PVOID Privilege=NULL;
	WCHAR* FullPath=NULL;
	REPARSE_DATA_BUFFER* QueryInBuffer=NULL;
	ULONG QueryInSize;
	BOOLEAN IsRelative=FALSE;

	if (lpSymlinkFileName==NULL || lpTargetFileName==NULL)
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		goto _Cleanup;
	}
	//MSDN上说还有个SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE标记（Developer Mode可用）
	BOOL IsDirectory=dwFlags&SYMBOLIC_LINK_FLAG_DIRECTORY;
	if (IsDirectory!=dwFlags)
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		goto _Cleanup;
	}
	RtlSetLastWin32Error(ERROR_SUCCESS);

/*
	//XP没有SeCreateSymbolicLinkPrivilege，一定会失败
	ULONG Requset=35;
	Result=RtlAcquirePrivilege(&Requset,1,0,&Privilege);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		goto _Cleanup;
	}*/

	RTL_PATH_TYPE PathType=RtlDetermineDosPathNameType_U(lpTargetFileName);
	switch (PathType)
	{
	case RtlPathTypeUnknown:
	case RtlPathTypeRooted:
	case RtlPathTypeRelative:
		IsRelative=TRUE;
		NtFileName.Buffer=(PWSTR)lpTargetFileName;
		NtFileName.MaximumLength=wcslen(lpTargetFileName)*sizeof(WCHAR);
		NtFileName.Length=NtFileName.MaximumLength;
		break;
	case RtlPathTypeDriveRelative:
		FullPath=GetFullPath(lpTargetFileName);
		if (FullPath==NULL)
			goto _Cleanup;
		lpTargetFileName=FullPath;
		IsRelative=FALSE;
		break;
	case RtlPathTypeUncAbsolute:
	case RtlPathTypeDriveAbsolute:
	case RtlPathTypeLocalDevice:
	case RtlPathTypeRootLocalDevice:
		IsRelative=FALSE;
		break;
	default:
		//IsRelative=FALSE;
		break;
	}
	if (!IsRelative)
	{
		//Win7原代码这段放在default里
		if (!RtlDosPathNameToNtPathName_U(lpTargetFileName,&NtFileName,NULL,NULL))
		{
			RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
			goto _Cleanup;
		}
	}

	//FIELD_OFFSET(REPARSE_DATA_BUFFER,SymbolicLinkReparseBuffer.PathBuffer)=0x14
	QueryInSize=NtFileName.Length+wcslen(lpTargetFileName)*sizeof(WCHAR)+FIELD_OFFSET(REPARSE_DATA_BUFFER,SymbolicLinkReparseBuffer.PathBuffer);
	QueryInBuffer=(REPARSE_DATA_BUFFER*)RtlAllocateHeap(HeapHandle,*BaseDllTag,QueryInSize);
	if (QueryInBuffer==NULL)
	{
		RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
		goto _Cleanup;
	}

	//QueryInBuffer内存排布：
	//REPARSE_DATA_BUFFER header size=8
	//SymbolicLinkReparseBuffer size=10（计入PathBuffer）
	//lpTargetFileName
	//NtFileName.Buffer
	memset(QueryInBuffer,0,sizeof(REPARSE_DATA_BUFFER));
	if (IsRelative)
		QueryInBuffer->SymbolicLinkReparseBuffer.Flags|=SYMLINK_FLAG_RELATIVE;
	//#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)
	QueryInBuffer->ReparseDataLength=(USHORT)QueryInSize-FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer);
	QueryInBuffer->SymbolicLinkReparseBuffer.PrintNameOffset=0;
	QueryInBuffer->ReparseTag=IO_REPARSE_TAG_SYMLINK;
	QueryInBuffer->SymbolicLinkReparseBuffer.PrintNameLength=wcslen(lpTargetFileName)*sizeof(WCHAR);
	memcpy(QueryInBuffer->SymbolicLinkReparseBuffer.PathBuffer,lpTargetFileName,QueryInBuffer->SymbolicLinkReparseBuffer.PrintNameLength);
	QueryInBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset=QueryInBuffer->SymbolicLinkReparseBuffer.PrintNameLength;
	QueryInBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength=NtFileName.Length;
	memcpy((BYTE*)(QueryInBuffer->SymbolicLinkReparseBuffer.PathBuffer)+QueryInBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset,
		NtFileName.Buffer,NtFileName.Length);
	if (!RtlDosPathNameToNtPathName_U(lpSymlinkFileName,&NtSymbolName,NULL,NULL))
	{
		RtlSetLastWin32Error(ERROR_PATH_NOT_FOUND);
		goto _Cleanup;
	}
	
	InitializeObjectAttributes(&ObjectAttributes,&NtSymbolName,OBJ_CASE_INSENSITIVE,NULL,NULL);
	ULONG CreateOptions=IsDirectory?(FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE):
		(FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
	Result=NtCreateFile(&FileHandle,FILE_WRITE_ATTRIBUTES|DELETE|SYNCHRONIZE,&ObjectAttributes,&IoStatusBlock,NULL,
		FILE_ATTRIBUTE_NORMAL,0,FILE_CREATE,CreateOptions,NULL,0);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		goto _Cleanup;
	}
	Result=NtFsControlFile(FileHandle,NULL,NULL,NULL,&IoStatusBlock,FSCTL_SET_REPARSE_POINT,QueryInBuffer,QueryInSize,NULL,0);
	if (!NT_SUCCESS(Result))
	{
		BaseSetLastNTError(Result);
		//Win7原汇编借用栈上的dwFlags构造DispositionInformation
		FILE_DISPOSITION_INFORMATION DispositionInformation;
		DispositionInformation.DeleteFile=TRUE;
		NtSetInformationFile(FileHandle,&IoStatusBlock,&DispositionInformation,sizeof(DispositionInformation),FileDispositionInformation);
	}
_Cleanup:
	//XP不支持SeCreateSymbolicLinkPrivilege
	//if (Privilege!=NULL)
	//	RtlReleasePrivilege(Privilege);
	if (FullPath!=NULL)
		RtlFreeHeap(HeapHandle,0,FullPath);
	if (QueryInBuffer!=NULL)
		RtlFreeHeap(HeapHandle,0,QueryInBuffer);
	if (!IsRelative && NtFileName.Buffer!=NULL)
		RtlFreeHeap(HeapHandle,0,NtFileName.Buffer);
	if (NtSymbolName.Buffer!=NULL)
		RtlFreeHeap(HeapHandle,0,NtSymbolName.Buffer);
	if (FileHandle!=INVALID_HANDLE_VALUE)
		NtClose(FileHandle);
	return GetLastError()==ERROR_SUCCESS;
}

BOOL WINAPI Basep8BitStringToDynamicUnicodeString(UNICODE_STRING* OutUnicode,LPCSTR InputAnsi)
{
	ANSI_STRING AnsiString;
	NTSTATUS Result=RtlInitAnsiStringEx(&AnsiString,InputAnsi);
	if (!NT_SUCCESS(Result))
	{
		RtlSetLastWin32Error(ERROR_FILENAME_EXCED_RANGE);
		return FALSE;
	}
	//KernelBaseGetGlobalData()->RtlAnsiStringToUnicodeString;
	Result=RtlAnsiStringToUnicodeString(OutUnicode,&AnsiString,TRUE);
	if (!NT_SUCCESS(Result))
	{
		if (Result==STATUS_BUFFER_OVERFLOW)
			RtlSetLastWin32Error(ERROR_FILENAME_EXCED_RANGE);
		else
			BaseSetLastNTError(Result);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN WINAPI K32CreateSymbolicLinkA(LPCSTR lpSymlinkFileName,LPCSTR lpTargetFileName,DWORD dwFlags)
{
	UNICODE_STRING UnicodeSymlink;
	UNICODE_STRING UnicodeTarget;
	if (lpSymlinkFileName==NULL || lpTargetFileName==NULL)
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (!Basep8BitStringToDynamicUnicodeString(&UnicodeSymlink,lpSymlinkFileName))
		return FALSE;
	if (!Basep8BitStringToDynamicUnicodeString(&UnicodeTarget,lpTargetFileName))
	{
		RtlFreeUnicodeString(&UnicodeSymlink);
		return FALSE;
	}
	//尽管UNICODE_STRING限定了长度，RtlAnsiStringToUnicodeString仍会额外附加一个\0
	BOOLEAN Ret=K32CreateSymbolicLinkW(UnicodeSymlink.Buffer,UnicodeTarget.Buffer,dwFlags);
	RtlFreeUnicodeString(&UnicodeTarget);
	RtlFreeUnicodeString(&UnicodeSymlink);
	return Ret;
}