
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

typedef struct _STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PCHAR  Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG  Length;
	HANDLE  RootDirectory;
	PUNICODE_STRING  ObjectName;
	ULONG  Attributes;
	PVOID  SecurityDescriptor;
	PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _KSYSTEM_TIME {
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef LONG KPRIORITY;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,		// obsolete...delete
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	MaxSystemInfoClass_XP = 66,

	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformationObsolete = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	SystemThreadPriorityClientIdInformation = 82,
	SystemProcessorIdleCycleTimeInformation = 83,
	SystemVerifierCancellationInformation = 84,
	SystemProcessorPowerInformationEx = 85,
	SystemRefTraceInformation = 86,
	SystemSpecialPoolInformation = 87,
	SystemProcessIdInformation = 88,
	SystemErrorPortInformation = 89,
	SystemBootEnvironmentInformation = 90,
	SystemHypervisorInformation = 91,
	SystemVerifierInformationEx = 92,
	SystemTimeZoneInformation = 93,
	SystemImageFileExecutionOptionsInformation = 94,
	SystemCoverageInformation = 95,
	SystemPrefetchPatchInformation = 96,
	SystemVerifierFaultsInformation = 97,
	SystemSystemPartitionInformation = 98,
	SystemSystemDiskInformation = 99,
	SystemProcessorPerformanceDistribution = 100,
	SystemNumaProximityNodeInformation = 101,
	SystemDynamicTimeZoneInformation = 102,
	SystemCodeIntegrityInformation = 103,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString = 105,
	SystemVirtualAddressInformation = 106,
	SystemLogicalProcessorAndGroupInformation = 107,
	SystemProcessorCycleTimeInformation = 108,
	SystemStoreInformation = 109,
	SystemRegistryAppendString = 110,
	SystemAitSamplingValue = 111,
	SystemVhdBootInformation = 112,
	SystemCpuQuotaInformation = 113,
	SystemNativeBasicInformation = 114,
	SystemErrorPortTimeouts = 115,
	SystemLowPriorityIoInformation = 116,
	SystemBootEntropyInformation = 117,
	SystemVerifierCountersInformation = 118,
	SystemPagedPoolInformationEx = 119,
	SystemSystemPtesInformationEx = 120,
	SystemNodeDistanceInformation = 121,
	SystemAcpiAuditInformation = 122,
	SystemBasicPerformanceInformation = 123,
	MaxSystemInfoClass_W7 = 124,

	SystemQueryPerformanceCounterInformation = 124,
	SystemSessionBigPoolInformation = 125,
	SystemBootGraphicsInformation = 126,
	SystemScrubPhysicalMemoryInformation = 127,
	SystemBadPageInformation = 128,
	SystemProcessorProfileControlArea = 129,
	SystemCombinePhysicalMemoryInformation = 130,
	SystemEntropyInterruptTimingInformation = 131,
	SystemConsoleInformation = 132,
	SystemPlatformBinaryInformation = 133,
	SystemPolicyInformation = 134,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation = 136,
	SystemDeviceDataEnumerationInformation = 137,
	SystemMemoryTopologyInformation = 138,
	SystemMemoryChannelInformation = 139,
	SystemBootLogoInformation = 140,
	SystemProcessorPerformanceInformationEx = 141,
	SystemSpare0 = 142,
	SystemSecureBootPolicyInformation = 143,
	SystemPageFileInformationEx = 144,
	SystemSecureBootInformation = 145,
	SystemEntropyInterruptTimingRawInformation = 146,
	SystemPortableWorkspaceEfiLauncherInformation = 147,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemBootMetadataInformation = 150,
	SystemSoftRebootInformation = 151,
	SystemElamCertificateInformation = 152,
	SystemOfflineDumpConfigInformation = 153,
	SystemProcessorFeaturesInformation = 154,
	SystemRegistryReconciliationInformation = 155,
	SystemEdidInformation = 156,
	MaxSystemInfoClass_W81 = 157
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileMaximumInformation_XP = 41,

	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,		//FileAttributeCacheInformation
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileMaximumInformation_W7 = 56,

	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileMaximumInformation_W81 = 64
} FILE_INFORMATION_CLASS;

typedef struct _FILE_NAME_INFORMATION {
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef enum _FSINFOCLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsMaximumInformation_XP = 10,

	FileFsVolumeFlagsInformation = 10,
	FileFsMaximumInformation_W7 = 11,

	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMaximumInformation_W81 = 13
} FS_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdtInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,		// Note: this is kernel mode only
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	MaxProcessInfoClass_XP = 33,

	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessTlsInformation = 35,
	ProcessCookie = 36,
	ProcessImageInformation = 37,
	ProcessCycleTime = 38,
	ProcessPagePriority = 39,
	ProcessInstrumentationCallback = 40,
	ProcessThreadStackAllocation = 41,
	ProcessWorkingSetWatchEx = 42,
	ProcessImageFileNameWin32 = 43,
	ProcessImageFileMapping = 44,
	ProcessAffinityUpdateMode = 45,
	ProcessMemoryAllocationMode = 46,
	ProcessGroupInformation = 47,
	ProcessTokenVirtualizationEnabled = 48,
	ProcessOwnerInformation = 49,		//ProcessConsoleHostProcess
	ProcessWindowInformation = 50,
	MaxProcessInfoClass_W7 = 51,

	ProcessHandleInformation = 51,
	ProcessMitigationPolicy = 52,
	ProcessDynamicFunctionTableInformation = 53,
	ProcessHandleCheckingMode = 54,
	ProcessKeepAliveCount = 55,
	ProcessRevokeFileHandles = 56,
	ProcessWorkingSetControl = 57,
	ProcessHandleTable = 58,
	ProcessCheckStackExtentsMode = 59,
	ProcessCommandLineInformation = 60,
	ProcessProtectionInformation = 61,
	MaxProcessInfoClass_W81 = 62
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;	//PPEB
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation = 0,
	ThreadTimes = 1,
	ThreadPriority = 2,
	ThreadBasePriority = 3,
	ThreadAffinityMask = 4,
	ThreadImpersonationToken = 5,
	ThreadDescriptorTableEntry = 6,
	ThreadEnableAlignmentFaultFixup = 7,
	ThreadEventPair_Reusable = 8,
	ThreadQuerySetWin32StartAddress = 9,
	ThreadZeroTlsCell = 10,
	ThreadPerformanceCount = 11,
	ThreadAmILastThread = 12,
	ThreadIdealProcessor = 13,
	ThreadPriorityBoost = 14,
	ThreadSetTlsArrayAddress = 15,
	ThreadIsIoPending = 16,
	ThreadHideFromDebugger = 17,
	ThreadBreakOnTermination = 18,
	MaxThreadInfoClass_XP = 19,

	ThreadSwitchLegacyState = 19,
	ThreadIsTerminated = 20,
	ThreadLastSystemCall = 21,
	ThreadIoPriority = 22,
	ThreadCycleTime = 23,
	ThreadPagePriority = 24,
	ThreadActualBasePriority = 25,
	ThreadTebInformation = 26,
	ThreadCSwitchMon = 27,
	ThreadCSwitchPmu = 28,
	ThreadWow64Context = 29,
	ThreadGroupInformation = 30,
	ThreadUmsInformation = 31,
	ThreadCounterProfiling = 32,
	ThreadIdealProcessorEx = 33,
	MaxThreadInfoClass_W7 = 34,

	ThreadCpuAccountingInformation = 34,
	ThreadSuspendCount = 35,
	MaxThreadInfoClass_W81 = 36
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;	//PTEB
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _INITIAL_TEB {
	PVOID OldStackBase;
	PVOID OldStackLimit;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2,
	ObjectTypesInformation = 3,
	ObjectHandleFlagInformation = 4,
	MaxObjectInfoClass_XP = 5,

	ObjectSessionInformation = 5,
	MaxObjectInfoClass_W7 = 6,
	MaxObjectInfoClass_W81 = 6
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS  Status;
		PVOID  Pointer;
	};
	ULONG_PTR  Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef
	VOID
	(NTAPI *PIO_APC_ROUTINE) (
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);

typedef struct _RTL_RELATIVE_NAME {
	STRING RelativeName;
	HANDLE ContainingDirectory;
	PUNICODE_STRING CurrentDirectory;	//Win7ÓÉRtlpReferenceCurrentDirectory·µ»Ø
} RTL_RELATIVE_NAME, *PRTL_RELATIVE_NAME;

typedef enum _RTL_PATH_TYPE {
	RtlPathTypeUnknown,         // 0
	RtlPathTypeUncAbsolute,     // 1
	RtlPathTypeDriveAbsolute,   // 2
	RtlPathTypeDriveRelative,   // 3
	RtlPathTypeRooted,          // 4
	RtlPathTypeRelative,        // 5
	RtlPathTypeLocalDevice,     // 6
	RtlPathTypeRootLocalDevice  // 7
} RTL_PATH_TYPE;

extern "C"
{
	NTSTATUS NTAPI
		NtClose(
		IN HANDLE  Handle
		);

	NTSTATUS NTAPI
		NtWaitForSingleObject(
		__in HANDLE  Handle,
		__in BOOLEAN  Alertable,
		__in_opt PLARGE_INTEGER  Timeout
		);

	NTSTATUS NTAPI
		NtCreateFile(
		__out PHANDLE  FileHandle,
		__in ACCESS_MASK  DesiredAccess,
		__in POBJECT_ATTRIBUTES  ObjectAttributes,
		__out PIO_STATUS_BLOCK  IoStatusBlock,
		__in_opt PLARGE_INTEGER  AllocationSize,
		__in ULONG  FileAttributes,
		__in ULONG  ShareAccess,
		__in ULONG  CreateDisposition,
		__in ULONG  CreateOptions,
		__in_opt PVOID  EaBuffer,
		__in ULONG  EaLength
		);

	NTSTATUS NTAPI
		NtQueryDirectoryFile(
		__in HANDLE  FileHandle,
		__in_opt HANDLE  Event,
		__in_opt PIO_APC_ROUTINE  ApcRoutine,
		__in_opt PVOID  ApcContext,
		__out PIO_STATUS_BLOCK  IoStatusBlock,
		__out PVOID  FileInformation,
		__in ULONG  Length,
		__in FILE_INFORMATION_CLASS  FileInformationClass,
		__in BOOLEAN  ReturnSingleEntry,
		__in_opt PUNICODE_STRING  FileName,
		__in BOOLEAN  RestartScan
		);

	NTSTATUS NTAPI
		NtQueryInformationFile(
		IN HANDLE  FileHandle,
		OUT PIO_STATUS_BLOCK  IoStatusBlock,
		OUT PVOID  FileInformation,
		IN ULONG  Length,
		IN FILE_INFORMATION_CLASS  FileInformationClass
		);

	NTSTATUS NTAPI
		NtSetInformationFile(
		IN HANDLE  FileHandle,
		OUT PIO_STATUS_BLOCK  IoStatusBlock,
		IN PVOID  FileInformation,
		IN ULONG  Length,
		IN FILE_INFORMATION_CLASS  FileInformationClass
		);

	NTSTATUS NTAPI
		NtFsControlFile(
		IN HANDLE  FileHandle,
		IN HANDLE  Event OPTIONAL,
		IN PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
		IN PVOID  ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK  IoStatusBlock,
		IN ULONG  FsControlCode,
		IN PVOID  InputBuffer OPTIONAL,
		IN ULONG  InputBufferLength,
		OUT PVOID  OutputBuffer OPTIONAL,
		IN ULONG  OutputBufferLength
		); 

	NTSTATUS NTAPI NtCreateKeyedEvent(OUT PHANDLE Handle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG Flags);
	NTSTATUS NTAPI NtOpenKeyedEvent(OUT PHANDLE Handle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS NTAPI NtWaitForKeyedEvent(IN HANDLE Handle, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER TimeoutMs);
	NTSTATUS NTAPI NtReleaseKeyedEvent(IN HANDLE Handle, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER TimeoutMs);

	NTSTATUS
		NTAPI
		NtOpenProcess (
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN PCLIENT_ID ClientId OPTIONAL
		);

	NTSTATUS NTAPI
		NtTerminateProcess(
		IN HANDLE  ProcessHandle,
		IN NTSTATUS  ExitStatus
		);

	NTSTATUS
		NTAPI
		NtOpenThread (
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN PCLIENT_ID ClientId OPTIONAL
		);

	NTSTATUS
		NTAPI
		NtTerminateThread(
		IN HANDLE ThreadHandle OPTIONAL,
		IN NTSTATUS ExitStatus
		);

	NTSTATUS
		NTAPI
		NtCreateProcessEx(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ParentProcess,
		IN ULONG Flags,
		IN HANDLE SectionHandle OPTIONAL,
		IN HANDLE DebugPort OPTIONAL,
		IN HANDLE ExceptionPort OPTIONAL,
		IN ULONG JobMemberLevel
		);

	NTSTATUS
		NTAPI
		NtCreateThread(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ProcessHandle,
		OUT PCLIENT_ID ClientId,
		IN PCONTEXT ThreadContext,
		IN PINITIAL_TEB InitialTeb,
		IN BOOLEAN CreateSuspended
		);

	NTSTATUS NTAPI NtSuspendThread(IN HANDLE ThreadHandle,OUT PULONG PreviousSuspendCount OPTIONAL);
	NTSTATUS NTAPI NtResumeThread(IN HANDLE ThreadHandle,OUT PULONG PreviousSuspendCount OPTIONAL);
	NTSTATUS NTAPI NtSuspendProcess(IN HANDLE ProcessHandle);
	NTSTATUS NTAPI NtResumeProcess(IN HANDLE ProcessHandle);

	NTSTATUS NTAPI
		NtQuerySystemInformation (
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	NTSTATUS
		NTAPI
		NtSetSystemInformation (
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		IN PVOID SystemInformation,
		IN ULONG SystemInformationLength
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtSetInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtQueryInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtSetInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN PVOID ThreadInformation,
		IN ULONG ThreadInformationLength
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtQueryObject(
		IN HANDLE Handle,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		OUT PVOID ObjectInformation,
		IN ULONG Length,
		OUT PULONG ReturnLength OPTIONAL
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtSetInformationObject(
		IN HANDLE Handle,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		IN PVOID ObjectInformation,
		IN ULONG ObjectInformationLength
		);

	BOOLEAN NTAPI
		RtlDosPathNameToNtPathName_U(
		PCWSTR DosFileName,
		PUNICODE_STRING NtFileName,
		PWSTR *FilePart OPTIONAL,
		PRTL_RELATIVE_NAME RelativeName OPTIONAL
		);

	RTL_PATH_TYPE NTAPI
		RtlDetermineDosPathNameType_U(
		IN PCWSTR DosFileName
		);

	PVOID NTAPI
		RtlAllocateHeap( 
		IN PVOID  HeapHandle,
		IN ULONG  Flags,
		IN SIZE_T  Size
		); 

	BOOLEAN NTAPI
		RtlFreeHeap( 
		IN PVOID  HeapHandle,
		IN ULONG  Flags,
		IN PVOID  HeapBase
		); 

	NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount);
	NTSTATUS NTAPI RtlEnterCriticalSection(PRTL_CRITICAL_SECTION lpCriticalSection);
	NTSTATUS NTAPI RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION lpCriticalSection);

	VOID NTAPI DbgBreakPoint();
	VOID NTAPI RtlRaiseException(PEXCEPTION_RECORD ExceptionRecord);
	VOID NTAPI RtlRaiseStatus(NTSTATUS Status);
	NTSTATUS NTAPI NtRaiseException(PEXCEPTION_RECORD ExceptionRecord,PCONTEXT Context,BOOL SearchFrames);
	NTSTATUS NTAPI NtRaiseHardError(NTSTATUS Status,DWORD NumberOfArguments,DWORD StringArgumentsMask,
		ULONG_PTR Arguments,DWORD MessageBoxType,LPDWORD MessageBoxResult);

	VOID NTAPI
		RtlInitUnicodeString(
		IN OUT PUNICODE_STRING  DestinationString,
		IN PCWSTR  SourceString
		);

	LONG NTAPI
		RtlCompareUnicodeString(
		IN PUNICODE_STRING  String1,
		IN PUNICODE_STRING  String2,
		IN BOOLEAN  CaseInSensitive
		);

	NTSTATUS NTAPI
		RtlAnsiStringToUnicodeString(
		IN OUT PUNICODE_STRING  DestinationString,
		IN PANSI_STRING  SourceString,
		IN BOOLEAN  AllocateDestinationString
		);

	NTSTATUS NTAPI
		RtlUnicodeStringToAnsiString(
		IN OUT PANSI_STRING  DestinationString,
		IN PUNICODE_STRING  SourceString,
		IN BOOLEAN  AllocateDestinationString
		);

	VOID NTAPI
		RtlFreeAnsiString(
		IN PANSI_STRING  AnsiString
		);

	VOID NTAPI
		RtlFreeUnicodeString(
		IN PUNICODE_STRING  UnicodeString
		);

	BOOLEAN NTAPI
		RtlEqualString(
		IN PSTRING  String1,
		IN PSTRING  String2,
		IN BOOLEAN  CaseInSensitive
		);

	BOOLEAN NTAPI
		RtlEqualUnicodeString(
		IN CONST UNICODE_STRING  *String1,
		IN CONST UNICODE_STRING  *String2,
		IN BOOLEAN  CaseInSensitive
		);

	ULONG DbgPrint(PCSTR Format, ... );
	ULONG DbgPrintEx(ULONG ComponentId,ULONG Level,PCSTR Format, ... );
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union 
	{
		LIST_ENTRY HashLinks;
		struct 
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union 
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/*
typedef struct _PEB_FREE_BLOCK
{
	_PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK;
*/

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;	//+0x000
	UCHAR ReadImageFileExecOptions;	//+0x001
	UCHAR BeingDebugged;	//+0x002
	UCHAR SpareBool;	//+0x003
	PVOID Mutant;	//+0x004
	PVOID ImageBaseAddress;	//+0x008
	PEB_LDR_DATA* Ldr;	//+0x00c
	PVOID ProcessParameters;	//+0x010 RTL_USER_PROCESS_PARAMETERS*
	PVOID SubSystemData;	//+0x014
	PVOID ProcessHeap;	//+0x018
	RTL_CRITICAL_SECTION* FastPebLock;	//+0x01c
	PVOID FastPebLockRoutine;	//+0x020
	PVOID FastPebUnlockRoutine;	//+0x024
	ULONG EnvironmentUpdateCount;	//+0x028
	PVOID KernelCallbackTable;	//+0x02c
	ULONG SystemReserved[1];	//+0x030
	ULONG AtlThunkSListPtr32;	//+0x034
	PVOID FreeList;	//+0x038 PEB_FREE_BLOCK*
	ULONG TlsExpansionCounter;	//+0x03c
	PVOID TlsBitmap;	//+0x040
	ULONG TlsBitmapBits[2];	//+0x044
	PVOID ReadOnlySharedMemoryBase;	//+0x04c
	PVOID ReadOnlySharedMemoryHeap;	//+0x050
	PVOID* ReadOnlyStaticServerData;	//+0x054
	PVOID AnsiCodePageData;	//+0x058
	PVOID OemCodePageData;	//+0x05c
	PVOID UnicodeCaseTableData;	//+0x060
	ULONG NumberOfProcessors;	//+0x064
	ULONG NtGlobalFlag;	//+0x068
	LARGE_INTEGER CriticalSectionTimeout;	//+0x070
	ULONG HeapSegmentReserve;	//+0x078
	ULONG HeapSegmentCommit;	//+0x07c
	ULONG HeapDeCommitTotalFreeThreshold;	//+0x080
	ULONG HeapDeCommitFreeBlockThreshold;	//+0x084
	ULONG NumberOfHeaps;	//+0x088
	ULONG MaximumNumberOfHeaps;	//+0x08c
	PVOID* ProcessHeaps;	//+0x090
	PVOID GdiSharedHandleTable;	//+0x094
	PVOID ProcessStarterHelper;	//+0x098
	ULONG GdiDCAttributeList;	//+0x09c
	PVOID LoaderLock;	//+0x0a0
	ULONG OSMajorVersion;	//+0x0a4
	ULONG OSMinorVersion;	//+0x0a8
	USHORT OSBuildNumber;	//+0x0ac
	USHORT OSCSDVersion;	//+0x0ae
	ULONG OSPlatformId;	//+0x0b0
	ULONG ImageSubsystem;	//+0x0b4
	ULONG ImageSubsystemMajorVersion;	//+0x0b8
	ULONG ImageSubsystemMinorVersion;	//+0x0bc
	ULONG ImageProcessAffinityMask;	//+0x0c0
	ULONG GdiHandleBuffer[34];	//+0x0c4
	PVOID PostProcessInitRoutine;	//+0x14c
	PVOID TlsExpansionBitmap;	//+0x150
	ULONG TlsExpansionBitmapBits[32];	//+0x154
	ULONG SessionId;	//+0x1d4
	ULARGE_INTEGER AppCompatFlags;	//+0x1d8
	ULARGE_INTEGER AppCompatFlagsUser;	//+0x1e0
	PVOID pShimData;	//+0x1e8
	PVOID AppCompatInfo;	//+0x1ec
	UNICODE_STRING CSDVersion;	//+0x1f0
	PVOID ActivationContextData;	//+0x1f8
	PVOID ProcessAssemblyStorageMap;	//+0x1fc
	PVOID SystemDefaultActivationContextData;	//+0x200
	PVOID SystemAssemblyStorageMap;	//+0x204
	ULONG MinimumStackCommit;	//+0x208
} PEB;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	PVOID ActiveFrame;
	LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG hDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH;

typedef struct _Wx86ThreadState
{
	ULONG* CallBx86Eip;
	PVOID DeallocationCpu;
	UCHAR UseKnownWx86Dll;
	CHAR OleStubInvoked;
} Wx86ThreadState;

/*
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	CHAR* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	_TEB_ACTIVE_FRAME* Previous;
	TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME;
*/

typedef struct _TEB
{
	NT_TIB NtTib;	//+0x000
	PVOID EnvironmentPointer;	//+0x01c
	CLIENT_ID ClientId;	//+0x020
	PVOID ActiveRpcHandle;	//+0x028
	PVOID ThreadLocalStoragePointer;	//+0x02c
	PEB* ProcessEnvironmentBlock;	//+0x030
	ULONG LastErrorValue;	//+0x034
	ULONG CountOfOwnedCriticalSections;	//+0x038
	PVOID CsrClientThread;	//+0x03c
	PVOID Win32ThreadInfo;	//+0x040
	ULONG User32Reserved[26];	//+0x044
	ULONG UserReserved[5];	//+0x0ac
	PVOID WOW32Reserved;	//+0x0c0
	ULONG CurrentLocale;	//+0x0c4
	ULONG FpSoftwareStatusRegister;	//+0x0c8
	PVOID SystemReserved1[54];	//+0x0cc
	LONG ExceptionCode;	//+0x1a4
	ACTIVATION_CONTEXT_STACK ActivationContextStack;	//+0x1a8
	UCHAR SpareBytes1[24];	//+0x1bc
	GDI_TEB_BATCH GdiTebBatch;	//+0x1d4
	CLIENT_ID RealClientId;	//+0x6b4
	PVOID GdiCachedProcessHandle;	//+0x6bc
	ULONG GdiClientPID;	//+0x6c0
	ULONG GdiClientTID;	//+0x6c4
	PVOID GdiThreadLocalInfo;	//+0x6c8
	ULONG Win32ClientInfo[62];	//+0x6cc
	PVOID glDispatchTable[233];	//+0x7c4
	ULONG glReserved1[29];	//+0xb68
	PVOID glReserved2;	//+0xbdc
	PVOID glSectionInfo;	//+0xbe0
	PVOID glSection;	//+0xbe4
	PVOID glTable;	//+0xbe8
	PVOID glCurrentRC;	//+0xbec
	PVOID glContext;	//+0xbf0
	ULONG LastStatusValue;	//+0xbf4
	UNICODE_STRING StaticUnicodeString;	//+0xbf8
	USHORT StaticUnicodeBuffer[261];	//+0xc00
	PVOID DeallocationStack;	//+0xe0c
	PVOID TlsSlots[64];	//+0xe10
	LIST_ENTRY TlsLinks;	//+0xf10
	PVOID Vdm;	//+0xf18
	PVOID ReservedForNtRpc;	//+0xf1c
	PVOID DbgSsReserved[2];	//+0xf20
	ULONG HardErrorsAreDisabled;	//+0xf28
	PVOID Instrumentation[16];	//+0xf2c
	PVOID WinSockData;	//+0xf6c
	ULONG GdiBatchCount;	//+0xf70
	UCHAR InDbgPrint;	//+0xf74
	UCHAR FreeStackOnTermination;	//+0xf75
	UCHAR HasFiberData;	//+0xf76
	UCHAR IdealProcessor;	//+0xf77
	ULONG Spare3;	//+0xf78
	PVOID ReservedForPerf;	//+0xf7c
	PVOID ReservedForOle;	//+0xf80
	ULONG WaitingOnLoaderLock;	//+0xf84
	Wx86ThreadState Wx86Thread;	//+0xf88
	PVOID* TlsExpansionSlots;	//+0xf94
	ULONG ImpersonationLocale;	//+0xf98
	ULONG IsImpersonating;	//+0xf9c
	PVOID NlsCache;	//+0xfa0
	PVOID pShimData;	//+0xfa4
	ULONG HeapVirtualAffinity;	//+0xfa8
	PVOID CurrentTransactionHandle;	//+0xfac
	PVOID ActiveFrame;	//+0xfb0 TEB_ACTIVE_FRAME*
	UCHAR SafeThunkCall;	//+0xfb4
	UCHAR BooleanSpare[3];	//+0xfb5
} TEB;

enum _NT_PRODUCT_TYPE
{
	NtProductWinNt=1,
	NtProductLanManNt=2,
	NtProductServer=3
};
typedef _NT_PRODUCT_TYPE NT_PRODUCT_TYPE;

enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign=0,
	NEC98x86=1,
	EndAlternatives=2
};
typedef _ALTERNATIVE_ARCHITECTURE_TYPE ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA
{
	ULONG TickCountLow;	//+0x000
	ULONG TickCountMultiplier;	//+0x004
	KSYSTEM_TIME InterruptTime;	//+0x008
	KSYSTEM_TIME SystemTime;	//+0x014
	KSYSTEM_TIME TimeZoneBias;	//+0x020
	USHORT ImageNumberLow;	//+0x02c
	USHORT ImageNumberHigh;	//+0x02e
	USHORT NtSystemRoot[260];	//+0x030
	ULONG MaxStackTraceDepth;	//+0x238
	ULONG CryptoExponent;	//+0x23c
	ULONG TimeZoneId;	//+0x240
	ULONG Reserved2[8];	//+0x244
	NT_PRODUCT_TYPE NtProductType;	//+0x264
	UCHAR ProductTypeIsValid;	//+0x268
	ULONG NtMajorVersion;	//+0x26c
	ULONG NtMinorVersion;	//+0x270
	UCHAR ProcessorFeatures[64];	//+0x274
	ULONG Reserved1;	//+0x2b4
	ULONG Reserved3;	//+0x2b8
	ULONG TimeSlip;	//+0x2bc
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;	//+0x2c0
	LARGE_INTEGER SystemExpirationDate;	//+0x2c8
	ULONG SuiteMask;	//+0x2d0
	UCHAR KdDebuggerEnabled;	//+0x2d4
	UCHAR NXSupportPolicy;	//+0x2d5
	ULONG ActiveConsoleId;	//+0x2d8
	ULONG DismountCount;	//+0x2dc
	ULONG ComPlusPackage;	//+0x2e0
	ULONG LastSystemRITEventTickCount;	//+0x2e4
	ULONG NumberOfPhysicalPages;	//+0x2e8
	UCHAR SafeBootMode;	//+0x2ec
	ULONG TraceLogging;	//+0x2f0
	ULONGLONG TestRetInstruction;	//+0x2f8
	ULONG SystemCall;	//+0x300
	ULONG SystemCallReturn;	//+0x304
	ULONGLONG SystemCallPad[3];	//+0x308
	union
	{
		KSYSTEM_TIME TickCount;	//+0x320
		ULONGLONG TickCountQuad;	//+0x320
	};
	ULONG Cookie;	//+0x330
} KUSER_SHARED_DATA;

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define NT_FAILED(Status)	(((NTSTATUS)(Status)) < 0)

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
}

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess()         
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )   
#define ZwCurrentThread() NtCurrentThread()  