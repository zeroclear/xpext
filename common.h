
#include <Windows.h>
#include <intrin.h>  

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG  Length;
	HANDLE  RootDirectory;
	PUNICODE_STRING  ObjectName;
	ULONG  Attributes;
	PVOID  SecurityDescriptor;
	PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

extern "C"
{
	NTSTATUS NTAPI NtCreateKeyedEvent(OUT PHANDLE handle, IN ACCESS_MASK access, IN POBJECT_ATTRIBUTES attr, IN ULONG flags);
	NTSTATUS NTAPI NtOpenKeyedEvent(OUT PHANDLE handle, IN ACCESS_MASK access, IN POBJECT_ATTRIBUTES attr);
	NTSTATUS NTAPI NtWaitForKeyedEvent(IN HANDLE handle, IN PVOID key, IN BOOLEAN alertable, IN PLARGE_INTEGER mstimeout);
	NTSTATUS NTAPI NtReleaseKeyedEvent(IN HANDLE handle, IN PVOID key, IN BOOLEAN alertable, IN PLARGE_INTEGER mstimeout);
	NTSTATUS NTAPI ZwTerminateProcess(IN HANDLE  ProcessHandle, IN NTSTATUS  ExitStatus);
	NTSTATUS NTAPI NtClose(IN HANDLE Handle);
	VOID NTAPI RtlRaiseStatus(NTSTATUS Status);
	VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString,PCWSTR SourceString);
};

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int __stdcall GetProcessorCount();
void __stdcall OpenGlobalKeyedEvent();
void __stdcall CloseGlobalKeyedEvent();

BOOL NTAPI RtlpWaitCouldDeadlock();
void NTAPI RtlBackoff(DWORD *pCount);

extern HANDLE GlobalKeyedEventHandle;

void NTAPI RtlInitializeSRWLock(SRWLOCK* SRWLock);
void NTAPI RtlAcquireSRWLockExclusive(SRWLOCK* pSRWLock);
void NTAPI RtlAcquireSRWLockShared(SRWLOCK* pSRWLock);
void NTAPI RtlReleaseSRWLockExclusive(SRWLOCK* pSRWLock);
void NTAPI RtlReleaseSRWLockShared(SRWLOCK* pSRWLock);
BOOL NTAPI RtlTryAcquireSRWLockExclusive(SRWLOCK* pSRWLock);
BOOL NTAPI RtlTryAcquireSRWLockShared(SRWLOCK* pSRWLock);
