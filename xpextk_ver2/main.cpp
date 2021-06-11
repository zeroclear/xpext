
#include <ntddk.h>

void InitTickCount64Helper();
void UninitTickCount64Helper();
void InitProcessorIdHelper();
void UninitProcessorIdHelper();
void InitProcessInfoSsdtHook();
void UninitProcessInfoSsdtHook();

VOID DriverUnload(DRIVER_OBJECT* DriverObject)
{
	UninitTickCount64Helper();
	UninitProcessorIdHelper();
	UninitProcessInfoSsdtHook();

	DbgPrint("Unload success\n");
}

NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject,PUNICODE_STRING RegistryPath)
{
	DbgPrint("Enter DriverEntry\n");
	for (int i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
		DriverObject->MajorFunction[i]=NULL;
	DriverObject->DriverUnload=DriverUnload;
	
	InitTickCount64Helper();
	InitProcessorIdHelper();
	InitProcessInfoSsdtHook();

	DbgPrint("Leave DriverEntry\n");
	return STATUS_SUCCESS;	
}