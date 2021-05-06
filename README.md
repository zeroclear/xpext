## xpext - Windows XP API补全计划
### 已完成：
#### nk_criticalsection.cpp
InitializeCriticalSectionEx  
#### nt_srwlock.cpp
InitializeSRWLock  
AcquireSRWLockExclusive  
AcquireSRWLockShared  
ReleaseSRWLockExclusive  
ReleaseSRWLockShared  
TryAcquireSRWLockExclusive  
TryAcquireSRWLockShared  
#### nk_conditionvariable.cpp
InitializeConditionVariable  
SleepConditionVariableCS  
SleepConditionVariableSRW  
WakeConditionVariable  
WakeAllConditionVariable  
#### nk_runonce.cpp
InitOnceInitialize  
InitOnceBeginInitialize  
InitOnceComplete  
InitOnceExecuteOnce  
#### k32_processthread.cpp
GetThreadId  
GetProcessId  
GetProcessIdOfThread
#### k32_processor.cpp
GetCurrentProcessorNumber  
GetCurrentProcessorNumberEx  
GetActiveProcessorGroupCount  
GetMaximumProcessorGroupCount  
GetActiveProcessorCount  
GetMaximumProcessorCount  
#### k32_miscellaneous.cpp
GetTickCount64  
RaiseFailFastException  

### 即将完成：
#### misc.cpp
GetErrorMode 
#### k32_processthread.cpp
InitializeProcThreadAttributeList  
UpdateProcThreadAttribute  
DeleteProcThreadAttributeList  
#### k32_file.cpp
GetFinalPathNameByHandleA/W  
GetFileInformationByHandleEx  
SetFileInformationByHandle  
CreateSymbolicLinkA/W  

### 分析中：
FlsAlloc  
FlsFree  
FlsGetValue  
FlsSetValue  
IsThreadAFiber  
ConvertThreadToFiberEx  
ws2_32.inet_ntop  
ws2_32.inet_pton  
ws2_32.WSAPoll  
CreateEventExA/W  
CreateMutexExA/W  
CreateSemaphoreExA/W  
PathCchCanonicalizeEx(Win8+)  
PathCchCombineEx(Win8+)  
advapi32.RegGetValueA/W  
advapi32.RegSetKeyValueA/W  
advapi32.RegDeleteKeyValueA/W  
mpr.WNetRestoreConnectionA  
运行时TLS动态分配槽的问题  

### 暂时无法实现：
CreateProcess应用AttributeList  
NtXXXKeyedEvent允许句柄传入NULL  
IoConnectInterruptEx和MSIX  
CreateRemoteThreadEx  
Core Audio系列API  
NTFS的transacted  
NtQueryObject用在某些对象上会卡死  
完成端口的CloseHandle可以直接唤醒线程并返回-1  
CancelIoEx  
GetOverlappedResultEx  
normaliz.dll  
SetLastError断点

### 其它说明：
代码是开源出来参考的，希望能得到反馈，更正错误，你编译了也没用  
将来会通过私人工具修改PE文件，重定向API调用，在release里提供  
某些功能需要内核驱动辅助实现，请使用reg文件将驱动设为开机启动  

### 有什么用？
The procedure entry point XXX could not be located in the dynamic link library XXX.dll  
![Entry Point Not Found](https://github.com/zeroclear/ntext/raw/master/introduce.png)  

### 类似项目
[SharedReadWriteLock](https://github.com/anydream/SharedReadWriteLock)  
[YY-Thunks - 让兼容 Windows 更轻松](https://github.com/Chuyu-Team/YY-Thunks)  
[PHP 7 and PHP 5.6 for Windows XP/2003](https://github.com/source-power/php7-for-windows2003)  
[win7lib](https://github.com/TheDeadFish/win7lib)  
[wine](https://github.com/wine-mirror/wine)  
[ReactOS](https://github.com/reactos/reactos)  
[NTOSKRNL Emu_Extender](https://github.com/MovAX0xDEAD/NTOSKRNL_Emu)  
