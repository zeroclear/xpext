## Windows XP API补全计划
### 已完成：
#### cs.cpp
InitializeCriticalSectionEx  
#### srw.cpp
RtlInitializeSRWLock  
RtlAcquireSRWLockExclusive  
RtlAcquireSRWLockShared  
RtlReleaseSRWLockExclusive  
RtlReleaseSRWLockShared  
RtlTryAcquireSRWLockExclusive  
RtlTryAcquireSRWLockShared  
#### cv.cpp
RtlInitializeConditionVariable  
RtlSleepConditionVariableCS  
RtlSleepConditionVariableSRW  
RtlWakeConditionVariable  
RtlWakeAllConditionVariable  
#### ps.cpp
GetThreadId  
GetProcessId  
GetProcessIdOfThread

### 即将完成：
#### processor.cpp
GetCurrentProcessorNumber  
GetCurrentProcessorNumberEx
#### runonce.cpp
RtlRunOnceInitialize  
RtlRunOnceBeginInitialize  
RtlRunOnceComplete  
RtlRunOnceExecuteOnce  
#### misc.cpp
GetErrorMode 

### 分析中：
FlsAlloc  
FlsFree  
FlsGetValue  
FlsSetValue  
IsThreadAFiber  
ws2_32.inet_ntop  
ws2_32.inet_pton  
ws2_32.WSAPoll  
RaiseFailFastException  
CreateEventExA/W  
CreateMutexExA/W  
CreateSemaphoreExA/W  
GetFinalPathNameByHandleA/W  
GetFileInformationByHandleEx  
InitializeProcThreadAttributeList  
UpdateProcThreadAttribute  
DeleteProcThreadAttributeList  
CreateSymbolicLinkA/W  
GetTickCount64  
PathCchCanonicalizeEx(Win8+)  
PathCchCombineEx(Win8+)  
GetActiveProcessorCount  
GetActiveProcessorGroupCount  
GetMaximumProcessorCount  
GetMaximumProcessorGroupCount  
advapi32.RegGetValueA/W  
advapi32.RegSetKeyValueA/W  
advapi32.RegDeleteKeyValueA/W  
mpr.WNetRestoreConnectionA  
运行时TLS动态分配槽的问题  

### 暂时无法实现：
IoConnectInterruptEx和MSIX  
CreateRemoteThreadEx  
Core Audio系列API  
NTFS的transacted  
NtQueryObject用在某些对象上会卡死  
完成端口的CloseHandle可以直接唤醒线程并返回-1  
CancelIoEx  
GetOverlappedResultEx  
normaliz.dll

### 其它说明：
代码是开源出来参考的，希望能得到反馈，更正错误  
将来会通过私人工具修改PE文件，重定向API调用，在release里提供    
某些功能需要内核驱动辅助实现，请使用reg文件将驱动设为开机启动  

### 有什么用？
![Entry Point Not Found](https://github.com/zeroclear/ntext/raw/master/introduce.png)
The procedure entry point XXX could not be located in the dynamic link library XXX.dll  
