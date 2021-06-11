## xpext - Windows XP API补全计划
### 已完成：
#### nk_criticalsection.cpp
InitializeCriticalSectionEx（仅接口）  
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
SetThreadErrorMode（仅接口）  
GetThreadErrorMode（仅接口）  
QueryFullProcessImageNameA  
QueryFullProcessImageNameW  
InitializeProcThreadAttributeList（仅接口）  
UpdateProcThreadAttribute（仅接口）  
DeleteProcThreadAttributeList（仅接口）  
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
#### k32_file.cpp
GetFileInformationByHandleEx  
SetFileInformationByHandle  
GetFinalPathNameByHandleA  
GetFinalPathNameByHandleW  
CreateSymbolicLinkA  
CreateSymbolicLinkW  
#### nk_fiber.cpp
ConvertThreadToFiberEx  
IsThreadAFiber  
ConvertThreadToFiber（增强）  
CreateFiberEx（增强）  
CreateFiber（增强）  
DeleteFiber（增强）  
ConvertFiberToThread（增强）  
SwitchToFiber（增强）  
FlsAlloc  
FlsFree  
FlsGetValue  
FlsSetValue  

### 近期计划：
GetSystemInfo  
GetVersion  
GetVersionEx  
VerifyVersionInfoA/W  
GetProductInfo  
制作PE编辑工具  

### 分析中：
GetErrorMode  
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
Wow64DisableWow64FsRedirection  
Wow64EnableWow64FsRedirection  
Wow64RevertWow64FsRedirection  
AddDllDirectory  
RemoveDllDirectory  
SetDefaultDllDirectories  
LoadLibraryEx的LOAD_LIBRARY_SEARCH_USER_DIRS标记  
ReOpenFile  
CreateFile2(Win8+)  
user32.SetProcessDPIAware  
CompareStringEx  
PsSetCreateProcessNotifyRoutineEx  
shell32.SHGetKnownFolderPath  

### 暂时无法实现：
QueryThreadCycleTime  
QueryProcessCycleTime  
CreateProcess应用ProcThreadAttribute  
ThreadPool相关API  
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

### 更新说明：
ver4 2021.06.12  
增加fiber相关API，以及一些其他API  
内核模块尝试新功能  
在study文件夹里给出一些代码中难以描述的信息  
将废弃的代码打包成zip文件  
ver3 2021.05.11  
增加一些文件相关的API，修复ver2中BaseSetLastNTError的严重bug  
由于Github展示代码的算法不完善，从ver3开始代码文件全部使用BOM+UTF8编码  
由于Github目录操作设计太差，从ver3开始新版和旧版都放在根目录下，以最新版本号为准  
ver2 2021.05.02  
添加内核支持模块xpextk  
增加RunOnce系列API，以及一些其他API  
项目名由ntext改为xpext，调整代码结构，重新编排文件名  
ver1 2021.03.21  
确定了基本框架和实现方向  
增加Condition Variable系列API，以及一些其他API  
调整SRW Lock，使之与Condition Variable一致  
ver0 2020.05.29  
初版，SRW Lock系列API  

### 其它说明：
代码是开源出来参考的，希望能得到反馈，更正错误，你编译了也没用  
将来会通过私人工具修改PE文件，重定向API调用，在release里提供  
某些功能需要内核驱动辅助实现，请使用reg文件将驱动设为开机启动  

### 有什么用？
The procedure entry point XXX could not be located in the dynamic link library XXX.dll  
![Entry Point Not Found](https://github.com/zeroclear/ntext/raw/master/introduce.png)  

### 相关项目：
[SharedReadWriteLock](https://github.com/anydream/SharedReadWriteLock)  
[YY-Thunks - 让兼容 Windows 更轻松](https://github.com/Chuyu-Team/YY-Thunks)  
[PHP 7 and PHP 5.6 for Windows XP/2003](https://github.com/source-power/php7-for-windows2003)  
[win7lib](https://github.com/TheDeadFish/win7lib)  
[wine](https://github.com/wine-mirror/wine)  
[ReactOS](https://github.com/reactos/reactos)  
[NTOSKRNL Emu_Extender](https://github.com/MovAX0xDEAD/NTOSKRNL_Emu)  
[CreateProcessInternal](https://github.com/MeeSong/Reverse-Engineering)  
[ExtendedXP-Core-Api-implementation](https://github.com/DibyaTheXPFan/ExtendedXP-Core-Api-implementation)  
