#include <windows.h>
#include <tlhelp32.h>
#include <Plugin/Target/MemModuleInfo.h>
#include <Plugin/Target/MemRegionInfo.h>
#include "Win32MemoryHandler.h"
#include "NativeCpp.h"

NativeCpp::NativeCpp()
{
    _memHandler = new Win32MemoryHandler(this);
    GetSystemInfo(&_sysInfo);
}

NativeCpp::~NativeCpp()
{
    delete _memHandler;
    _memHandler = nullptr;
}

bool NativeCpp::IsValidHandle(const void* pHandle)
{
    return pHandle && pHandle != INVALID_HANDLE_VALUE;
}

CG::MemoryHandler* NativeCpp::GetMemoryHandler()
{
    return _memHandler;
}

void NativeCpp::Load()
{
    CG_LOG_FUNC_CALL;
}

void NativeCpp::Unload()
{
    CG_LOG_FUNC_CALL;
}

void NativeCpp::OnTargetFree()
{
    CG_LOG_FUNC_CALL;
    _pid = 0;

    if (!IsValidHandle(_processHandle))
        return;

    CloseHandle(_processHandle);
}

bool NativeCpp::OnTargetLock(const int32_t processId)
{
    CG_LOG_FUNC_CALL;
    _processHandle = OpenProcess(
        PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE,
        processId);
    _pid = processId;

    return IsValidHandle(_processHandle);
}

void NativeCpp::OnTargetReady()
{
    CG_LOG_FUNC_CALL;
    _memHandler->OnTargetReady(_processHandle);
}

CG::CGArray<CG::MemModuleInfo>* NativeCpp::GetModules()
{
    CG_LOG_FUNC_CALL;
    std::vector<CG::MemModuleInfo> ret;

    // Get target exe full path
    constexpr DWORD pathSize = 1024;
    DWORD outPathSize = pathSize;
    wchar_t exeFullPath[pathSize]{};
    QueryFullProcessImageName(_processHandle, 0, exeFullPath, &outPathSize);

    // Loop modules
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, _pid);
    if (!IsValidHandle(hSnap))
        return nullptr;

    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &modEntry))
    {
        do
        {
            CG::MemModuleInfo curModule(
                modEntry.hModule,
                modEntry.szModule,
                modEntry.szExePath,
                reinterpret_cast<uintptr_t>(modEntry.modBaseAddr),
                modEntry.modBaseSize,
                wcscmp(modEntry.szExePath, exeFullPath) == 0);

            ret.push_back(curModule);
        }
        while (Module32Next(hSnap, &modEntry));
    }

    CloseHandle(hSnap);
    return new CG::CGArray<CG::MemModuleInfo>(ret);
}

bool NativeCpp::GetIs64Bit()
{
    CG_LOG_FUNC_CALL;
    BOOL retVal;
    return IsWow64Process(_processHandle, &retVal) && !retVal;
}

int32_t NativeCpp::GetSystemPageSize()
{
    CG_LOG_FUNC_CALL;
    return static_cast<int32_t>(_sysInfo.dwPageSize);
}

void* NativeCpp::GetMinValidAddress()
{
    CG_LOG_FUNC_CALL;
    return _sysInfo.lpMinimumApplicationAddress;
}

void* NativeCpp::GetMaxValidAddress()
{
    CG_LOG_FUNC_CALL;
    return reinterpret_cast<void*>(_sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && GetIs64Bit()
        ? 0x800000000000
        : 0x100000000);
}

bool NativeCpp::GetMemoryRegion(void* address, CG::MemRegionInfo* memRegion)
{
    CG_LOG_FUNC_CALL;
    MEMORY_BASIC_INFORMATION info;

    // Get Region information
    bool valid = VirtualQueryEx(
        _processHandle,
        address,
        &info,
        sizeof(MEMORY_BASIC_INFORMATION)
    ) == sizeof(MEMORY_BASIC_INFORMATION);

    if (!valid)
        return false;

    memRegion->AllocationBase = info.AllocationBase;
    memRegion->BaseAddress = info.BaseAddress;
    memRegion->Size = info.RegionSize;
    memRegion->State = info.State;
    memRegion->Protect = info.Protect;
    memRegion->Type = info.Type;

    return true;
}

bool NativeCpp::IsValidRegion(CG::MemRegionInfo* memRegion)
{
    CG_LOG_FUNC_CALL;
    bool check = (memRegion->State & MEM_COMMIT) != 0;
    if (!check)
        return false;

    check = (memRegion->Protect & PAGE_NOACCESS) == 0
        && (memRegion->Protect & PAGE_TARGETS_INVALID) == 0
        && (memRegion->Protect & PAGE_GUARD) == 0
        && (memRegion->Protect & PAGE_NOCACHE) == 0;

    return check;
}

bool NativeCpp::IsValidProcess(const int processId)
{
    CG_LOG_FUNC_CALL;
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process || process == INVALID_HANDLE_VALUE)
        return false;

    DWORD exitCode;
    if (!GetExitCodeProcess(process, &exitCode))
        return false;

    return exitCode == STILL_ACTIVE;
}

bool NativeCpp::IsValidTarget()
{
    CG_LOG_FUNC_CALL;
    return IsValidProcess(_pid) && IsValidHandle(_processHandle);
}

bool NativeCpp::Suspend()
{
    CG_LOG_FUNC_CALL;
    using NtSuspendProcessType = LONG(NTAPI *)(IN HANDLE processHandle);
    static auto pfnNtSuspendProcess = reinterpret_cast<NtSuspendProcessType>(GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess"));

    return pfnNtSuspendProcess(_processHandle) >= 0;
}

bool NativeCpp::Resume()
{
    CG_LOG_FUNC_CALL;
    using NtResumeProcessType = LONG(NTAPI *)(IN HANDLE processHandle);
    static auto pfnNtSuspendProcess = reinterpret_cast<NtResumeProcessType>(GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess"));

    return pfnNtSuspendProcess(_processHandle) >= 0;
}

bool NativeCpp::Terminate()
{
    CG_LOG_FUNC_CALL;
    using NtTerminateProcessType = LONG(NTAPI *)(IN HANDLE processHandle, IN NTSTATUS exitStatus);
    static auto pfnNtTerminateProcess = reinterpret_cast<NtTerminateProcessType>(GetProcAddress(GetModuleHandleA("ntdll"), "NtTerminateProcess"));

    return pfnNtTerminateProcess(_processHandle, 0) >= 0;
}
