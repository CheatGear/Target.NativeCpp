#include <windows.h>
#include <tlhelp32.h>
#include "NativeCpp.h"

static bool IsValidHandle(const void* pHandle)
{
    return pHandle && pHandle != INVALID_HANDLE_VALUE;
}

static wchar_t* fromUTF8(
    const char* src,
    size_t src_length, /* = 0 */
    size_t* out_length /* = NULL */
)
{
    if (!src)
    {
        return nullptr;
    }

    if (src_length == 0) { src_length = strlen(src); }
    int length = MultiByteToWideChar(CP_UTF8, 0, src, src_length, 0, 0);
    wchar_t* output_buffer = (wchar_t*)malloc((length + 1) * sizeof(wchar_t));
    if (output_buffer)
    {
        MultiByteToWideChar(CP_UTF8, 0, src, src_length, output_buffer, length);
        output_buffer[length] = L'\0';
    }
    if (out_length) { *out_length = length; }
    return output_buffer;
}

static char* toUTF8(
    const wchar_t* src,
    size_t src_length, /* = 0 */
    size_t* out_length /* = NULL */
)
{
    if (!src)
    {
        return nullptr;
    }

    if (src_length == 0) { src_length = wcslen(src); }
    int length = WideCharToMultiByte(CP_UTF8, 0, src, src_length,
                                     0, 0, NULL, NULL);
    char* output_buffer = (char*)malloc((length + 1) * sizeof(char));
    if (output_buffer)
    {
        WideCharToMultiByte(CP_UTF8, 0, src, src_length,
                            output_buffer, length, NULL, NULL);
        output_buffer[length] = '\0';
    }
    if (out_length) { *out_length = length; }
    return output_buffer;
}

bool NativeCpp::IsValidProcess(const int processId)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process || process == INVALID_HANDLE_VALUE)
        return false;

    DWORD exitCode;
    if (!GetExitCodeProcess(process, &exitCode))
        return false;

    return exitCode == STILL_ACTIVE;
}

int NativeCpp::OnTargetLock(const int32_t processId)
{
    _processHandle = OpenProcess(
        PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE,
        processId);
    _pid = processId;

    return IsValidHandle(_processHandle) ? 0 : 1;
}

int NativeCpp::OnTargetFree()
{
    _pid = 0;

    if (!IsValidHandle(_processHandle))
        return -1;

    CloseHandle(_processHandle);
    return 0;
}

bool NativeCpp::GetIs64Bit()
{
    CG_LOG_FUNC_CALL;
    BOOL retVal;
    return IsWow64Process(_processHandle, &retVal) && !retVal;
}

CG::CGArray<CG::TargetModuleInfo>* NativeCpp::GetModules()
{
    CG_LOG_FUNC_CALL;
    std::vector<CG::TargetModuleInfo> ret;

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
            CG::TargetModuleInfo curModule(
                modEntry.hModule,
                toUTF8(modEntry.szModule, 0, nullptr),
                toUTF8(modEntry.szExePath, 0, nullptr),
                reinterpret_cast<uintptr_t>(modEntry.modBaseAddr),
                modEntry.modBaseSize,
                wcscmp(modEntry.szExePath, exeFullPath) == 0);

            ret.push_back(curModule);
        }
        while (Module32Next(hSnap, &modEntry));
    }

    CloseHandle(hSnap);
    return new CG::CGArray<CG::TargetModuleInfo>(ret);
}

bool NativeCpp::Suspend()
{
    CG_LOG_FUNC_CALL;
    using NtSuspendProcessType = LONG(NTAPI *)(IN HANDLE processHandle);
    static auto pfnNtSuspendProcess = reinterpret_cast<NtSuspendProcessType>(GetProcAddress(
        GetModuleHandleA("ntdll"), "NtSuspendProcess"));

    return pfnNtSuspendProcess(_processHandle) >= 0;
}

bool NativeCpp::Resume()
{
    CG_LOG_FUNC_CALL;
    using NtResumeProcessType = LONG(NTAPI *)(IN HANDLE processHandle);
    static auto pfnNtSuspendProcess = reinterpret_cast<NtResumeProcessType>(GetProcAddress(
        GetModuleHandleA("ntdll"), "NtResumeProcess"));

    return pfnNtSuspendProcess(_processHandle) >= 0;
}

bool NativeCpp::Terminate()
{
    CG_LOG_FUNC_CALL;
    using NtTerminateProcessType = LONG(NTAPI *)(IN HANDLE processHandle, IN NTSTATUS exitStatus);
    static auto pfnNtTerminateProcess = reinterpret_cast<NtTerminateProcessType>(GetProcAddress(
        GetModuleHandleA("ntdll"), "NtTerminateProcess"));

    return pfnNtTerminateProcess(_processHandle, 0) >= 0;
}

bool NativeCpp::VirtualQuery(void* address, CG::MemoryInformation* outMemInfo)
{
    if (address == nullptr)
        return false;
    
    if (!outMemInfo)
        return false;
    
    MEMORY_BASIC_INFORMATION info;
    constexpr size_t mbi_size = sizeof(MEMORY_BASIC_INFORMATION);
    const bool valid_call = VirtualQueryEx(_processHandle, address, &info, mbi_size) == mbi_size;
    if (!valid_call)
        return false;

    outMemInfo->AllocationBase = info.AllocationBase;
    outMemInfo->BaseAddress = info.BaseAddress;
    outMemInfo->Protect = info.Protect;
    outMemInfo->Size = info.RegionSize;
    outMemInfo->State = info.State;
    outMemInfo->Type = info.Type;

    return true;
}

bool NativeCpp::IsValidAddress(void* address)
{
    CG::MemoryInformation out_mem_info;
    if (!VirtualQuery(address, &out_mem_info))
    {
        return false;
    }

    return (out_mem_info.Protect & PAGE_NOACCESS) == 0;
}

void* NativeCpp::VirtualAlloc(void* address, int32_t size)
{
    // TODO: This method should take type and protection instead of address param
    return VirtualAllocEx(_processHandle, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void NativeCpp::VirtualFree(void* address, int32_t size)
{
    VirtualFreeEx(_processHandle, address, size, MEM_RELEASE);
}

bool NativeCpp::IsValidMemory(CG::MemoryInformation* memRegion)
{
    bool check = (memRegion->State & MEM_COMMIT) != 0;
    if (!check)
        return false;

    check = (memRegion->Protect & PAGE_NOACCESS) == 0
        && (memRegion->Protect & PAGE_TARGETS_INVALID) == 0
        && (memRegion->Protect & PAGE_GUARD) == 0
        && (memRegion->Protect & PAGE_NOCACHE) == 0;

    return check;
}

bool NativeCpp::IsStaticAddress(void* address, int32_t* outFailStatus)
{
    ///*
    // * Thanks To Roman_Ablo @ GuidedHacking
    // * https://guidedhacking.com/threads/hyperscan-fast-vast-memory-scanner.9659/
    // */
    //if (IsBadAddress(address))
    //    return false;

    //ulong length = 0;
    //auto sectionInformation = new StructAllocator<Win32.SectionInfo>();
    //
    //int retStatus = _ntQueryVirtualMemory(
    //    _processHandle,
    //    address,
    //    Win32.MemoryInformationClass.MemoryMappedFilenameInformation,
    //    sectionInformation.UnManagedPtr.ToUIntPtr(),
    //    (ulong)Marshal.SizeOf<Win32.SectionInfo>(),
    //    ref length);

    //// 32bit game
    //if (!_target.Process64Bit)
    //    return Win32.NtSuccess(retStatus);

    //if (!Win32.NtSuccess(retStatus))
    //    return false;

    //sectionInformation.Update();
    //string deviceName = sectionInformation.ManagedStruct.SzData;

    ///*
    //string filePath = new string(deviceName);
    //for (int i = 0; i < 3; i++)
    //    filePath = filePath[(filePath.IndexOf('\\') + 1)..];
    //filePath = filePath.Trim('\0');
    //*/

    //IEnumerable<string> drivesLetter = DriveInfo.GetDrives().Select(d =  > d.Name.Replace("\\", ""));
    //foreach(string driveLetter in drivesLetter)
    //{
    //    var sb = new StringBuilder(64);
    //    _ = Win32.QueryDosDevice(driveLetter, sb, 64 * 2); // * 2 Unicode

    //    if (deviceName.Contains(sb.ToString()))
    //        return true;
    //}
    CG_LOG_FUNC_CALL;

    return false;
}

bool NativeCpp::ReadBytes(void* address, uint8_t* bytes, const int size, uint64_t* numberOfBytesRead)
{
    return ReadProcessMemory(_processHandle, address, bytes, size, numberOfBytesRead);
}

bool NativeCpp::WriteBytes(void* address, uint8_t* bytes, const int size, uint64_t* numberOfBytesWritten)
{
    return WriteProcessMemory(_processHandle, address, bytes, size, numberOfBytesWritten);
}

void NativeCpp::Dispose()
{
    _pid = 0;

    if (!IsValidHandle(_processHandle))
        return;

    CloseHandle(_processHandle);
}
