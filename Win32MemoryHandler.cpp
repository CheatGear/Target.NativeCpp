#include <windows.h>
#include "NativeCpp.h"
#include "Win32MemoryHandler.h"

Win32MemoryHandler::Win32MemoryHandler(NativeCpp* target)
{
    _target = target;
}

bool Win32MemoryHandler::IsBadAddress(void* address)
{
    return !address || address < _target->GetMinValidAddress() || address > _target->GetMaxValidAddress();
}

bool Win32MemoryHandler::IsStaticAddress(void* address)
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

bool Win32MemoryHandler::IsValidRemoteAddress(void* address)
{
    if (address == nullptr || IsBadAddress(address))
        return false;

    MEMORY_BASIC_INFORMATION info;
    bool valid = VirtualQueryEx(_pHandle, address, &info, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
    if (!valid)
        return false;

    return (info.Protect & PAGE_NOACCESS) == 0;
}

bool Win32MemoryHandler::ReadBytes(void* address, uint8_t* bytes, const int size, uint64_t* numberOfBytesRead)
{
    return ReadProcessMemory(_pHandle, address, bytes, size, numberOfBytesRead);
}

bool Win32MemoryHandler::WriteBytes(void* address, uint8_t* bytes, const int size, uint64_t* numberOfBytesWritten)
{
    return WriteProcessMemory(_pHandle, address, bytes, size, numberOfBytesWritten);
}

void Win32MemoryHandler::OnTargetReady(void* pHandle)
{
    _pHandle = pHandle;
}
