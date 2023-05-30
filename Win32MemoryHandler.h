#pragma once
#include <CGMacro.h>
#include <Plugin/Target/MemoryHandler.h>

class NativeCpp;

class CG_EXPORTS Win32MemoryHandler final : public CG::MemoryHandler
{
private:
    NativeCpp* _target = nullptr;
    void* _pHandle = nullptr;

public:
    explicit Win32MemoryHandler(NativeCpp* target);

public:
    bool IsBadAddress(void* address) override;
    bool IsStaticAddress(void* address) override;
    bool IsValidRemoteAddress(void* address) override;
    bool ReadBytes(void* address, uint8_t* bytes, int size, uint64_t* numberOfBytesRead) override;
    bool WriteBytes(void* address, uint8_t* bytes, int size, uint64_t* numberOfBytesWritten) override;

    void OnTargetReady(void* pHandle);
};
