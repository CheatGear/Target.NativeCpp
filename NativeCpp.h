#pragma once
#include <CGMacro.h>
#include <Plugins/Target/TargetHandlerPlugin.h>

class CG_EXPORTS NativeCpp final : public CG::TargetHandlerPlugin
{
    int32_t _pid = 0;
    void* _processHandle = nullptr;

public:
    bool IsValidProcess(int processId) override;
    int OnTargetLock(int32_t processId) override;
    int OnTargetFree() override;
    bool GetIs64Bit() override;
    CG::CGArray<CG::TargetModuleInfo>* GetModules() override;
    bool Suspend() override;
    bool Resume() override;
    bool Terminate() override;
    bool VirtualQuery(void* address, CG::MemoryInformation* outMemInfo) override;
    bool IsValidAddress(void* address) override;
    void* VirtualAlloc(void* address, int32_t size) override;
    void VirtualFree(void* address, int32_t size) override;
    bool IsValidMemory(CG::MemoryInformation* memRegion) override;
    bool IsStaticAddress(void* address, int32_t* outFailStatus) override;
    auto ReadBytes(void* address, uint8_t* bytes, int size, uint64_t* numberOfBytesRead) -> bool override;
    bool WriteBytes(void* address, uint8_t* bytes, int size, uint64_t* numberOfBytesWritten) override;
    void Dispose() override;
};
