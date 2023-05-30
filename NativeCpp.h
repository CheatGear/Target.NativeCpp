#pragma once
#include <CGMacro.h>
#include <Plugin/Target/TargetHandlerPlugin.h>
#include "Win32MemoryHandler.h"

class CG_EXPORTS NativeCpp final : public CG::TargetHandlerPlugin
{
private:
    Win32MemoryHandler* _memHandler = nullptr;
    int32_t _pid = 0;
    void* _processHandle = nullptr;
    SYSTEM_INFO _sysInfo{};

public:
    NativeCpp();
    ~NativeCpp() override;

private:
    static bool IsValidHandle(const void* pHandle);

public:
    CG::MemoryHandler* GetMemoryHandler() override;
    void Load() override;
    void Unload() override;
    void OnTargetFree() override;
    bool OnTargetLock(int32_t processId) override;
    void OnTargetReady() override;
    CG::CGArray<CG::MemModuleInfo>* GetModules() override;
    bool GetIs64Bit() override;
    int32_t GetSystemPageSize() override;
    void* GetMinValidAddress() override;
    void* GetMaxValidAddress() override;
    bool GetMemoryRegion(void* address, CG::MemRegionInfo* memRegion) override;
    bool IsValidRegion(CG::MemRegionInfo* memRegion) override;
    bool IsValidProcess(int processId) override;
    bool IsValidTarget() override;
    bool Suspend() override;
    bool Resume() override;
    bool Terminate() override;
};
