#include <windows.h>
#include "NativeCpp.h"

CG_REGISTER_PLUGIN(
    NativeCpp,
    CG::PluginKind::TargetHandler,
    "NativeCpp",
    "5.0.0",
    "CorrM",
    "Use current system API to read/write memory process",
    "",
    "");

BOOL APIENTRY DllMain(const HMODULE hModule, const DWORD ulReasonForCall, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(hModule);
    return TRUE;
}
