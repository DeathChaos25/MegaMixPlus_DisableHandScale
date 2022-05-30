// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <vector>

const uint64_t TargetAddress = 0x1402534e9;
const std::vector<uint8_t> bytes_original = { 0x45, 0x85, 0xc0, 0x75, 0x0a, 0xe8, 0x7d, 0x40, 0x29, 0x00 };
const std::vector<uint8_t> bytes_patched  = { 0x66, 0x90, 0x66, 0x90, 0x66, 0x90, 0x66, 0x90, 0x66, 0x90 };

void InjectCode(void* address, const std::vector<uint8_t> data) // taken from https://github.com/nastys/ExPatch/blob/main/ExPatch/dllmain.cpp
{
    const size_t byteCount = data.size() * sizeof(uint8_t);

    DWORD oldProtect;
    VirtualProtect(address, byteCount, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(address, data.data(), byteCount);
    VirtualProtect(address, byteCount, oldProtect, nullptr);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        puts("[DisableHandScale] Initializing...");
        if (memcmp(bytes_original.data(), (void*)0x1402534e9, 10))
        {
            puts("[DisableHandScale] Error: unsupported game version.");
            return FALSE;
        }

        InjectCode((void*)0x1402534e9, bytes_patched);
        puts("[DisableHandScale] Patch Successful.");
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

