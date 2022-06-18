// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <vector>
#include "Signature.h"

const std::vector<uint8_t> bytes_original = { 0x45, 0x85, 0xc0, 0x75, 0x0a, 0xe8, 0x7d, 0x40, 0x29, 0x00 };
const std::vector<uint8_t> bytes_patched  = { 0x66, 0x90, 0x66, 0x90, 0x66, 0x90, 0x66, 0x90, 0x66, 0x90 };

bool console = GetConsoleWindow() != NULL;

//v1.0.0 = 0x1402534e9
void* TargetAddress = sigScan(
    "\x45\x85\xC0\x75\x00\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x41\x83\xF8\x01",
    "xxxx?x????x????xxxx");

void InjectCode(void* address, const std::vector<uint8_t> data)
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
        if (console) console = freopen("CONOUT$", "w", stdout) != NULL;

        if (TargetAddress)
        {
            if (console) printf("[DisableHandScale] Target Address for Signature is 0x%p\n", TargetAddress);

            InjectCode(TargetAddress, bytes_patched);

            if (console) printf("[DisableHandScale] Patch Successful.\n");

            return TRUE; // Adachi TRUE!
        }
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}