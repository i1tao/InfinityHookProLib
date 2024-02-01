
#include "..\InfinityHookProLib/InfinityHookProLib.h"




extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    //InfHookProLib::g_vecHookFunc.push_back({ DriverEntry,DriverEntry });
    InfHookProLib::InfHookFunc func;
    func.FakeFuncAddr = GET_NT_FUNCTION_ADDRESS("NtCreateFile");

    UNICODE_STRING us = RTL_CONSTANT_STRING(L"NtCreateFile");

    return STATUS_SUCCESS;
}