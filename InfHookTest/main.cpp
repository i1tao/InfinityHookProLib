#include <ntddk.h>

#include "../include/InfinityHookProLib.h"


extern "C" VOID
Unload(_In_ struct _DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    IHookProStop();
    return;
}

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = Unload;
    __debugbreak();
    IHookProInitialize();
    IHookProAddHookFunction("NtCreateFile", DriverEntry);

    return STATUS_SUCCESS;
}