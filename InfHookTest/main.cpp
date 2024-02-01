#include <ntddk.h>

#include "../include/InfinityHookProLib.h"

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    IHookProInitialize();
    IHookProAddHookFunction("NtCreateFile", DriverEntry);

    return STATUS_SUCCESS;
}