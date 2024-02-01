#include "EventTrace.h"
#include "log.h"
#include <ntddk.h>
#include <evntrace.h>

NTSTATUS EventTraceControl(ETWP_TRACE_TYPE Type)
{
    const unsigned long Tag = 'OTIL';
    GUID GuidCkclSession = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

    CKCL_TRACE_PROPERTIES* Property = (CKCL_TRACE_PROPERTIES*)ExAllocatePool2(NonPagedPool, PAGE_SIZE, Tag);
    if (!Property)
    {
        LOG_ERROR("Allocate ckcl trace propertice struct failed \n");
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    PWCHAR ProviderName = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(PWCHAR), Tag);
    if (!ProviderName)
    {
        LOG_ERROR("Allocate provider name failed \n");
        ExFreePoolWithTag(Property, Tag);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    RtlZeroMemory(Property, PAGE_SIZE);
    RtlZeroMemory(ProviderName, 256 * sizeof(PWCHAR));

    RtlCopyMemory(ProviderName, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
    RtlInitUnicodeString(&Property->ProviderName, ProviderName);

    Property->EventTraceProperties.Wnode.BufferSize = PAGE_SIZE;
    Property->EventTraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    Property->EventTraceProperties.Wnode.Guid = GuidCkclSession;
    Property->EventTraceProperties.Wnode.ClientContext = 3;
    Property->EventTraceProperties.BufferSize = sizeof(unsigned long);
    Property->EventTraceProperties.MinimumBuffers = 2;
    Property->EventTraceProperties.MaximumBuffers = 2;
    Property->EventTraceProperties.LogFileMode = EVENT_TRACE_BUFFERING_MODE;

    if (Type == EtwpUpdateTrace)
    {
        Property->EventTraceProperties.EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
    }

    unsigned long nLength = 0;
    NTSTATUS ntStatus = NtTraceControl(Type, Property, PAGE_SIZE, Property, PAGE_SIZE, &nLength);

    ExFreePoolWithTag(ProviderName, Tag);
    ExFreePoolWithTag(Property, Tag);

    return ntStatus;
}