#pragma once
#include <ntdef.h>
#include <wmistr.h>



#ifdef __cplusplus
extern "C"
{
#endif

    NTSTATUS NTAPI NtTraceControl(
        ULONG FunctionCode,
        PVOID InBuffer,
        ULONG InBufferLen,
        PVOID OutBuffer,
        ULONG OutBufferLen,
        PULONG ReturnLength);
    LONGLONG NTAPI RtlGetSystemTimePrecise();
#ifdef __cplusplus
}
#endif

typedef enum _ETWP_TRACE_TYPE
{
    EtwpStartTrace = 1,
    EtwpStopTrace = 2,
    EtwpQueryTrace = 3,
    EtwpUpdateTrace = 4,
    EtwpFlushTrace = 5
}ETWP_TRACE_TYPE;

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _EVENT_TRACE_PROPERTIES
{
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    union {
        LONG AgeLimit;
        LONG FlushThreshold;
    } DUMMYUNIONNAME;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;
#pragma warning(pop)
typedef struct _CKCL_TRACE_PROPERIES
{
    struct _EVENT_TRACE_PROPERTIES EventTraceProperties;
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

NTSTATUS EventTraceControl(ETWP_TRACE_TYPE Type);
