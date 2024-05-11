#pragma once
#include <ntdef.h>

typedef __int64 (*pfnHvlGetQpcBias)();

typedef struct _INF_HOOK_FUNC
{
    PVOID OriginalAddr;
    PVOID FakeFuncAddr;
}IHookFunc;


typedef struct _INFINITY_HOOK_PRO_CONTEXT
{
    BOOLEAN     InitFlg;
    int         HookedFunNum;
    IHookFunc   lstHook[256];

    ULONG       BuildNumber;
    ULONG64     NtoskrnlBase;

    //ULONG64     EtwpDebuggerData;
    PVOID*      EtwpDebuggerDataSilo;
    PVOID       CkclWmiLoggerContext;
    PVOID*      GetCpuClock;
    ULONG64     OriginalGetCpuClockValue;
    PVOID       SystemCallTable;
    PVOID       HvlpReferenceTscPage;
    PVOID       HvlGetQpcBias;
    PVOID       HvlpGetReferenceTimeUsingTscPage;
    PVOID       HalpPerformanceCounter;
    PVOID       HalpOriginalPerformanceCounter;
    PULONG      HalpPerformanceCounterType;
    UCHAR       VmHalpPerformanceCounterType;
    PVOID       HalpOriginalPerformanceCounterCopy;

    pfnHvlGetQpcBias OriginalHvlGetQpcBias;
}IHookProContext;

