#pragma once
#include <ntdef.h>


typedef struct _INF_HOOK_FUNC
{
    PVOID OriginalAddr;
    PVOID FakeFuncAddr;
}IHookFunc;


typedef struct _INFINITY_HOOK_PRO_CONTEXT
{
    BOOLEAN     InitFlg;
    int         HookedFunNum;
    IHookFunc   lstHook[IHOOKPRO_MAX_HOOK_NUM];

    ULONG       BuildNumber;
    ULONG64     NtoskrnlBase;
    
}IHookProContext;

