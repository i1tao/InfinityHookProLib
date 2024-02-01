#pragma once

#define IHOOKPRO_MAX_HOOK_NUM 100

#include <ntdef.h>
#pragma comment(lib, "InfinityHookProLib.lib")


#ifdef __cplusplus
extern "C" {
#endif

typedef struct _INF_HOOK_FUNC
{
    PVOID OriginalAddr;
    PVOID FakeFuncAddr;
}IHookFunc;


BOOLEAN     g_InitFlg;
int         g_HookedFunNum;
IHookFunc   g_HookList[IHOOKPRO_MAX_HOOK_NUM];


BOOLEAN
IHookProInitialize();

BOOLEAN
IHookProAddHookFunction(PCHAR FuncName,
                        PVOID FakeFuncAddr);

BOOLEAN
IHookProStart();

BOOLEAN
IHookProStop();

#ifdef __cplusplus
}
#endif