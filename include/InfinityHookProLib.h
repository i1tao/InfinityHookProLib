#pragma once



#include <ntdef.h>
#pragma comment(lib, "InfinityHookProLib.lib")

#ifdef __cplusplus
extern "C"
{
#endif

#define IHOOKPRO_MAX_HOOK_NUM 20    // the number of hook function you want.

    NTSTATUS
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