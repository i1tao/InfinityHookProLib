#pragma once

#include <ntdef.h>
#pragma comment(lib, "InfinityHookProLib.lib")

#ifdef __cplusplus
extern "C"
{
#endif

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