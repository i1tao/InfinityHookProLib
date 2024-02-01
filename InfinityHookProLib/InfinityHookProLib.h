#ifndef INFINITY_HOOK_PRO_LIB
#define INFINITY_HOOK_PRO_LIB

#include <ntddk.h>
#include <wdm.h>

namespace InfHookProLib
{
#define MAX_HOOK_NUM 100

    typedef struct _INF_HOOK_FUNC
    {
        PVOID OriginalAddr;
        PVOID FakeFuncAddr;
    }InfHookFunc; 

    InfHookFunc g_HookList[MAX_HOOK_NUM];


    bool Initialize();
    bool AddHookFunction(char* FuncName, PVOID HookAddress);

    bool Start();
    bool Stop();
}


#endif
