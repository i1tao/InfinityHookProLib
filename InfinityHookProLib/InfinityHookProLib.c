#include "../include/InfinityHookProLib.h"
#include "log.h"
#include "EventTrace.h"

#include <ntddk.h>
BOOLEAN g_InitFlg      = FALSE;
int     g_HookedFunNum = 0;

BOOLEAN IHookProInitialize()
{
    RtlZeroMemory(g_HookList,sizeof(IHookFunc) * IHOOKPRO_MAX_HOOK_NUM);

    if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
    {
        if (!NT_SUCCESS(EventTraceControl(EtwpStartTrace)))
        {
            LOG_ERROR("start ckcl fail \n", __FUNCTION__);
            return FALSE;
        }

        if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
        {
            LOG_ERROR("syscall ckcl fail \n", __FUNCTION__);
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN IHookProAddHookFunction(PCHAR FuncName, PVOID FakeFuncAddr)
{
    ANSI_STRING as = RTL_CONSTANT_STRING(FuncName);
    UNICODE_STRING us;

    if (!g_InitFlg)
    {
        LOG_ERROR("Don't Initialize.");
        return FALSE;
    }

    RtlAnsiStringToUnicodeString(&us, &as, FALSE);

    PVOID OriginalAddr = MmGetSystemRoutineAddress(&us);
    if (!OriginalAddr)
    {
        LOG_ERROR("Get hook function address error.");
        return FALSE;
    }

    g_HookList[g_HookedFunNum].FakeFuncAddr = FakeFuncAddr;
    g_HookList[g_HookedFunNum].OriginalAddr = OriginalAddr;
    g_HookedFunNum++;

    LOG_INFO("Hook function <id:%d> name:<%Ws> Origin Addr:<0x%p> Fake Addr:<0x%p>. ", 
        g_HookedFunNum - 1, us, OriginalAddr, FakeFuncAddr);

    return TRUE;
}

BOOLEAN IHookProStart()
{
    return TRUE;
}

BOOLEAN IHookProStop()
{
    return TRUE;
}
