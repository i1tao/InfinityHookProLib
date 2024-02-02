#include "../include/InfinityHookProLib.h"
#include "log.h"
#include "EventTrace.h"
#include "Defs.h"
#include <ntddk.h>
#include <stdbool.h>

#include "Utils.h"

IHookProContext g_IHookProContext = { 0 };

NTSTATUS IHookProInitialize()
{
    //
    // Init the array of hook functions
    //
    g_IHookProContext.InitFlg = FALSE;
    g_IHookProContext.HookedFunNum = 0;
    RtlZeroMemory(g_IHookProContext.lstHook, sizeof(IHookFunc) * IHOOKPRO_MAX_HOOK_NUM);

    //
    // Check if the "Circular Kernel Context Logger" session has been started.
    // If not, start the session.
    //
    if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
    {
        if (!NT_SUCCESS(EventTraceControl(EtwpStartTrace)))
        {
            LOG_ERROR("Start ckcl failed");
            return FALSE;
        }

        if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
        {
            LOG_ERROR("Update ckcl failed");
            return FALSE;
        }
    }

    RTL_OSVERSIONINFOW os;
    RtlGetVersion(&os);
    g_IHookProContext.BuildNumber = os.dwBuildNumber;
    g_IHookProContext.NtoskrnlBase = GetModuleAddress("ntoskrnl.exe", NULL);

    if (!g_IHookProContext.NtoskrnlBase)
    {
        LOG_ERROR("Can't get ntoskrnl.exe base");
        return FALSE;
    }

    LOG_INFO("System BuildNumber is <%d>. Ntoskrnl address is <0x%llX> \n", os.dwBuildNumber, g_IHookProContext.NtoskrnlBase);

    //
    // EtwpDebuggerData -> EtwpDebuggerDataSilo -> CkclWmiLoggerContext.
    // If not, start the session.
    //
    ULONG64 EtwpDebuggerData = FindPatternImage(g_IHookProContext.NtoskrnlBase, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
    if (!EtwpDebuggerData)
    {
        EtwpDebuggerData = FindPatternImage(g_IHookProContext.NtoskrnlBase, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
    }

    if (!EtwpDebuggerData)
    {
        EtwpDebuggerData = FindPatternImage(g_IHookProContext.NtoskrnlBase, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
    }

    if (!EtwpDebuggerData)
    {
        LOG_ERROR("Find etwp data error.");
        return FALSE;
    }
    LOG_INFO("Find etwp debugger data <0x%llX> .", EtwpDebuggerData);



    return TRUE;
}

BOOLEAN IHookProAddHookFunction(PCHAR FuncName, PVOID FakeFuncAddr)
{
    ANSI_STRING as = RTL_CONSTANT_STRING(FuncName);
    UNICODE_STRING us;

    if (!g_IHookProContext.InitFlg)
    {
        LOG_ERROR("Does't Initialize.");
        return FALSE;
    }

    RtlAnsiStringToUnicodeString(&us, &as, FALSE);

    PVOID OriginalAddr = MmGetSystemRoutineAddress(&us);
    if (!OriginalAddr)
    {
        LOG_ERROR("Get hook function address error.");
        return FALSE;
    }

    g_IHookProContext.lstHook[g_IHookProContext.HookedFunNum].FakeFuncAddr = FakeFuncAddr;
    g_IHookProContext.lstHook[g_IHookProContext.HookedFunNum].OriginalAddr = OriginalAddr;
    g_IHookProContext.HookedFunNum++;

    LOG_INFO("Hook function <id:%d> name:<%Ws> Origin Addr:<0x%p> Fake Addr:<0x%p>. ",
        g_IHookProContext.HookedFunNum - 1,
        us,
        OriginalAddr,
        FakeFuncAddr);

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
