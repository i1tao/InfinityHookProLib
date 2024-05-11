#define HALP_PERFORMANCE_COUNTER_TYPE_OFFSET (0xE4)
#define HALP_PERFORMANCE_COUNTER_BASE_RATE_OFFSET (0xC0)
#define HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE  (0x5)
#define HALP_PERFORMANCE_COUNTER_BASE_RATE (10000000i64) 

#pragma warning(disable: 4996)

#include "../include/InfinityHookProLib.h"
#include "log.h"
#include "EventTrace.h"
#include "Defs.h"
#include "Utils.h"
#include "IHookFunctions.h"
#include <ntddk.h>

IHookProContext g_IHookProContext = { 0 };

NTSTATUS IHookProInitialize()
{
    //
    // Init the array of hook functions
    //
    IHookProContext* ctx = &g_IHookProContext;
    ctx->InitFlg = FALSE;
    ctx->HookedFunNum = 0;
    RtlZeroMemory(ctx->lstHook, sizeof(IHookFunc) * IHOOKPRO_MAX_HOOK_NUM);

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

    //
    // Get system build number to get some args that run hooking needed.
    //
    RTL_OSVERSIONINFOW os;
    RtlGetVersion(&os);
    ctx->BuildNumber = os.dwBuildNumber;
    ctx->NtoskrnlBase = GetModuleAddress("ntoskrnl.exe", NULL);

    if (!ctx->NtoskrnlBase)
    {
        LOG_ERROR("Can't get ntoskrnl.exe base");
        return FALSE;
    }

    LOG_INFO("System BuildNumber is <%d>. Ntoskrnl address is <0x%llX>.", os.dwBuildNumber, ctx->NtoskrnlBase);

    //
    // EtwpDebuggerData -> EtwpDebuggerDataSilo -> CkclWmiLoggerContext.
    // If not, start the session.
    //
    ULONG64 EtwpDebuggerData = FindPatternImage(ctx->NtoskrnlBase, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
    if (!EtwpDebuggerData)
    {
        EtwpDebuggerData = FindPatternImage(ctx->NtoskrnlBase, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
    }

    if (!EtwpDebuggerData)
    {
        EtwpDebuggerData = FindPatternImage(ctx->NtoskrnlBase, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
    }

    if (!EtwpDebuggerData)
    {
        LOG_ERROR("Find etwp data error.");
        return FALSE;
    }
    LOG_INFO("Find etwp debugger data <0x%llX>.", EtwpDebuggerData);

    //
    // Find EtwpDebuggerDataSilo.
    //
    ctx->EtwpDebuggerDataSilo = *(void***)((ULONG64)EtwpDebuggerData + 0x10);
    LOG_INFO("Etwp debugger data silo is <0x%p>.", ctx->EtwpDebuggerDataSilo);
    if (!ctx->EtwpDebuggerDataSilo)
    {
        return FALSE;
    }

    //
    // Find CkclWmiLoggerContext.
    //
    ctx->CkclWmiLoggerContext = ctx->EtwpDebuggerDataSilo[0x2];
    LOG_INFO("Ckcl wmi logger context is <0x%p>.", ctx->CkclWmiLoggerContext);
    if (!ctx->CkclWmiLoggerContext)
    {
        return FALSE;
    }

    //
    // Find GetCpuClock.
    //
    if (ctx->BuildNumber <= 7601 || ctx->BuildNumber >= 22000)
    {
        // Win7 & Win11
        ctx->GetCpuClock = (PVOID*)((ULONG64)ctx->CkclWmiLoggerContext + 0x18);
    }
    else
    {
        // Win8 -> Win10
        ctx->GetCpuClock = (PVOID*)((ULONG64)ctx->CkclWmiLoggerContext + 0x28);
    }

    if (!MmIsAddressValid(ctx->GetCpuClock))
    {
        return FALSE;
    }
    LOG_INFO("GetCpuClock is <0x%p>.", *ctx->GetCpuClock);

    //
    // Find SSDT entry.
    //
    ctx->SystemCallTable = PAGE_ALIGN(GetSyscallEntry(ctx->NtoskrnlBase));
    LOG_INFO("Syscall table is <0x%p>.", ctx->SystemCallTable);
    if (!ctx->SystemCallTable)
    {
        return FALSE;
    }

    if (ctx->BuildNumber <= 18363)
    {
        ctx->InitFlg = TRUE;
        return TRUE;
    }

    //
    // Find misc data that hook used.
    //

    ULONG64 RefHvlpReferenceTscPageAddress = FindPatternImage(
        ctx->NtoskrnlBase,
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
        "xxx????xxx?xxx????xxx",
        ".text");
    if (!RefHvlpReferenceTscPageAddress)
    {
        LOG_INFO("Find HvlpReferenceTscPage Failed!");
        return FALSE;
    }

    ctx->HvlpReferenceTscPage = (char*)(RefHvlpReferenceTscPageAddress)+7 + *(int*)((char*)RefHvlpReferenceTscPageAddress + 3);
    LOG_INFO("HvlpReferenceTscPage is <0x%llX>.", ctx->HvlpReferenceTscPage);
    if (!ctx->HvlpReferenceTscPage)
    {
        return FALSE;
    }

    LOG_INFO("HvlpReferenceTscPage Value is <0x%llX>.", *(PULONG64)(ctx->HvlpReferenceTscPage));

    //
    // Find HvlGetQpcBias.
    //
    ULONG64 RefHvlGetQpcBiasAddress = FindPatternImage(
        ctx->NtoskrnlBase,
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74", // before Win10 22H2 & before Win11 22621
        "xxx????xxxx?xxx?????x",
        ".text");

    if (!RefHvlGetQpcBiasAddress)
    {
        //All of these feature codes are present.
        RefHvlGetQpcBiasAddress = FindPatternImage(
            ctx->NtoskrnlBase,
            "\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8\x48\x89\x1f",
            "xxx????x????xxxxxx",
            ".text");
        if (!RefHvlGetQpcBiasAddress)
        {
            LOG_ERROR("Find HvlGetQpcBias Failed!");
            return FALSE;
        }
    }

    ctx->HvlGetQpcBias = (char*)(RefHvlGetQpcBiasAddress)+7 + *(int*)((char*)RefHvlGetQpcBiasAddress + 3);

    LOG_INFO("HvlGetQpcBias is <0x%llX>.", ctx->HvlGetQpcBias);
    if (!ctx->HvlpReferenceTscPage)
    {
        return FALSE;
    }
    LOG_INFO("[%s] HvlGetQpcBias Value Is <0x%llX>.", __FUNCTION__, *(PULONG64)ctx->HvlGetQpcBias);

    //
    // Find HvlpGetReferenceTimeUsingTscPage.
    //
    ULONG64 RefHvlpGetReferenceTimeUsingTscPageAddress = FindPatternImage(
        ctx->NtoskrnlBase,
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x33\xc9\xe8\x00\x00\x00\x00\x48\x8b\xd8",  //Win10 22H2 & Win11 22621
        "xxx????xxxx?xxx????xxx",
        ".text");
    if (!RefHvlpGetReferenceTimeUsingTscPageAddress)
    {
        RefHvlpGetReferenceTimeUsingTscPageAddress = FindPatternImage(
            ctx->NtoskrnlBase,
            "\x48\x8b\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x03\xd8",
            "xxx????x????xxx",
            ".text");
    }
    if (!RefHvlpGetReferenceTimeUsingTscPageAddress)
    {
        LOG_ERROR("Find HvlpGetReferenceTimeUsingTscPage Failed!");
        return FALSE;
    }
    ctx->HvlpGetReferenceTimeUsingTscPage = (char*)(RefHvlpGetReferenceTimeUsingTscPageAddress) + 7 + *(int*)((char*)(RefHvlpGetReferenceTimeUsingTscPageAddress) + 3);
    LOG_INFO("HvlGetReferenceTimeUsingTscPage is <0x%llX>.", ctx->HvlpGetReferenceTimeUsingTscPage);
    if (!ctx->HvlpGetReferenceTimeUsingTscPage)
    {
        return FALSE;
    }
    
    LOG_INFO("HvlGetReferenceTimeUsingTscPage value is <0x%llX>.", *(PULONG64)(ctx->HvlpGetReferenceTimeUsingTscPage));

    //
    // Find HalpPerformanceCounter.
    //
    ULONG64 RefHalpPerformanceCounterAddress = FindPatternImage(
        ctx->NtoskrnlBase,
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\xf9\x48\x85\xc0\x74\x00\x83\xb8",
        "xxx????xxxxxxx?xx",
        ".text");
    if (!RefHalpPerformanceCounterAddress)
    {
        LOG_ERROR("Find HalpPerformanceCounter Failed! ");
        return FALSE;
    }

    ctx->HalpPerformanceCounter = (char*)(RefHalpPerformanceCounterAddress)+7 + *(int*)((char*)RefHalpPerformanceCounterAddress + 3);
    LOG_INFO("HalpPerformanceCounter is <0x%llX>.", ctx->HalpPerformanceCounter);
    if (!ctx->HvlpReferenceTscPage)
    {
        return FALSE;
    }
    LOG_INFO("HalpPerformanceCounter Value is <0x%llX>.", *(PULONG64)(ctx->HalpPerformanceCounter));

    ULONG64  RefHalpOriginalPerformanceCounterAddress = FindPatternImage(
        ctx->NtoskrnlBase,
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x3b\x00\x0f\x85\x00\x00\x00\x00\xA0",
        "xxx????xx?xx????x",
        ".text");
    if (!RefHalpOriginalPerformanceCounterAddress)
    {
        RefHalpOriginalPerformanceCounterAddress = FindPatternImage(
            ctx->NtoskrnlBase,
            "\x48\x8b\x0d\x00\x00\x00\x00\x4c\x00\x00\x00\x00\x48\x3b\xf1",
            "xxx????x????xxx",
            ".text");
        if (!RefHalpOriginalPerformanceCounterAddress)
        {
            LOG_ERROR("Find HalpOriginalPerformanceCounter Failed!");
            return FALSE;
        }
    }

    ctx->HalpOriginalPerformanceCounter = ((char*)RefHalpOriginalPerformanceCounterAddress + 7) + *(int*)((char*)RefHalpOriginalPerformanceCounterAddress + 3);
    LOG_INFO("HalpOriginalPerformanceCounter is <0x%llX>.", ctx->HalpOriginalPerformanceCounter);
    if (!ctx->HalpOriginalPerformanceCounter)
    {
        return FALSE;
    }
    LOG_INFO("HalpOriginalPerformanceCounter value is <0x%llX>.", *(PULONG64)(ctx->HalpOriginalPerformanceCounter));

    ctx->HalpPerformanceCounterType = (ULONG*)((ULONG_PTR)(*(PVOID*)ctx->HalpPerformanceCounter) + HALP_PERFORMANCE_COUNTER_TYPE_OFFSET);
    if (!ctx->HalpPerformanceCounterType)
    {
        LOG_ERROR("m_HalpPerformanceCounterType is Null!");
        return FALSE;
    }

    // Is the physical machine?
    if (*ctx->HalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE)
    {
        ctx->VmHalpPerformanceCounterType = *((char*)RefHalpPerformanceCounterAddress + 21);
        LOG_INFO("HalpPerformanceCounterType In Virtual Machine Value is <0x%x>.", ctx->VmHalpPerformanceCounterType);

        ctx->HalpOriginalPerformanceCounterCopy = ExAllocatePool(NonPagedPool, 0xFF);
        if (!ctx->HalpOriginalPerformanceCounterCopy)
        {
            LOG_ERROR("Allocate HalpOriginalPerformanceCounterCopy Failed!");
            return FALSE;
        }

        RtlZeroMemory((PVOID)ctx->HalpOriginalPerformanceCounterCopy, 0xFF);

        *(PULONGLONG)((ULONG64)ctx->HalpOriginalPerformanceCounterCopy + HALP_PERFORMANCE_COUNTER_BASE_RATE_OFFSET) = HALP_PERFORMANCE_COUNTER_BASE_RATE;
        *(PULONG)((ULONG64)ctx->HalpOriginalPerformanceCounterCopy + HALP_PERFORMANCE_COUNTER_TYPE_OFFSET) = HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE;
        LOG_INFO("HalpOriginalPerformanceCounterCopy£º<0x%llX>.", ctx->HalpOriginalPerformanceCounterCopy);
    }

    ctx->InitFlg = TRUE;
    return TRUE;
}

BOOLEAN IHookProAddHookFunction(PCHAR FuncName, PVOID FakeFuncAddr)
{
    ANSI_STRING as = RTL_CONSTANT_STRING(FuncName);
    UNICODE_STRING us;

    IHookProContext* ctx = &g_IHookProContext;

    if (!ctx->InitFlg)
    {
        LOG_ERROR("Dont Initialize.");
        return FALSE;
    }

    RtlAnsiStringToUnicodeString(&us, &as, FALSE);

    PVOID OriginalAddr = MmGetSystemRoutineAddress(&us);
    if (!OriginalAddr)
    {
        LOG_ERROR("Get hook function address error.");
        return FALSE;
    }

    ctx->lstHook[ctx->HookedFunNum].FakeFuncAddr = FakeFuncAddr;
    ctx->lstHook[ctx->HookedFunNum].OriginalAddr = OriginalAddr;
    ctx->HookedFunNum++;

    LOG_INFO("Hook function <id:%d> name:<%Ws> Origin Addr:<0x%p> Fake Addr:<0x%p>. ",
        ctx->HookedFunNum - 1,
        us,
        OriginalAddr,
        FakeFuncAddr);

    return TRUE;
}

BOOLEAN IHookProStart()
{
    IHookProContext* ctx = &g_IHookProContext;

    if (!MmIsAddressValid(ctx->GetCpuClock))
    {
        LOG_ERROR("GetCpuClock address vaild.");
        return FALSE;
    }

    ctx->OriginalGetCpuClockValue = (ULONG64)(*ctx->GetCpuClock);

    if (ctx->BuildNumber <= 18363) // win 7 -> win10 1909
    {
        LOG_INFO("GetCpuClock Is 0x%p", *ctx->GetCpuClock);
        *ctx->GetCpuClock = (PVOID)FakeGetCpuClock;                // replace function.
        LOG_INFO("Update GetCpuClock Is 0x%p", *ctx->GetCpuClock);
    }
    else
    {
        *ctx->GetCpuClock = (PVOID)2;
        LOG_INFO("Update GetCpuClock Is 0x%p", *ctx->GetCpuClock);

        ctx->OriginalHvlGetQpcBias = (pfnHvlGetQpcBias)(*((PULONG64)ctx->HvlGetQpcBias));
    }
    return TRUE;
}

BOOLEAN IHookProStop()
{
    return TRUE;
}
