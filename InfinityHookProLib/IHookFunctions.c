#include "IHookFunctions.h"

#include <intrin.h>
#include <ntddk.h>

#include "IHookFunctions.h"

#include "Defs.h"


extern IHookProContext g_IHookProContext;

void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID* pSsdtAddress);

ULONG64 FakeGetCpuClock()
{
    if (ExGetPreviousMode() == KernelMode)
    {
        __rdtsc();
    }

    PKTHREAD pCurrentThread = (PKTHREAD)__readgsqword(0x188);

    UINT32 nCallIndex = 0;
    if (g_IHookProContext.BuildNumber <= 7601)
    {
        nCallIndex = *(unsigned int*)((ULONG64)pCurrentThread + 0x1f8);
    }
    else
    {
        nCallIndex = *(unsigned int*)((ULONG64)pCurrentThread + 0x80);
    }

    void** pStackMax = (void**)__readgsqword(0x1a8);
    void** pStackFrame = (void**)_AddressOfReturnAddress();

    for (void** pStackCurrent = pStackMax; pStackCurrent > pStackFrame; --pStackCurrent)
    {
#define INFINITYHOOK_MAGIC_501802 ((unsigned long)0x501802)
#define INFINITYHOOK_MAGIC_601802 ((unsigned long)0x601802)
#define INFINITYHOOK_MAGIC_F33 ((unsigned short)0xF33)

        unsigned long* pValue1 = (unsigned long*)pStackCurrent;
        if ((*pValue1 != INFINITYHOOK_MAGIC_501802) &&
            (*pValue1 != INFINITYHOOK_MAGIC_601802))
        {
            continue;
        }

        --pStackCurrent;

        unsigned short* pValue2 = (unsigned short*)pStackCurrent;
        if (*pValue2 != INFINITYHOOK_MAGIC_F33)
        {
            continue;
        }

        for (; pStackCurrent < pStackMax; ++pStackCurrent)
        {
            // 检查是否在ssdt表内
            PULONG64 pllValue = (PULONG64)pStackCurrent;
            if (!(PAGE_ALIGN(*pllValue) >= g_IHookProContext.SystemCallTable &&
                PAGE_ALIGN(*pllValue) < (void*)((ULONG64)g_IHookProContext.SystemCallTable + (PAGE_SIZE * 2))))

            {
                continue;
            }

            // 现在已经确定是ssdt函数调用了
            // 这里是找到KiSystemServiceExit
            void** pSystemCallFunction = &pStackCurrent[9];

            InfinityCallback(nCallIndex, pSystemCallFunction);

            break;
        }
        break;
    }


    return __rdtsc();
}

ULONG64 FakeHvlGetQpcBias()
{
    return *((PULONG64)(*((PULONG64)g_IHookProContext.HvlpReferenceTscPage)) + 3);
}



void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID* pSsdtAddress)
{
    // https://hfiref0x.github.io/
    UNREFERENCED_PARAMETER(nCallIndex);
    if (pSsdtAddress)
    {
        for (int i = 0; i < g_IHookProContext.HookedFunNum; i++)
        {
            if (*pSsdtAddress == g_IHookProContext.lstHook[i].OriginalAddr)
            {
                *pSsdtAddress = g_IHookProContext.lstHook[i].FakeFuncAddr;
            }
        }

    }

}
