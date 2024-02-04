#include "Utils.h"

#include <intrin.h>
#include <ntddk.h>
#include <ntimage.h>

#include "hde/hde64.h"

ULONG64 GetModuleAddress(const char* Name, unsigned long* Size)
{
    ULONG64 Result = 0;
    ULONG Length = 0;
    ULONG Tag = 'VMON';
    NTSTATUS Ntstatus = STATUS_SUCCESS;

    ZwQuerySystemInformation(SystemModuleInformation, &Length, 0, &Length);
    if (!Length)
    {
        return Result;
    }

    PSYSTEM_MODULE_INFORMATION SystemModules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Length, Tag);
    if (!SystemModules)
    {
        return Result;
    }

    Ntstatus = ZwQuerySystemInformation(SystemModuleInformation, SystemModules, Length, 0);
    if (NT_SUCCESS(Ntstatus))
    {
        for (ULONG64 i = 0; i < SystemModules->ulModuleCount; i++)
        {
            PSYSTEM_MODULE_INFORMATION_ENTRY Mod = &SystemModules->Modules[i];
            if (strstr(Mod->ImageName, Name))
            {
                Result = (ULONG64)Mod->Base;
                if (Size)
                {
                    *Size = Mod->Size;
                }
                break;
            }
        }
    }

    ExFreePoolWithTag(SystemModules, Tag);
    return Result;
}

BOOLEAN PatternCheck(const char* pData, const char* szPattern, const char* szMask)
{
    size_t nLen = strlen(szMask);

    for (size_t i = 0; i < nLen; i++)
    {
        if (pData[i] == szPattern[i] || szMask[i] == '?')
            continue;
        else
            return FALSE;
    }

    return TRUE;
}

unsigned long long FindPattern(unsigned long long pAddress, unsigned long nSize, const char* szPattern, const char* szMask)
{
    nSize -= (unsigned long)strlen(szMask);

    for (unsigned long i = 0; i < nSize; i++)
    {
        if (PatternCheck((const char*)pAddress + i, szPattern, szMask))
            return pAddress + i;
    }

    return 0;
}

ULONG64 FindPatternImage(ULONG64 Address, const char* Pattern, const char* Mask, const char* SectionName)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Address;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(Address + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    for (unsigned short i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER Sec = &SectionHeader[i];

        if (strstr((const char*)Sec->Name, SectionName))
        {
            ULONG64 Result = FindPattern(Address + Sec->VirtualAddress, Sec->Misc.VirtualSize, Pattern, Mask);
            if (Result)
            {
                return Result;
            }
        }
    }

    return 0;
}

ULONG64 GetImageSectionAddress(ULONG64 Address, const char* SectionName, PULONG Size)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Address;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(Address + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sec = &SectionHeader[i];

        if (strstr((const char*)sec->Name, SectionName))
        {
            if (Size)
            {
                *Size = sec->SizeOfRawData;
            }
            return (ULONG64)sec + sec->VirtualAddress;
        }
    }

    return 0;
}

PVOID GetSyscallEntry(ULONG64 NtBase)
{
    if (!NtBase)
    {
        return NULL;
    }

#define IA32_LSTAR_MSR 0xC0000082
    PVOID SysCallEntry = (PVOID)__readmsr(IA32_LSTAR_MSR);

    ULONG SecionSize = 0;
    ULONG64 pKVASCODE = GetImageSectionAddress(NtBase, "KVASCODE", &SecionSize);
    if (!pKVASCODE)
    {
        return SysCallEntry;
    }

    if (!(SysCallEntry >= (PVOID)pKVASCODE && SysCallEntry < (PVOID)(pKVASCODE + SecionSize)))
    {
        return SysCallEntry;
    }

    hde64s hdeInfo = {0};
    for (char* pKiSystemServiceUser = (char*)SysCallEntry; ; pKiSystemServiceUser += hdeInfo.len)
    {
        if (!hde64_disasm(pKiSystemServiceUser, &hdeInfo))
        {
            break;
        }

        if (hdeInfo.opcode != 0xE9)
        {
            continue;
        }

        PVOID pPossibleSyscallEntry = (PVOID)((ULONG64)pKiSystemServiceUser + (int)hdeInfo.len + (int)hdeInfo.imm.imm32);
        if (pPossibleSyscallEntry >= (PVOID)pKVASCODE && pPossibleSyscallEntry < (PVOID)((ULONG64)pKVASCODE + SecionSize))
        {
            continue;
        }

        SysCallEntry = pPossibleSyscallEntry;
        break;
    }

    return SysCallEntry;
}