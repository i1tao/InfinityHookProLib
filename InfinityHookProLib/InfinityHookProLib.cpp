#include "InfinityHookProLib.h"

bool InfHookProLib::Initialize()
{
}

bool InfHookProLib::AddHookFunction(char* FuncName, PVOID HookAddress)
{
	ANSI_STRING as = RTL_CONSTANT_STRING(FuncName);
	UNICODE_STRING us;

	RtlAnsiStringToUnicodeString(&us, &as,false);
	auto FuncAddress = MmGetSystemRoutineAddress(&us);

    if (!FuncAddress)
    {
        return false;
    }
}

bool InfHookProLib::Start()
{
}

bool InfHookProLib::Stop()
{
}
