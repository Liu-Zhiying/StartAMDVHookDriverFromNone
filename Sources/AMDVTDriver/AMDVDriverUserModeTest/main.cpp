#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "AMDVDriverSDK.h"

void SyscallCallback(GenericRegisters& guestRegisters, StackDump& stackDump, UINT32 pid, PVOID param)
{
	printf("Syscall PID = %u\n", pid);
}

int main()
{
	printf("Process Id = %d\n", GetCurrentProcessId());

	SetLStartCallbackParam param = {};
	param.callback = SyscallCallback;
	param.param = 0;

	printf("Syacall hook call register %s\n", AMDVDriverInterface::SetSyscallHookCallback(&param) ? "success" : "failed");

	system("pause");
}