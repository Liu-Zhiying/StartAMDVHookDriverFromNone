#include "Basic.h"

extern "C" PTR_TYPE OldSysCallFunctionAddr = NULL;

extern "C" void SysCallHookLog()
{
	KdPrint(("Hook OK!\n"));
}