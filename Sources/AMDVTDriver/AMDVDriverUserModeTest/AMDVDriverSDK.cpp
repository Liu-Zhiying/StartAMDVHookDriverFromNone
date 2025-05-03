#include "AMDVDriverSDK.h"

PVOID UserLStarCallbackEntry(PVOID param)
{
	LStarCallbackArgsPack* pack = (LStarCallbackArgsPack*)param;
	pack->callback(pack->guestRegisters, pack->stackDump, pack->pid, pack->param);
	return NULL;
}
