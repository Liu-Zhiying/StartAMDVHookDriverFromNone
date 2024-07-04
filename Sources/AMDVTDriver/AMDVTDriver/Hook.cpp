#include "Hook.h"

extern "C" PTR_TYPE LStarHookCallback;
extern "C" PTR_TYPE OldLStarEntry;
extern "C" void LStarHookEntry();

void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback)
{
	LStarHookCallback = pCallback;
	OldLStarEntry = oldEntry;
}

PTR_TYPE GetLStarHookEntry()
{
	return (PTR_TYPE)LStarHookEntry;
}