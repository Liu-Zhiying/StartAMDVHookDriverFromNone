#pragma once

#include <ntddk.h>
#include "dbgclient_ioctl.h"



#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)   \
	 (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
	 (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)  \
	 (((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)	 \
	 (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define MINUTES(minutes)	 \
	 (((signed __int64)(minutes)) * SECONDS(60L))

#define HOURS(hours)		 \
	 (((signed __int64)(hours)) * MINUTES(60L))

typedef struct _DEBUG_WINDOW_ENTRY {
	LIST_ENTRY	le;
	PMDL	pWindowMdl;
	DEBUG_WINDOW	DebugWindow;
} DEBUG_WINDOW_ENTRY, *PDEBUG_WINDOW_ENTRY;