#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"

//“≥±Ìπ‹¿Ì∆˜
class PageTableManager : public IManager
{
	PTR_TYPE pSystemPxe;
	KSPIN_LOCK operationLock;
public:
	#pragma code_seg("PAGE")
	PageTableManager() : pSystemPxe(NULL) { PAGED_CODE(); KeInitializeSpinLock(&operationLock); }
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
};

#endif
