#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"

const PTR_TYPE INVALID_NPT_PAGE_TABLE = (PTR_TYPE)-1;

//见https://www.iaik.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/
typedef union
{
	UINT64 data;
	struct
	{
		UINT64 present : 1;
		UINT64 writeable : 1;
		UINT64 userAccess : 1;
		UINT64 writeThrough : 1;
		UINT64 cacheDisabled : 1;
		UINT64 accessed : 1;
		UINT64 ignored3 : 1;
		UINT64 size : 1; // must be 0
		UINT64 ignored2 : 4;
		UINT64 pagePpn : 28;
		UINT64 reserved1 : 12; // must be 0
		UINT64 ignored1 : 11;
		UINT64 executionDisabled : 1;
	} fields;
} PageTableLevel4Entry;

typedef union
{
	UINT64 data;
	struct
	{
		UINT64 present : 1;
		UINT64 writeable : 1;
		UINT64 userAccess : 1;
		UINT64 writeThrough : 1;
		UINT64 cacheDisabled : 1;
		UINT64 accessed : 1;
		UINT64 dirty : 1;
		UINT64 size : 1;
		UINT64 global : 1;
		UINT64 ignored2 : 3;
		UINT64 pagePpn : 28;
		UINT64 reserved1 : 12; // must be 0
		UINT64 ignored1 : 11;
		UINT64 executionDisabled : 1;
	} fields;
} PageTableLevel123Entry;

//见SimpleSVMHook项目 https://github.com/tandasat/SimpleSvmHook/blob/master/SimpleSvmHook/x86_64.hpp
typedef union
{
	UINT64 data;
	struct
	{
		UINT64 reserved1 : 8;           // [0:7]
		UINT64 bootstrapProcessor : 1;  // [8]
		UINT64 reserved2 : 1;           // [9]
		UINT64 enableX2ApicMode : 1;    // [10]
		UINT64 enableXApicGlobal : 1;   // [11]
		UINT64 apicBase : 24;           // [12:35]
	} fields;
} ApicBase;

struct PageTableLevel4
{
	PageTableLevel4Entry entries[512];
};

struct PageTableLevel23
{
	PageTableLevel123Entry entries[512];
};

//页表管理器
class PageTableManager : public IManager
{
	PTR_TYPE pSystemPxe;
	KMUTEX operationLock;
	PTR_TYPE pNptPageTable;
	KernelVector<PVOID> nptPageTableVirtAddrs;
public:
	#pragma code_seg("PAGE")
	PageTableManager() : pSystemPxe(NULL), pNptPageTable(INVALID_NPT_PAGE_TABLE) { PAGED_CODE(); KeInitializeMutex(&operationLock, 0); }
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	void DeinitImpl();
	#pragma code_seg("PAGE")
	PTR_TYPE GetNtpPageTable();
	#pragma code_seg("PAGE")
	virtual ~PageTableManager() { PAGED_CODE(); PageTableManager::Deinit(); }
};

#endif
