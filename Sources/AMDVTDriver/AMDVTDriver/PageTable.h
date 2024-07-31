#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"
#include "SVM.h"

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

//见SimpleSVMHook项目 https://github.com/tandasat/SimpleSvmHook/blob/master/SimpleSvmHook/Svm.hpp
typedef union
{
	UINT64 data;
	struct
	{
		//Vaild
		UINT64 present : 1;                   // [0]
		//Write
		UINT64 writeable : 1;                   // [1]
		//User
		UINT64 userAccesss : 1;                    // [2]
		//Reserved
		UINT64 reserved : 1;                // [3]
		//Execute
		UINT64 execute : 1;                 // [4]
		//Reserved2
		UINT64 reserved2 : 27;              // [5:31]
		//GuestPhysicalAddress
		UINT64 guestPhysicalAddress : 1;    // [32]
		//GuestPageTables
		UINT64 guestPageTables : 1;         // [33]
	} fields;
} NpfExitInfo1;

struct PageTableLevel4
{
	typedef PageTableLevel4Entry EntryType;
	PageTableLevel4Entry entries[0x200];
};

struct PageTableLevel123
{
	typedef PageTableLevel123Entry EntryType;
	PageTableLevel123Entry entries[0x200];
};

struct PageTableRecord
{
	PTR_TYPE pVirtAddr;
	PTR_TYPE pPhyAddr;
	#pragma code_seg()
	PageTableRecord() : pVirtAddr(NULL), pPhyAddr(NULL) {}
	#pragma code_seg()
	PageTableRecord(PTR_TYPE _pVirtAddr,PTR_TYPE _pPhyAddr) : pVirtAddr(_pVirtAddr), pPhyAddr(_pPhyAddr) {}
	#pragma code_seg()
	~PageTableRecord() {}
};

template<SIZE_TYPE bucketCnt>
class PageTableRecordBacket
{
	KernelVector<PageTableRecord> data[bucketCnt];

	static SIZE_TYPE GetBucketIdx(PTR_TYPE pa)
	{
		return (pa >> 12) % bucketCnt;
	}

public:
	#pragma code_seg()
	PageTableRecordBacket() {}
	#pragma code_seg()
	PageTableRecordBacket(PageTableRecordBacket&& other)
	{
		*this = static_cast<PageTableRecordBacket&&>(other);
	}
	#pragma code_seg()
	PageTableRecordBacket& operator=(PageTableRecordBacket&& other)
	{
		for (SIZE_TYPE i = 0; i < bucketCnt; i++)
			data[i] = static_cast<KernelVector<PageTableRecord>&&>(other.data[i]);
		return *this;
	}

	#pragma code_seg()
	SIZE_TYPE Length() const
	{
		SIZE_TYPE result = 0;
		for (auto& bucket : data)
			result += bucket.Length();
		return result;
	}
	#pragma code_seg()
	void PushBack(const PageTableRecord& record)
	{
		data[GetBucketIdx(record.pPhyAddr)].PushBack(record);
	}
	#pragma code_seg()
	PTR_TYPE FindVaFromPa(PTR_TYPE pa) const
	{
		const KernelVector<PageTableRecord>& bucket = data[GetBucketIdx(pa)];
		for (SIZE_TYPE idx = 0; idx < bucket.Length(); ++idx)
		{
			if (bucket[idx].pPhyAddr == pa)
				return bucket[idx].pVirtAddr;
		}
		return (PTR_TYPE)INVALID_ADDR;
	}
	#pragma code_seg()
	void Clear()
	{
		for (auto& bucket : data)
			bucket.Clear();
	}
	#pragma code_seg()
	const PageTableRecord& operator[](SIZE_TYPE idx) const
	{
		KernelVector<PageTableRecord>* pBucket = NULL;
		SIZE_TYPE cnt = 0;
		for (auto& bucket : data)
		{
			if (cnt > idx)
				break;
			if (idx - cnt < bucket.Length())
			{
				pBucket = &bucket;
				break;
			}
			cnt += bucket.Length();
		}
		if (pBucket == NULL)
			KeBugCheck(MEMORY_MANAGEMENT);
		return (*pBucket)[idx - cnt];
	}
	#pragma code_seg()
	PageTableRecord& operator[](SIZE_TYPE idx)
	{
		KernelVector<PageTableRecord>* pBucket = NULL;
		SIZE_TYPE cnt = 0;
		for (auto& bucket : data)
		{
			if (cnt > idx)
				break;
			if (idx - cnt < bucket.Length())
			{
				pBucket = &bucket;
				break;
			}
			cnt += bucket.Length();
		}
		if (pBucket == NULL)
			KeBugCheck(MEMORY_MANAGEMENT);
		return (*pBucket)[idx - cnt];
	}
};

using PageTableRecords = PageTableRecordBacket<0x20>;

//每个核心的NPT页表管理器
class CoreNptPageTableManager
{
	PTR_TYPE pNptPageTable;
	PageTableRecords level123Records;
	PageTableRecords level4Records;

public:
	#pragma code_seg()
	CoreNptPageTableManager(CoreNptPageTableManager&& other)
	{
		*this = static_cast<CoreNptPageTableManager&&>(other);
	}
	#pragma	code_seg()
	CoreNptPageTableManager& operator=(CoreNptPageTableManager&& other)
	{
		pNptPageTable = other.pNptPageTable;
		level123Records = static_cast<PageTableRecords&&>(other.level123Records);
		level4Records = static_cast<PageTableRecords&&>(other.level4Records);
		other.pNptPageTable = INVALID_ADDR;
		return *this;
	}
	#pragma code_seg()
	CoreNptPageTableManager() : pNptPageTable(INVALID_ADDR) {}
	#pragma code_seg()
	~CoreNptPageTableManager() { Deinit(); }
	NTSTATUS FixPageFault(PTR_TYPE startAddr, PTR_TYPE endAddr);
	void Deinit();
	NTSTATUS BuildNptPageTable();
	#pragma code_seg()
	PTR_TYPE GetNptPageTable() const { return pNptPageTable; }
};

//页表管理器
class PageTableManager : public IManager, public INpfInterceptPlugin, public INCr3Provider
{
	PTR_TYPE pSystemPxe;
	CoreNptPageTableManager* corePageTables;
	SIZE_TYPE pageTableCnt;

public:
	#pragma code_seg("PAGE")
	PageTableManager() : pSystemPxe(NULL), corePageTables(NULL), pageTableCnt(0) { PAGED_CODE(); }
	virtual bool HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	virtual PVOID GetNCr3ForCore(UINT32 cpuIdx) override;
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg()
	const CoreNptPageTableManager* GetCoreNptPageTables() const { return corePageTables; }
	SIZE_TYPE GetCoreNptPageTablesCnt() const { return pageTableCnt; }
	#pragma code_seg()
	virtual ~PageTableManager() { PageTableManager::Deinit(); }
};

#endif
