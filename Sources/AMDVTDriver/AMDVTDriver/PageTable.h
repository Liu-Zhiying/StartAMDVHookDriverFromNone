#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"
#include "SVM.h"

constexpr ULONG PT_TAG = MAKE_TAG('p', 't', 'm', ' ');

/*
//����ʹ�õĽṹ
//��https://www.iaik.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/
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
*/

//�µĽṹ�������ýṹ��������pagePpn��40λ��ԭ���amd�ֲᡣamd�ֲ���reserved1����Ҳ��pagePpn���ݣ�Ȩ��λҲ���˲����޸�
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
		UINT64 ignored2 : 6;
		UINT64 pagePpn : 40;
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
		UINT64 pagePpn : 40;
		UINT64 ignored1 : 11;
		UINT64 executionDisabled : 1;
	} fields;
} PageTableLevel123Entry;

//��SimpleSVMHook��Ŀ https://github.com/tandasat/SimpleSvmHook/blob/master/SimpleSvmHook/x86_64.hpp
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

//��SimpleSVMHook��Ŀ https://github.com/tandasat/SimpleSvmHook/blob/master/SimpleSvmHook/Svm.hpp
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
//LEVEL 4ҳ��
struct PageTableLevel4
{
	typedef PageTableLevel4Entry EntryType;
	PageTableLevel4Entry entries[0x200];
};
//LEVE 1 2 3ҳ��
struct PageTableLevel123
{
	typedef PageTableLevel123Entry EntryType;
	PageTableLevel123Entry entries[0x200];
};

//�����NPTҳ���¼��Ŀ
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

//NPTҳ���¼������¼���з�����ʼ����NPTҳ��������ַ�������ַ
//ʹ�ü򵥵Ĺ�ϣ��ʵ�֣���ѯ�ٶȻ��һЩ
template<SIZE_TYPE bucketCnt>
class PageTableRecordBacket
{
	KernelVector<PageTableRecord, PT_TAG> data[bucketCnt];

	static SIZE_TYPE GetBucketIdx(PTR_TYPE pa)
	{
		return (pa >> 12) % bucketCnt;
	}

public:
	#pragma code_seg()
	PageTableRecordBacket() {}
	//�ƶ�����Ϳ���
	#pragma code_seg()
	PageTableRecordBacket(PageTableRecordBacket&& other)
	{
		*this = static_cast<PageTableRecordBacket&&>(other);
	}
	#pragma code_seg()
	PageTableRecordBacket& operator=(PageTableRecordBacket&& other)
	{
		if (&other != this)
		{
			for (SIZE_TYPE i = 0; i < bucketCnt; i++)
				data[i] = static_cast<KernelVector<PageTableRecord, PT_TAG>&&>(other.data[i]);
		}
		return *this;
	}
	//��Ŀ����
	#pragma code_seg()
	SIZE_TYPE Length() const
	{
		SIZE_TYPE result = 0;
		for (auto& bucket : data)
			result += bucket.Length();
		return result;
	}
	//�����Ŀ
	#pragma code_seg()
	void PushBack(const PageTableRecord& record)
	{
		data[GetBucketIdx(record.pPhyAddr)].PushBack(record);
	}
	//ͨ�������ַѰ����Ŀ����
	#pragma code_seg()
	PTR_TYPE FindVaFromPa(PTR_TYPE pa) const
	{
		const KernelVector<PageTableRecord, PT_TAG>& bucket = data[GetBucketIdx(pa)];
		for (SIZE_TYPE idx = 0; idx < bucket.Length(); ++idx)
		{
			if (bucket[idx].pPhyAddr == pa)
				return bucket[idx].pVirtAddr;
		}
		return (PTR_TYPE)INVALID_ADDR;
	}
	//ɾ��������Ŀ
	#pragma code_seg()
	void Clear()
	{
		for (auto& bucket : data)
			bucket.Clear();
	}
	//ͨ��������ȡ��Ŀ��ֻ����
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
		{
			__debugbreak();
			KeBugCheck(MEMORY_MANAGEMENT);
		}
		return (*pBucket)[idx - cnt];
	}
	//ͨ��������ȡ��Ŀ����д��
	#pragma code_seg()
	PageTableRecord& operator[](SIZE_TYPE idx)
	{
		KernelVector<PageTableRecord, PT_TAG>* pBucket = NULL;
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
		{
			__debugbreak();
			KeBugCheck(MEMORY_MANAGEMENT);
		}
		return (*pBucket)[idx - cnt];
	}
	//ͨ�������ַɾ����Ŀ
	#pragma code_seg()
	bool RemoveByPa(PTR_TYPE pa)
	{
		SIZE_TYPE idx = GetBucketIdx(pa);
		KernelVector<PageTableRecord, PT_TAG>& bucket = data[idx];
		for (SIZE_TYPE i = 0; i < bucket.Length(); ++i)
		{
			if (bucket[i].pPhyAddr == pa)
			{
				bucket.Remove(i);
				return true;
			}
		}
		return false;
	}
};

using PageTableRecords3 = PageTableRecordBacket<0x1>;
using PageTableRecords2 = PageTableRecordBacket<0x10>;
using PageTableRecords1 = PageTableRecordBacket<0x40>;

class CoreNptPageTableManager;

//ҳ�������
class PageTableManager : public IManager, public INpfInterceptPlugin, public INCr3Provider
{
public:
	//ҳ����Ŀ����������������дֻ�ǲ���дlambda���ʽ��������������һ��lambda���ʽ
	class EntrySetter
	{
		PageTableManager* pageTableManager;
	public:
		#pragma code_seg()
		EntrySetter(PageTableManager* _pageTableManager) : pageTableManager(_pageTableManager) { PAGED_CODE(); NT_ASSERT(pageTableManager != NULL); }
		#pragma code_seg()
		void operator()(PageTableLevel123Entry* pEntry, PTR_TYPE pfn, bool isLargePage, UINT32 level) const {
			{
				//level Ϊ 1 2 3
				NT_ASSERT(level < 4 && level > 0);

				PageTableLevel123Entry permission = {};
				permission.data = pageTableManager->GetDefaultPermission(level);

				permission.fields.present = true;
				permission.fields.size = isLargePage;
				permission.fields.pagePpn = pfn;

				*pEntry = permission;
			}
		}
		#pragma code_seg()
		void operator()(PageTableLevel4Entry* pEntry, PTR_TYPE pfn, bool isLargePage, UINT32 level) const {
			{
				UNREFERENCED_PARAMETER(isLargePage);

				//level Ϊ 4
				NT_ASSERT(level == 4);

				PageTableLevel4Entry permission = {};
				permission.data = pageTableManager->GetDefaultPermission(level);
				permission.fields.ignored2 = 0;

				permission.fields.present = true;
				permission.fields.pagePpn = pfn;

				*pEntry = permission;
			}
		}
	};
private:
	PTR_TYPE pSystemPxe;
	CoreNptPageTableManager* corePageTables;
	SIZE_TYPE pageTableCnt;
	PageTableLevel4Entry defaultPermissionLevel4;
	PageTableLevel123Entry defaultPermissionLevel3;
	PageTableLevel123Entry defaultPermissionLevel2;
	PageTableLevel123Entry defaultPermissionLevel1;
	EntrySetter entrySetter;
public:
	#pragma code_seg("PAGE")
	PageTableManager() : pSystemPxe(NULL), corePageTables(NULL), pageTableCnt(0), entrySetter(this)
	{
		PAGED_CODE();

		//����Ĭ��Ȩ��
		defaultPermissionLevel3 = {};
		defaultPermissionLevel3.fields.writeable = true;
		defaultPermissionLevel3.fields.userAccess = true;

		defaultPermissionLevel1 = defaultPermissionLevel2 = defaultPermissionLevel3;

		defaultPermissionLevel4 = {};
		defaultPermissionLevel4.fields.writeable = true;
		defaultPermissionLevel4.fields.userAccess = true;
	}
	void SetDefaultPermission(UINT64 permission, UINT32 level);
	UINT64 GetDefaultPermission(UINT32 level) const;
	virtual bool HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	virtual PVOID GetNCr3ForCore(UINT32 cpuIdx) override;
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg()
	CoreNptPageTableManager* GetCoreNptPageTables() { return corePageTables; }
	SIZE_TYPE GetCoreNptPageTablesCnt() const { return pageTableCnt; }
	#pragma code_seg("PAGE")
	virtual ~PageTableManager() { PAGED_CODE(); Deinit(); }
};

//ÿ�����ĵ�NPTҳ�������
class CoreNptPageTableManager
{
	//����ҳ��������ַ
	PTR_TYPE pNptPageTableVa;
	//����ҳ��������ַ
	PTR_TYPE pNptPageTablePa;
	PageTableRecords3 level3Records;
	PageTableRecords2 level2Records;
	PageTableRecords1 level1Records;
	PageTableManager::EntrySetter* pEntrySetter;

public:
	//ɾ��Ĭ�Ϲ���
	CoreNptPageTableManager() = delete;
	//ʹ��PageTableManager::EntrySetter���죬PageTableManager::EntrySetter��������ҳ���Ĭ��Ȩ��
	CoreNptPageTableManager(PageTableManager::EntrySetter* _pEntrySetter) : pNptPageTableVa(INVALID_ADDR), pEntrySetter(_pEntrySetter), pNptPageTablePa(INVALID_ADDR) {}
	//�ƶ�����
	#pragma code_seg()
	CoreNptPageTableManager(CoreNptPageTableManager&& other)
	{
		*this = static_cast<CoreNptPageTableManager&&>(other);
	}
	//�ƶ�����
	#pragma	code_seg()
	CoreNptPageTableManager& operator=(CoreNptPageTableManager&& other)
	{
		if (&other != this)
		{
			pEntrySetter = other.pEntrySetter;
			pNptPageTableVa = other.pNptPageTableVa;
			level3Records = static_cast<PageTableRecords3&&>(other.level3Records);
			level2Records = static_cast<PageTableRecords2&&>(other.level2Records);
			level1Records = static_cast<PageTableRecords1&&>(other.level1Records);
			other.pNptPageTableVa = INVALID_ADDR;
		}
		return *this;
	}
	#pragma code_seg("PAGE")
	~CoreNptPageTableManager() { PAGED_CODE(); Deinit(); }
	//ӳ��ȱҳ����
	NTSTATUS FixPageFault(PTR_TYPE startAddr, PTR_TYPE endAddr, bool usingLargePage);
	//isUsing Ϊ false ����ԭ��ҳ
	NTSTATUS UsingSmallPage(PTR_TYPE phyAddr, bool isUsing);
	//Сҳӳ�亯������ͬ��FixPageFault(begPhyAddr, endPhyAddr, false)
	NTSTATUS MapSmallPageByPhyAddr(PTR_TYPE begPhyAddr, PTR_TYPE endPhyAddr);
	//����Сҳ�����������ַ
	NTSTATUS SwapSmallPagePpn(PTR_TYPE phyAddr1, PTR_TYPE phyAddr2, UINT32 level);
	//��ȡָ�������ַ��Ӧ��NPTҳ�������PPN��Ӧ�������ַ
	NTSTATUS GetNptFinalAddrForPhyAddr(PTR_TYPE phyAddr, PTR_TYPE& pNptFinalAddr, PTR_TYPE& level);
	//�޸�������ײ�ҳ���Ȩ��
	void ChangeAllEndLevelPageTablePermession(PageTableLevel123Entry entry);
	//�޸��ض�ҳ���ֵ
	NTSTATUS ChangePageTableEntryPermession(PTR_TYPE pa, PageTableLevel123Entry entry, UINT32 level);
	void Deinit();
	NTSTATUS BuildNptPageTable();
	#pragma code_seg()
	PTR_TYPE GetNptPageTableVa() const { return pNptPageTableVa; }
	PTR_TYPE GetNptPageTablePa() const { return pNptPageTablePa; }
	//ͨ�������ַҲҳ����Ѱ��ҳ���������ַ
	PVOID FindPageTableByPhyAddr(PTR_TYPE pa, UINT32 level) const;
};

//��ѯ��ǰCR3������ҳ���������ַ
void GetSysPXEVirtAddr(PTR_TYPE* pPxeOut, PTR_TYPE pxePhyAddr);

#endif
