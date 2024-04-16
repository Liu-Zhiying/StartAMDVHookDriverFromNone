#include "PageTable.h"
#include <intrin.h>

const ULONG PT_TAG = MAKE_TAG('p', 't', 'm', ' ');

//见https://www.iaik.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/
//这个结构体的size成员我改成了is_large_page
typedef struct
{
	UINT64 present : 1;				//这个页表项是否有效
	UINT64 writeable : 1;			//是否可写
	UINT64 user_access : 1;			//可以被Ring3访问
	UINT64 write_through : 1;		//写入是否缓存
	UINT64 cache_disabled : 1;		//禁止缓存
	UINT64 accessed : 1;			//这一页可以访问
	UINT64 ignored_3 : 1;			//没有作用
	UINT64 is_large_page : 1;		//是否大页（2mb页）
	UINT64 ignored_2 : 4;			//没有作用
	UINT64 page_ppn : 28;			//物理地址（要右移12位才是真实物理地址）
	UINT64 reserved_1 : 12;			//必须为0
	UINT64 ignored_1 : 11;			//没有作用
	UINT64 execution_disabled : 1;	//禁止执行位
} PageTableItem;

//从页表项中取得物理地址
inline PTR_TYPE GetPhyAddrFromPageTableItem(const PageTableItem* pItem)
{
	return ((PTR_TYPE)pItem->page_ppn) << 12;
}

//封装一下Windows内核内存分配函数
#pragma code_seg()
PVOID AllocNonPagedMem(SIZE_T byteCnt)
{
#ifdef _BUILD_WIN_2004
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, byteCnt, PT_TAG);
#else
	return ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, byteCnt, ptTag);
#endif
}

#pragma code_seg()
void FreeNonPagedMem(PVOID pMem)
{
	ExFreePoolWithTag(pMem, PT_TAG);
}

//获取页表基地址（虚拟地址）
#pragma code_seg("PAGE")
void GetSysPXEVirtAddr(PTR_TYPE* pPxeOut)
{
	PAGED_CODE();
	//读取Cr3物理地址并使用Windows内核函数转换为虚拟地址
	//注意：MmGetVirtualForPhysical被微软标记为保留，除了名字外啥也没提
	PTR_TYPE pxePhyAddr = __readcr3();
	pxePhyAddr &= 0xFFFFFFFFFFFFF000;

	PTR_TYPE testAddr = NULL;
	PTR_TYPE testPhyAddr = NULL;
	BOOLEAN matchedPxe = FALSE;

	//通过测试内存页面和物理地址确认自映射页表编号
	PTR_TYPE index = 0;
	for (index = 0; index < 0x200; index++)
	{
		//构造可能的pxe地址
		testAddr = 0xFFFF000000000000;
		testAddr |= index << 39 | index << 30 | index << 21 | index << 12;

		//确认可以读
		if (MmIsAddressValid((PVOID)testAddr))
		{
			// MmIsAddressValid 只对非分页 但是 页表 一定是 非分页内存 直接通过范围确认在Pxe表内
			testPhyAddr = MmGetPhysicalAddress((PVOID)testAddr).QuadPart;

			if (testPhyAddr == pxePhyAddr)
			{
				matchedPxe = TRUE;
				break;
			}
		}
	}

	if (!matchedPxe)
	{
		*pPxeOut = NULL;
		return;
	}
	
	*pPxeOut = testAddr;
	
	/*

	老版代码，使用了微软的保留API

	PHYSICAL_ADDRESS temp = {};
	temp.QuadPart = (PTR_TYPE)pxePhyAddr;

	PTR_TYPE* pxeVirtualAddr = (PTR_TYPE*)MmGetVirtualForPhysical(temp);
	if (pxeVirtualAddr == NULL)
	{
		*pPxeOut = NULL;
		return;
	}

	*pPxeOut = (PTR_TYPE)pxeVirtualAddr;

	*/

	//显示结果
	KdPrint(("GetWinPageTableVirtualAddr(): PXE: 0x%llx\n", *pPxeOut));
	KdPrint(("GetWinPageTableVirtualAddr(): PPE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFFFE00000));
	KdPrint(("GetWinPageTableVirtualAddr(): PDE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFC0000000));
	KdPrint(("GetWinPageTableVirtualAddr(): PTE: 0x%llx\n", (*pPxeOut) & 0xFFFFFF8000000000));

	return;
}

#pragma code_seg("PAGE")
NTSTATUS PageTableManager::Init()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		//获取Windows页表地址
		//Windows 10 1607之后有页表随机化，确认随机化之后的页表基址
		GetSysPXEVirtAddr(&pSystemPxe);
		if (pSystemPxe == NULL)
		{
			KdPrint(("PageTableManager::Init(): Can not find system PXE virtual address."));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
	} while (false);

	return status;
}

#pragma code_seg("PAGE")
void PageTableManager::Deinit()
{
	PAGED_CODE();
}
