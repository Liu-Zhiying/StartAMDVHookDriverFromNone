#include "PageTable.h"
#include <intrin.h>

//页表项标志位判断
//见https://www.iaik.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/
//这个判断的方式会修改
#define GET_PHY_BASEARRD_IN_PAGETABLE(item) (((PTR_TYPE)(item)) & 0x7FFFFFF000)
//页表项目是否映射内存
#define IS_PAGETABLE_ITEM_ACCESSABLE(item) (((PTR_TYPE)(item)) & 0x20)
//页表项目的数据是否启用（如果这个判断失败，前两个（和其他页表项数据）全部作废）
#define IS_PAGETABLE_ITEM_PRESENT(item) (((PTR_TYPE)(item)) & 0x1)

const ULONG ptTag = MAKE_TAG('p', 't', 'm', ' ');

//封装一下Windows内核内存分配函数
#pragma code_seg()
PVOID AllocNonPagedMem(SIZE_T byteCnt)
{
#ifdef _BUILD_WIN_2004
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, byteCnt, ptTag);
#else
	return ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, byteCnt, ptTag);
#endif
}

#pragma code_seg()
void FreeNonPagedMem(PVOID pMem)
{
	ExFreePoolWithTag(pMem, ptTag);
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
