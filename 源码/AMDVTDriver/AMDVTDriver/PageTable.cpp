#include "PageTable.h"

#pragma code_seg()
void GetPageTableBaseVirtualAddress(PTR_TYPE* pPxeOut, PTR_TYPE* pageSizeOut)
{
	//读取Cr3物理地址并使用Windows内核函数转换为虚拟地址
	//注意：MmGetVirtualForPhysical被微软标记为保留，除了名字外啥也没提
	PTR_TYPE pxePhyAddr = ReadCr3();

	PHYSICAL_ADDRESS temp = {};
	temp.QuadPart = (PTR_TYPE)pxePhyAddr;

	PTR_TYPE* pxeVirtualAddr = (PTR_TYPE*)MmGetVirtualForPhysical(temp);
	if (pxeVirtualAddr == NULL)
	{
		*pPxeOut = NULL;
		return;
	}

	//这里开始 根据各级页表 的 LargePage 标志位 判断 Windows 当前的页面大小
	//这里我并没有让Windows开启大页模式（不过操作这种东西，错了肯定炸），在4k页普通模式下测试通过
	*pPxeOut = (PTR_TYPE)pxeVirtualAddr;

	PTR_TYPE pageSize = 0x40000000;
	UINT32 count = 2;

	do
	{
		UINT32 shrParam = (21 + count * 9);
		temp.QuadPart = (PTR_TYPE)pxeVirtualAddr[(*pPxeOut >> shrParam) & 0x1ff];
		temp.QuadPart = GET_PHY_BASEARRD_IN_PAGETABLE(temp.QuadPart);
		pxeVirtualAddr = (PTR_TYPE*)MmGetVirtualForPhysical(temp);
		if (count-- && !(pxeVirtualAddr[(*pPxeOut >> shrParam) & 0x1ff] & 0x80))
			pageSize >>= 9;
		else
			break;
	} while (true);

	*pageSizeOut = pageSize;

	//显示结果
	KdPrint(("PXE: 0x%llx\n", *pPxeOut));
	KdPrint(("PPE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFFFE00000));
	KdPrint(("PDE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFC0000000));
	KdPrint(("PTE: 0x%llx\n", (*pPxeOut) & 0xFFFFFF1000000000));
	KdPrint(("PageSize: 0x%llx\n", pageSize));
	return;
}