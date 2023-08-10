#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"

//分配的新页表内存信息
typedef struct _PAGE_TABLE_INFO
{
	//映射的虚拟内存
	PTR_TYPE virtAddressMapping;
	//页表自己的虚拟内存
	PTR_TYPE virtAddressThis;
	//页表自己的物理内存
	PTR_TYPE phyAddressThis;
} PT_INFO;

//VT驱动的页表全局数据
typedef struct _PAGE_TABLE_GLOBAL_INFO
{
	//PXE基址
	PTR_TYPE pPxe;
	//Windows 分配 分页内存是按照 页面分的 所以这里 存储新页表信息 的时候 会按照 页面 为单位利用
	//比如普通的4k页内存，页头部放双向链表除外，其余部分尽可能放 PT_INFO 数据
	PTR_TYPE pArrInfoList;
	//锁定标记
	volatile LONG lockFlag;
} PT_G_INFO;

//这三个用于提取页表项的数据
//关于页表项的结构 内存映射 自映射 等等 可以 google "x86-64 page mapping" , "x86-64 page table entry structure" 和 "self refenerce"
//现在只用了第一个，后面两个大概率也要用，先留着
//从页表项目中拿到物理地址
#define GET_PHY_BASEARRD_IN_PAGETABLE(item) (((PTR_TYPE)(item)) & 0x7FFFFFF000)
//页表项目是否映射内存
#define IS_PAGETABLE_ITEM_ACCESSABLE(item) (((PTR_TYPE)(item)) & 0x20)
//页表项目的数据是否启用（如果这个判断失败，前两个（和其他页表项数据）全部作废）
#define IS_PAGETABLE_ITEM_PRESENT(item) (((PTR_TYPE)(item)) & 0x1)

//获取页表基地址（虚拟地址）（从Windows 10的某个版本开始微软对页表基址进行了随机化处理）
//Newbluepill中使用的是固定的页表地址——过时了
//直接拿到pxe地址就行，其他的见函数实现结尾的输出的那一堆KdPrint
void GetPageTableBaseVirtualAddress(PTR_TYPE* pPxeOut);
//初始化新页表
NTSTATUS InitGlobalNewPageTableInfo(PT_G_INFO* pPtGInfo);
//分配新页表信息块
NTSTATUS AllocPageTableInfoBlock(PT_G_INFO* pPtGInfo, PVOID* pNewBlockOut);
//把新页表信息块加入页表信息块链表
void AttachPageTableInfoBlockToList(PT_G_INFO* pPtGInfo, PVOID pBlock);
//从页表信息块链表删除把新页表信息块
BOOLEAN DetachPageTableInfoBlockToList(PT_G_INFO* pPtGInfo, PVOID pBlock);
//释放页表信息块
void FreePageTableInfoBlock(const PT_G_INFO* pPtGInfo, PVOID pBlock);
//销毁页表信息块链表
void DestroyPageTableInfoBlockList(PT_G_INFO* pPtGInfo);
//插入页表信息块，注意没有自动分配功能，添加信息块要调用 AllocPageTableInfoBlock
BOOLEAN InsertPageTableInfo(PT_G_INFO* pPtGInfo, const PT_INFO* pPtInfo);
//删除页表信息块
BOOLEAN RemovePageTableInfo(PT_G_INFO* pPtGInfo, const PT_INFO* pPtInfo);

#endif
