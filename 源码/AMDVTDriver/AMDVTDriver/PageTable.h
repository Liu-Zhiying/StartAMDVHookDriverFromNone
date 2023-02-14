#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"
#include "ReadRegisters.h"

//这三个用于提取页表项的数据
//关于页表项的结构 内存映射 自映射 等等 可以 google "x86-64 page mapping" , "x86-64 page table entry structure" 和 "self refenerce"
//现在只用了第一个，后面两个大概率也要用，先留着
//从页表项目中拿到物理地址
#define GET_PHY_BASEARRD_IN_PAGETABLE(item) (((PTR_TYPE)(item)) & 0x7FFFFFF000)
//页表项目是否映射内存
#define IS_PAGETABLE_ITEM_ACCESSABLE(item) (((PTR_TYPE)(item)) & 0x20)
//页表项目的数据是否启用（如果这个2判断失败，前两个（和其他页表项数据）全部作废）
#define IS_PAGETABLE_ITEM_PRESENT(item) (((PTR_TYPE)(item)) & 0x1)

//获取页表基地址（虚拟地址）（从Windows 10的某个版本开始微软对页表基址进行了随机化处理）
//Newbluepill中使用的是固定的页表地址——过时了
//直接拿到pxe地址就行，其他的见函数实现结尾的输出的那一堆KdPrint
void GetPageTableBaseVirtualAddress(PTR_TYPE* pPxeOut, PTR_TYPE* pageSizeOut);

#endif
