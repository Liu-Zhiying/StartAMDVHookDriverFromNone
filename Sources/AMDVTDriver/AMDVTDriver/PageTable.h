#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include "Basic.h"

//�������ҳ���ڴ���Ϣ
typedef struct _PAGE_TABLE_INFO
{
	//ӳ��������ڴ�
	PTR_TYPE virtAddressMapping;
	//ҳ���Լ��������ڴ�
	PTR_TYPE virtAddressThis;
	//ҳ���Լ��������ڴ�
	PTR_TYPE phyAddressThis;
} PT_INFO;

//VT������ҳ��ȫ������
typedef struct _PAGE_TABLE_GLOBAL_INFO
{
	//PXE��ַ
	PTR_TYPE pPxe;
	//Windows ���� ��ҳ�ڴ��ǰ��� ҳ��ֵ� �������� �洢��ҳ����Ϣ ��ʱ�� �ᰴ�� ҳ�� Ϊ��λ����
	//������ͨ��4kҳ�ڴ棬ҳͷ����˫���������⣬���ಿ�־����ܷ� PT_INFO ����
	PTR_TYPE pArrInfoList;
	//�������
	volatile LONG lockFlag;
} PT_G_INFO;

//������������ȡҳ���������
//����ҳ����Ľṹ �ڴ�ӳ�� ��ӳ�� �ȵ� ���� google "x86-64 page mapping" , "x86-64 page table entry structure" �� "self refenerce"
//����ֻ���˵�һ�����������������ҲҪ�ã�������
//��ҳ����Ŀ���õ�������ַ
#define GET_PHY_BASEARRD_IN_PAGETABLE(item) (((PTR_TYPE)(item)) & 0x7FFFFFF000)
//ҳ����Ŀ�Ƿ�ӳ���ڴ�
#define IS_PAGETABLE_ITEM_ACCESSABLE(item) (((PTR_TYPE)(item)) & 0x20)
//ҳ����Ŀ�������Ƿ����ã��������ж�ʧ�ܣ�ǰ������������ҳ�������ݣ�ȫ�����ϣ�
#define IS_PAGETABLE_ITEM_PRESENT(item) (((PTR_TYPE)(item)) & 0x1)

//��ȡҳ������ַ�������ַ������Windows 10��ĳ���汾��ʼ΢����ҳ����ַ�����������������
//Newbluepill��ʹ�õ��ǹ̶���ҳ����ַ������ʱ��
//ֱ���õ�pxe��ַ���У������ļ�����ʵ�ֽ�β���������һ��KdPrint
void GetPageTableBaseVirtualAddress(PTR_TYPE* pPxeOut);
//��ʼ����ҳ��
NTSTATUS InitGlobalNewPageTableInfo(PT_G_INFO* pPtGInfo);
//������ҳ����Ϣ��
NTSTATUS AllocPageTableInfoBlock(PT_G_INFO* pPtGInfo, PVOID* pNewBlockOut);
//����ҳ����Ϣ�����ҳ����Ϣ������
void AttachPageTableInfoBlockToList(PT_G_INFO* pPtGInfo, PVOID pBlock);
//��ҳ����Ϣ������ɾ������ҳ����Ϣ��
BOOLEAN DetachPageTableInfoBlockToList(PT_G_INFO* pPtGInfo, PVOID pBlock);
//�ͷ�ҳ����Ϣ��
void FreePageTableInfoBlock(const PT_G_INFO* pPtGInfo, PVOID pBlock);
//����ҳ����Ϣ������
void DestroyPageTableInfoBlockList(PT_G_INFO* pPtGInfo);
//����ҳ����Ϣ�飬ע��û���Զ����书�ܣ�������Ϣ��Ҫ���� AllocPageTableInfoBlock
BOOLEAN InsertPageTableInfo(PT_G_INFO* pPtGInfo, const PT_INFO* pPtInfo);
//ɾ��ҳ����Ϣ��
BOOLEAN RemovePageTableInfo(PT_G_INFO* pPtGInfo, const PT_INFO* pPtInfo);

#endif