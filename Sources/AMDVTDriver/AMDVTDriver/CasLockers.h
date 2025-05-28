#ifndef CAS_LOCKERS_H
#define CAS_LOCKERS_H

#include "Basic.h"

//�̲߳��ɳ��뻥����������ԭ�Ӳ���
class SignleLockMutex
{
    LONG _locker;

public:
    SignleLockMutex() : _locker(0) {}
    //��������
    void Lock()
    {
        while (InterlockedCompareExchange(&_locker, TRUE, FALSE))
            continue;
    }
    //��������
    bool TryLock()
    {
        return !InterlockedCompareExchange(&_locker, TRUE, FALSE);
    }
    //����
    void Unlock()
    {
        InterlockedCompareExchange(&_locker, FALSE, TRUE);
    }
};

//��д�����̲߳�������
class ReadWriteLock
{
    const LONG ReadModeId = 2;
    const LONG WriteModeId = 1;
    const LONG UnlockModeId = 0;

    LONG _count;
    LONG _id;
public:
    ReadWriteLock() : _count(0), _id(0) {}
    // �����Ӷ���
    void ReadLock()
    {
        LONG previousId = UnlockModeId;
        do
        {
            previousId = InterlockedCompareExchange(&_id, ReadModeId, UnlockModeId);
        } while (previousId != UnlockModeId && previousId != ReadModeId);
        InterlockedIncrement(&_count);
    }
    // ���ԼӶ���
    bool TryRead()
    {
        LONG previousId = UnlockModeId;
        previousId = InterlockedCompareExchange(&_id, ReadModeId, UnlockModeId);
        if (previousId == UnlockModeId || previousId == ReadModeId)
        {
            InterlockedIncrement(&_count);
            return true;
        }
        else
        {
            return false;
        }
    }
    // �������
    void ReadUnlock()
    {
        if (InterlockedCompareExchange(&_id, ReadModeId, ReadModeId) == ReadModeId)
        {
            if (InterlockedDecrement(&_count) == 0)
                InterlockedCompareExchange(&_id, UnlockModeId, ReadModeId);
        }
    }
    // ������д��
    void WriteLock()
    {
        LONG previousId = 0;
        do
        {
            previousId = InterlockedCompareExchange(&_id, WriteModeId, UnlockModeId);
        } while (previousId != UnlockModeId);
        InterlockedExchange(&_count, 0);
    }
    // ���Լ�д��
    bool TryWrite()
    {
        bool result = InterlockedCompareExchange(&_id, WriteModeId, UnlockModeId) == UnlockModeId;
        if (result)
            InterlockedExchange(&_count, 0);
        return result;
    }
    // ���д��
    void WriteUnlock()
    {
        InterlockedCompareExchange(&_id, UnlockModeId, WriteModeId);
    }
};

#endif