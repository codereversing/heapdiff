#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

using Byte = unsigned char;
using Address = DWORD_PTR;

using ByteDiff = std::pair<Byte /*Old*/, Byte /*New*/>;
using AddressDiff = std::pair<Address /*Start*/, Address /*End*/>;

using Heap = std::set<std::pair<Address /*Heap address*/, Byte /*Byter at address*/>>;
using HeapDiff = std::set<std::pair<Address /*Heap address*/, ByteDiff /*Byte change*/>>;
using HeapDiffRange = std::set<std::pair<AddressDiff /*Contiguous heap address range*/,
    std::vector<ByteDiff /*Byte changes per address*/>>>;

using pNtSuspendProcess = NTSTATUS (NTAPI *)(HANDLE processHandle);
using pNtResumeProcess = NTSTATUS (NTAPI *)(HANDLE processHandle);

pNtSuspendProcess NtSuspendProcess = nullptr;
pNtResumeProcess NtResumeProcess = nullptr;

const HANDLE GetProcessHandle(const DWORD processId)
{
    const DWORD flags = PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;

    const HANDLE processHandle = OpenProcess(flags, false, processId);
    if (processHandle == nullptr)
    {
        fprintf(stderr, "Could not get process handle. "
            "Error = 0x%X\n", GetLastError());
        exit(-1);
    }

    return processHandle;
}

const bool IsReadable(const HANDLE processHandle, const DWORD_PTR heapAddress, const size_t size)
{
    MEMORY_BASIC_INFORMATION memInfo = { 0 };

    const SIZE_T readSize = VirtualQueryEx(processHandle, (LPCVOID)heapAddress, &memInfo, size);
    if (readSize == 0)
    {
        fprintf(stderr, "Could not query memory region 0x%p "
            "Error = 0x%X", (void *)heapAddress, GetLastError());
        return false;
    }

    return ((memInfo.State & MEM_COMMIT) && !(memInfo.Protect & PAGE_NOACCESS));
}

void ReadHeapData(const HANDLE processHandle, const DWORD_PTR heapAddress, const size_t size, Heap &heapInfo,
    std::unique_ptr<unsigned char[]> &heapBuffer, size_t &reserveSize)
{
    if (size > reserveSize)
    {
        heapBuffer = std::unique_ptr<unsigned char[]>(new unsigned char[size]);
        reserveSize = size;
    }

    SIZE_T bytesRead = 0;
    const BOOL success = ReadProcessMemory(processHandle, (LPCVOID)heapAddress, heapBuffer.get(), size, &bytesRead);

    if (success == 0)
    {
        fprintf(stderr, "Could not read process memory at 0x%p "
            "Error = 0x%X\n", (void *)heapAddress, GetLastError());
        return;
    }
    if (bytesRead != size)
    {
        fprintf(stderr, "Could not read process all memory at 0x%p "
            "Error = 0x%X\n", (void *)heapAddress, GetLastError());
        return;
    }

    for (size_t i = 0; i < size; ++i)
    {
        heapInfo.emplace_hint(std::end(heapInfo), std::make_pair((heapAddress + i), heapBuffer[i]));
    }
}

const Heap EnumerateProcessHeap(const DWORD processId, const HANDLE processHandle)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, processId);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Could not create toolhelp snapshot. "
            "Error = 0x%X\n", GetLastError());
        exit(-1);
    }

    Heap processHeapInfo;

    (void)NtSuspendProcess(processHandle);

    size_t reserveSize = 4096;
    std::unique_ptr<unsigned char[]> heapBuffer(new unsigned char[reserveSize]);

    HEAPLIST32 heapList = { 0 };
    heapList.dwSize = sizeof(HEAPLIST32);
    if (Heap32ListFirst(snapshot, &heapList))
    {
        do
        {
            HEAPENTRY32 heapEntry = { 0 };
            heapEntry.dwSize = sizeof(HEAPENTRY32);

            if (Heap32First(&heapEntry, processId, heapList.th32HeapID))
            {
                do
                {
                    if (IsReadable(processHandle, heapEntry.dwAddress, heapEntry.dwSize))
                    {
                        ReadHeapData(processHandle, heapEntry.dwAddress, heapEntry.dwSize,
                            processHeapInfo, heapBuffer, reserveSize);
                    }

                    heapEntry.dwSize = sizeof(HEAPENTRY32);
                } while (Heap32Next(&heapEntry));
            }

            heapList.dwSize = sizeof(HEAPLIST32);
        } while (Heap32ListNext(snapshot, &heapList));
    }

    (void)NtResumeProcess(processHandle);

    (void)CloseHandle(snapshot);

    return processHeapInfo;
}

const HeapDiff GetHeapDiffs(const Heap &firstHeap, Heap &secondHeap)
{
    HeapDiff heapDiff;

    for (auto &heapEntry : firstHeap)
    {
        auto &secondHeapEntry = std::find_if(std::begin(secondHeap), std::end(secondHeap),
            [&](const std::pair<DWORD_PTR, unsigned char> &entry) -> bool
        {
            return entry.first == heapEntry.first;
        });

        if (secondHeapEntry != std::end(secondHeap))
        {
            if (heapEntry.second != secondHeapEntry->second)
            {
                //Entries in both heaps but are different
                heapDiff.emplace_hint(std::end(heapDiff),
                    heapEntry.first, std::make_pair(heapEntry.second, secondHeapEntry->second));
            }
            secondHeap.erase(secondHeapEntry);
        }
        else
        {
            //Entries in first heap and not in second heap
            heapDiff.emplace_hint(std::end(heapDiff),
                heapEntry.first, std::make_pair(heapEntry.second, heapEntry.second));
        }
    }

    for (auto &newEntries : secondHeap)
    {
        //Entries in second heap and not in first heap
        heapDiff.emplace_hint(std::end(heapDiff),
            newEntries.first, std::make_pair(newEntries.second, newEntries.second));
    }

    return heapDiff;
}

const HeapDiffRange MergeHeapBlocks(const HeapDiff &heapDiff)
{
    HeapDiffRange heapRange;

    if (heapDiff.size() == 1)
    {
        auto &diff = std::begin(heapDiff);

        std::vector<ByteDiff> byteDiffs;
        byteDiffs.emplace_back(std::make_pair(diff->second.first, diff->second.second));
        AddressDiff addressDiffs(diff->first, diff->first);

        heapRange.emplace_hint(std::end(heapRange), std::make_pair(std::move(addressDiffs),
            std::move(byteDiffs)));
    }
    else if (heapDiff.size() > 1)
    {
        auto &iter = std::begin(heapDiff);
        while (iter != std::end(heapDiff))
        {            
            DWORD_PTR firstAddress = iter->first;
            DWORD_PTR lastAddress = iter->first;
            std::vector<ByteDiff> byteDiffs;

            size_t size = 0;
            while (iter != std::end(heapDiff))
            {
                byteDiffs.push_back(iter->second);

                ++iter;
                ++size;
                if (iter == std::end(heapDiff))
                {
                    break;
                }
                if ((iter->first - 1) != lastAddress)
                {
                    break;
                }
                lastAddress = iter->first;
            }

            heapRange.emplace_hint(std::end(heapRange), std::make_pair(std::make_pair(firstAddress, lastAddress),
                byteDiffs));
        }
    }

    return heapRange;
}

void PrintBlocks(const HeapDiffRange &mergedRange, size_t minimumSize = 0, bool outputBytes = false)
{
    for (auto &diff : mergedRange)
    {
        if (diff.second.size() >= minimumSize)
        {
            size_t size = diff.first.second - diff.first.first;
            ++size;

            fprintf(stderr, "Heap block: 0x%p -> 0x%p "
                "Size = %i (0x%X)\n",
                (void *)diff.first.first, (void *)diff.first.second,
                (int)size, (int)size);
            if (outputBytes)
            {
                for (size_t i = 0; i < size; ++i)
                {
                    auto IsPrintable = [](Byte first, Byte second)
                    {
                        return (first >= 0x20 && first <= 0x7E) &&
                            (second >= 0x20 && second <= 0x7E);
                    };
                    if (IsPrintable(diff.second[i].first, diff.second[i].second))
                    {
                        fprintf(stderr, "  %c -> %c\n",
                            diff.second[i].first, diff.second[i].second);
                    }
                }
                fprintf(stderr, "\n");
            }
        }
    }
}

int main(int argc, char *argv[])
{
    const HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");

    NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(hNtDll, "NtSuspendProcess");
    NtResumeProcess = (pNtResumeProcess)GetProcAddress(hNtDll, "NtResumeProcess");

    if (NtSuspendProcess == nullptr || NtResumeProcess == nullptr)
    {
        fprintf(stderr, "Could not locate NtSuspendProcess/NtResumeProcess.\n");
        exit(-1);
    }

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [process id: int] [min heap change size: int]"
            " [print block contents: 0/1]\n",
            argv[0]);
        exit(-1);
    }

    const DWORD processId = atoi(argv[1]);
    if (processId == 0)
    {
        fprintf(stderr, "Invalid process id entered.\n");
        exit(-1);
    }

    const int heapCutoff = (argc >= 3) ? atoi(argv[2]) : 0;
    const bool printBlocks = (argc >= 4) ? (atoi(argv[3]) == 1) : false;

    const HANDLE processHandle = GetProcessHandle(processId);

    auto &first = EnumerateProcessHeap(processId, processHandle);
    auto second = EnumerateProcessHeap(processId, processHandle);

    auto diff = GetHeapDiffs(first, second);

    auto mergedDiff = MergeHeapBlocks(diff);

    PrintBlocks(mergedDiff, heapCutoff, printBlocks);

    return 0;
}