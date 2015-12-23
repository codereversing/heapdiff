#include "pin.H"

#include <cstdio>
#include <set>

//Quick and dirty hack due to name conflicts between
//pin.h and windows.h. Abstract out Windows-specific calls
//to other files if you are using this code as a template
//so it looks less ugly
namespace WinApi
{
#include <Windows.h>
}

FILE *trace = NULL;
std::set<WinApi::DWORD_PTR> heapAddresses;

bool IsInHeap(void *address)
{
    using namespace WinApi;

    return heapAddresses.find((DWORD_PTR)address) != std::end(heapAddresses);
}

VOID OnMemoryWriteBefore(VOID *ip, VOID *addr)
{
    if(IsInHeap(addr))
    {
        fprintf(trace, "Heap entry 0x%p has been modified.\n", addr);
    }
}

VOID OnInstruction(INS instr, VOID *v)
{
    UINT32 memOperands = INS_MemoryOperandCount(instr);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsWritten(instr, memOp))
        {
            INS_InsertPredicatedCall(
                instr, IPOINT_BEFORE, (AFUNPTR)OnMemoryWriteBefore,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    (void)fclose(trace);
}

INT32 Usage()
{
    PIN_ERROR( "This Pintool tracks all heap writes\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

void WalkHeaps(WinApi::HANDLE *heaps, const size_t size)
{
    using namespace WinApi;

    fprintf(stderr, "Walking %i heaps.\n", size);

    for(size_t i = 0; i < size; ++i)
    {
        if(HeapLock(heaps[i]) == FALSE)
        {
            fprintf(stderr, "Could not lock heap 0x%X"
                "Error = 0x%X\n", heaps[i], GetLastError());
            continue;
        }

        PROCESS_HEAP_ENTRY heapEntry = { 0 };
        heapEntry.lpData = NULL;
        while(HeapWalk(heaps[i], &heapEntry) != FALSE)
        {
            for(size_t j = 0; j < heapEntry.cbData; ++j)
            {
                heapAddresses.insert(std::end(heapAddresses),
                    (DWORD_PTR)heapEntry.lpData + j);
            }
        }

        fprintf(stderr, "HeapWalk finished with 0x%X\n", GetLastError());

        if(HeapUnlock(heaps[i]) == FALSE)
        {
            fprintf(stderr, "Could not unlock heap 0x%X"
                "Error = 0x%X\n", heaps[i], GetLastError());
        }
    }

    size_t numHeapAddresses = heapAddresses.size();
    fprintf(stderr, "Found %i (0x%X) heap addresses.\n",
        numHeapAddresses, numHeapAddresses);

}

WinApi::HANDLE *GetHeapHandles(size_t &outSize)
{
    using namespace WinApi;

    const size_t maxHeaps = 32;
    HANDLE *heapHandles = new HANDLE[maxHeaps];
    memset(heapHandles, 0, maxHeaps * sizeof(HANDLE));

    DWORD numHeaps = GetProcessHeaps(maxHeaps, heapHandles);

    fprintf(stderr, "Process has %i heaps.\n", numHeaps);

    outSize = numHeaps;

    return heapHandles;
}

void InitializeDebugConsole()
{
	using namespace WinApi;

	if(AllocConsole())
	{
	    freopen("CONOUT$", "w", stderr);
	    SetConsoleTitle("Console");
	    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
			FOREGROUND_RED |FOREGROUND_GREEN | FOREGROUND_BLUE);
	    fprintf(stderr, "PIN DLL loaded.\n");
	}
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	InitializeDebugConsole();

    size_t numHeaps = 0;
    WinApi::HANDLE *heapHandles = GetHeapHandles(numHeaps);
    WalkHeaps(heapHandles, numHeaps);

    trace = fopen("pinatrace.out", "w");

    INS_AddInstrumentFunction(OnInstruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    
    return 0;
}