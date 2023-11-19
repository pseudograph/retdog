#include "pin.H"
#include <iostream>
#include <stack>
#include <algorithm>
#include <unordered_map>

/* ================================================================== */
// Global variables
/* ================================================================== */

std::stack<ADDRINT> callStack;
std::stack<ADDRINT> bpStack;
std::string mainImage;

#define MALLOC_FUNC "malloc"
#define FREE_FUNC "free"

enum MEMSTATE {
    ACTIVE,
    FREEING,
    FREE
};

std::unordered_map<ADDRINT, MEMSTATE> heap;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
    std::cerr << "Monitors control flow and heap allocations for errors." << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

VOID insertCallIntoStack(ADDRINT ret) {
    callStack.push(ret);
}

VOID verifyRetTarget(ADDRINT esp) {
    ADDRINT ret;
    PIN_SafeCopy(&ret, (void*)esp, sizeof(ADDRINT)); // Safely read the return address

    if (ret != callStack.top()) {
        printf("----------[RETURN ADDRESS MODIFIED]----------\n");
        printf("EXPECTED: 0x%016lx | ACTUAL: 0x%016lx\n", callStack.top(), ret);
        printf("---------------------------------------------\n");
    }

    callStack.pop();
}

VOID printRoutineName(VOID* name) {
    std::string nameStr{(char*)name};
    nameStr.erase(std::remove_if(nameStr.begin(), nameStr.end(), isspace), nameStr.end());
    printf("[ROUTINE]: %s\n", nameStr.c_str());
}


VOID insertBP(VOID* ip, CONTEXT* ctx, VOID* v) {
    bpStack.push(PIN_GetContextReg(ctx, REG_RBP));
}

VOID verifyRetBP(VOID* ip, CONTEXT* ctx, VOID* v) {
    auto bp{PIN_GetContextReg(ctx, REG_RBP)};
    if (bpStack.top() != PIN_GetContextReg(ctx, REG_RBP)) {
        printf("----------[BASE POINTER MODIFIED]----------\n");
        printf("EXPECTED: 0x%016lx | ACTUAL: 0x%016lx\n", bpStack.top(), bp);
        printf("-------------------------------------------\n");
    }
    bpStack.pop();
}

VOID logMalloc(ADDRINT* addr) {
    if (heap.find(*addr) != heap.end()) {
        heap[*addr] = ACTIVE;
        return;
    }
    printf("malloc AT 0x%016lx\n", *addr);
    heap.insert({*addr, ACTIVE});
}

VOID freeMemory(ADDRINT* addr) {
    if (heap.find(*addr) != heap.end() && heap[*addr] == ACTIVE) {
        heap[*addr] = FREEING;
    } else if (heap.find(*addr) != heap.end() && (heap[*addr] == FREEING || heap[*addr] == FREE)) {
        printf("----------[DOUBLE FREE]----------\n");
        printf("MEMORY AT 0x%016lx\n", *addr);
        if (heap[*addr] == FREEING) {
            printf("status freeing\n");
        } else if (heap[*addr] == FREE) {
            printf("status free");
        }
        printf("---------------------------------\n");
    } else if (heap.find(*addr) == heap.end()) {
        printf("----------[FREE BEFORE MALLOC]----------\n");
        printf("MEMORY AT 0x%016lx\n", *addr);
        printf("----------------------------------------\n");
    }
}

VOID verifyMemRead(ADDRINT addr) {
    if (heap.find(addr) != heap.end()) {
        if (heap[addr] == FREE) {
            printf("----------[READ AFTER FREE]----------\n");
            printf("MEMORY AT 0x%016lx\n", addr);
            printf("-------------------------------------\n");
        }
    }
}

VOID verifyMemWrite(ADDRINT addr) {
    if (heap.find(addr) != heap.end()) {
        if (heap[addr] == FREE) {
            printf("----------[WRITE AFTER FREE]----------\n");
            printf("MEMORY AT 0x%016lx\n", addr);
            printf("--------------------------------------\n");
        } else if (heap[addr] == FREEING) {
            printf("free AT 0x%016lx\n", addr);
            heap[addr] = FREE;
        }
    }
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Image(IMG img, VOID* val) {
    RTN mallocRtn = RTN_FindByName(img, MALLOC_FUNC);
    if (RTN_Valid(mallocRtn)) {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR) logMalloc, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_END);
        RTN_Close(mallocRtn);
    }

    RTN freeRtn = RTN_FindByName(img, FREE_FUNC);
    if (RTN_Valid(freeRtn)) {
        RTN_Open(freeRtn);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR) freeMemory, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
    if (IMG_IsMainExecutable(img)) {
        mainImage = IMG_Name(img);
        printf("[MAIN EXECUTABLE]: %s\n", mainImage.c_str());
    }
}

VOID Routine(RTN rtn, VOID* val) {
    RTN_Open(rtn);
    std::string* routineNamePtr{new std::string{RTN_Name(rtn)}};
    if (IMG_Name(SEC_Img(RTN_Sec(rtn))) == mainImage) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) printRoutineName, IARG_PTR, routineNamePtr, IARG_END);
    }
    RTN_Close(rtn);
}

VOID Instruction(INS ins, VOID* val) {
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) insertCallIntoStack, IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR) insertBP, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyRetTarget, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyRetBP, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }
    if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyMemRead, IARG_MEMORYREAD_EA, IARG_END);
    }
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyMemWrite, IARG_MEMORYWRITE_EA, IARG_END);
    }
}


VOID Fini(INT32 code, VOID* v) {}

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) {
        return Usage();
    }
    IMG_AddInstrumentFunction(Image, nullptr);
    RTN_AddInstrumentFunction(Routine, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);

    PIN_InitSymbols();
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
