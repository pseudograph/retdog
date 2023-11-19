#include "pin.H"
#include <iostream>
#include <stack>
#include <algorithm>
#include <unordered_map>

/* ================================================================== */
// Global variables
/* ================================================================== */

struct Snapshot {
    ADDRINT ret;
    ADDRINT bp;
};

std::stack<ADDRINT> callStack;
std::stack<ADDRINT> bpStack;
std::string mainImage;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    std::cerr << "This tool prints out the number of dynamically executed " << std::endl
         << "instructions, basic blocks and threads in the application." << std::endl
         << std::endl;

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
        printf("----------[RETURN ADDRESS MODIFIED]----------\n");
    }

    callStack.pop();
}

VOID printRoutineName(VOID* name) {
    std::string nameStr{(char*)name};
    nameStr.erase(std::remove_if(nameStr.begin(), nameStr.end(), isspace), nameStr.end());
    printf("[ROUTINE]: %s\n", nameStr.c_str());
}


VOID testCall(VOID* ip, CONTEXT* ctx, VOID* v) {
    bpStack.push(PIN_GetContextReg(ctx, REG_RBP));
}

VOID testRet(VOID* ip, CONTEXT* ctx, VOID* v) {
    auto bp{PIN_GetContextReg(ctx, REG_RBP)};
    if (bpStack.top() != PIN_GetContextReg(ctx, REG_RBP)) {
        printf("----------[BASE POINTER MODIFIED]----------\n");
        printf("EXPECTED: 0x%016lx | ACTUAL: 0x%016lx\n", bpStack.top(), bp);
        printf("----------[BASE POINTER MODIFIED]----------\n");
    }
    bpStack.pop();
}
/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Image(IMG img, VOID* val) {
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
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR) testCall, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyRetTarget, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) testRet, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <tool-name> -- ...
 */
int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }


    // Register function to be called to instrument traces
    //TRACE_AddInstrumentFunction(Trace, 0);

    IMG_AddInstrumentFunction(Image, nullptr);
    RTN_AddInstrumentFunction(Routine, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, nullptr);

    // Start the program, never returns
    PIN_InitSymbols();
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
