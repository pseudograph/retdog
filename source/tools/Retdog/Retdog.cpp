#include "pin.H"
#include <iostream>
#include <stack>
#include <algorithm>

/* ================================================================== */
// Global variables
/* ================================================================== */

std::stack<ADDRINT> callStack;
std::stack<ADDRINT> bpStack;
std::string mainImage;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

/* ===================================================================== */
// Utilities
/* ===================================================================== */

enum RESPONSE {
    CONTINUE,
    EXIT,
    RECOVER,
    ERROR
};

INT32 Usage()
{
    std::cerr << "Monitors control flow for errors." << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

RESPONSE askUserToContinue() {
    std::string input{};
    do {
        printf("Continue execution? y (yes)/n (no)/r (recover [unstable]) \n");
        input.clear();
        std::getline(std::cin, input);
        if (input == "n") {
            return EXIT;
        } else if (input == "y") {
            return CONTINUE;
        } else if (input == "r") {
            return RECOVER;
        }
    } while (input != "y" && input != "n" && input != "r");
    return ERROR;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

VOID insertCallIntoStack(ADDRINT ret) {
    callStack.push(ret);
}

VOID verifyRetTarget(ADDRINT esp, CONTEXT* ctx) {
    ADDRINT ret;
    PIN_SafeCopy(&ret, (void*)esp, sizeof(ADDRINT));
    if (ret != callStack.top()) {
        printf("----------[RETURN ADDRESS MODIFIED]----------\n");
        printf("Expected: 0x%016lx | Actual: 0x%016lx\n", callStack.top(), ret);
        RESPONSE response{askUserToContinue()};
        switch (response) {
            case CONTINUE:
                printf("Continuing\n");
                printf("---------------------------------------------\n");
                break;
            case EXIT:
                printf("Exiting\n");
                printf("---------------------------------------------\n");
                PIN_ExitProcess(1);
            case RECOVER:
                printf("Recovering: overwriting return address with expected\n");
                PIN_SafeCopy((ADDRINT*)esp, &callStack.top(), sizeof(ADDRINT));
                printf("Trying to resume execution\n");
                printf("---------------------------------------------\n");
                break;
            case ERROR:
                printf("RESPONSE ERROR");
                break;
        }
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

VOID verifyRetBP(VOID* ip, CONTEXT* ctx, ADDRINT bpReg, VOID* v) {
    auto bp{PIN_GetContextReg(ctx, REG_RBP)};
    if (bpStack.top() != PIN_GetContextReg(ctx, REG_RBP)) {
        printf("----------[BASE POINTER MODIFIED]----------\n");
        printf("Expected: 0x%016lx | Actual: 0x%016lx\n", bpStack.top(), bp);
        RESPONSE response{askUserToContinue()};
        switch (response) {
            case CONTINUE:
                printf("Continuing\n");
                printf("---------------------------------------------\n");
                break;
            case EXIT:
                printf("Exiting\n");
                printf("---------------------------------------------\n");
                PIN_ExitProcess(1);
            case RECOVER:
                printf("Recovering\n");
                PIN_SafeCopy((ADDRINT*)bp, &bpStack.top(), sizeof(ADDRINT));
                printf("Trying to resume execution\n");
                printf("---------------------------------------------\n");
                break;
            case ERROR:
                printf("RESPONSE ERROR");
                break;
        }
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
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR) insertBP, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyRetTarget, IARG_REG_VALUE, REG_STACK_PTR, IARG_CONTEXT, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) verifyRetBP, IARG_INST_PTR, IARG_CONTEXT, IARG_REG_VALUE, REG_BP, IARG_END);
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
