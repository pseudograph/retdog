Retdog is a Pintool that uses the Intel Pin binary instrumentation framework to enforce control flow in a target program.

It keeps track of return addresses and saved base pointers in a shadow stack stored safely in Retdog's memory, separate from the target program. Calls are instrumented to update the shadow stack, while returns are instrumented to check against the shadow stack.

It also prints the names of routines as they execute to hint the flow of execution to the user. This is not a stacktrace - routine names are simply logged to the console.

Retdog uses its shadow stack to detect buffer overflow attacks that attempt to overwrite the return address or saved base pointer. When discrepancies are encountered, Retdog prompts the user to choose how they want to handle the discrepancy:

- Continue with the tampered stack

- Terminate the target program with an exit code of 1

- Attempt to recover by overwriting the stack data of the target program with data from the shadow stack

This repository contains a full copy of the Intel Pin 3.28 development kit for easy compilation.

Retdog's source code is in source/tools/Retdog/Retdog.cpp and its artifacts are generated in source/tools/Retdog/obj-intel64/Retdog.so or source/tools/Retdog/obj-ia32/Retdog.so.

To build Retdog as a Pintool:

```
cd source/tools
make all TARGET=intel64
```

Replace intel64 with ia32 for 32-bit.

To run the tool:

```
cd source/tools
../../pin -t Retdog/obj-intel64/Retdog.so -- /bin/ls
```

Replace /bin/ls with your target application.

Example usage (target is a program that copies stdin input into a buffer using strcpy, causing a simple buffer overflow):

![image](https://github.com/pseudograph/retdog/assets/60597985/f2ce228f-2fbf-434c-8b80-a33ad63a102c)

CS5231 Team29
