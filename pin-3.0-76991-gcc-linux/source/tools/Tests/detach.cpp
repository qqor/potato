/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <stdio.h>
#include "pin.H"
#include <iostream>

// This tool shows how to detach Pin from an 
// application that is under Pin's control.

UINT64 icount = 0;
VOID docount() 
{
    icount++;

    // Release control of application if 10000 
    // instructions have been executed
    if ((icount % 10000) == 0) 
    {
        PIN_Detach();
    }
}
 
VOID Instruction(INS ins, VOID *v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

VOID HelloWorld(VOID *v)
{
    std::cerr << "Hello world!" << endl;
}

VOID ByeWorld(VOID *v)
{
    std::cerr << "Byebye world!" << endl;
}

VOID Fini(INT32 code, VOID *v)
{
    std::cerr << "Count: " << icount << endl;
}

int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);

    // Callback function to invoke for every 
    // execution of an instruction
    INS_AddInstrumentFunction(Instruction, 0);
    
    // Callback functions to invoke before
    // Pin releases control of the application
    PIN_AddDetachFunction(HelloWorld, 0);
    PIN_AddDetachFunction(ByeWorld, 0);

    PIN_AddFiniFunction(Fini, 0);
    
    // Never returns
    PIN_StartProgram();
    
    return 0;
}
