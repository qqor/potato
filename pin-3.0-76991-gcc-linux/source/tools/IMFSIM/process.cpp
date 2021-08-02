//
//  BEGIN_LEGAL
//  Intel Open Source License
//
//  Copyright (c) 2002-2013 Intel Corporation. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  Redistributions of source code must retain the above copyright notice,
//  this list of conditions and the following disclaimer.  Redistributions
//  in binary form must reproduce the above copyright notice, this list of
//  conditions and the following disclaimer in the documentation and/or
//  other materials provided with the distribution.  Neither the name of
//  the Intel Corporation nor the names of its contributors may be used to
//  endorse or promote products derived from this software without
//  specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
//  ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//  END_LEGAL
//
//  ------------------------------------------------------------------------
//
//

#include "pin.H"
#include <asm/unistd.h>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <unistd.h>
#include <map>
#include <boost/algorithm/string.hpp>

#include "mutation.h"
#include "instrutil.h"
#include "memutil.h"
#include "signal.h"
#include "utility.h"
#include "fuzzing.h"
#include "instrument.h"
#include "recorder.h"
#include "datadef.h"

VOID Fini(INT32 code, VOID *v)
{

    fprintf(trace, "#eof\n");
    fclose(trace);

    delete[] ptrHeap;


    cout << "[CRASH]" << endl;
    ADDRINT* dumpPtr = 0x0;
    *dumpPtr = 10;
}


int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    if (!KnobStart.Value() || !KnobEnd.Value())
      return Usage();



    fuzzValue = KnobStartValue.Value() - 1;

    initMemoryRegionRandom();

    PIN_SetSyntaxIntel();
    PIN_InterceptSignal(SIGSEGV, catchSignalSEGV, 0);
    PIN_InterceptSignal(SIGFPE, catchSignalFP, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}
bool isMemReadReg(INS ins)
{
    
    return (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 1) && INS_OperandIsReg(ins, 1));
}


bool isMemWriteReg(INS ins)
{
    return (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0) && INS_OperandIsReg(ins, 0));
}


REG getMemReadReg(INS ins)
{
    return INS_OperandReg(ins, 1);
}


REG getMemWriteReg(INS ins)
{
    return INS_OperandReg(ins, 0);
}



fpRecord aux(REG r, FPOp op, INT64 addr)
{
    fpRecord f = {r, op, addr};

    return f;
}

LEVEL_BASE::OPCODE getOP(INS ins)
{
    return INS_Opcode(ins);
}

bool isControlOP(LEVEL_BASE::OPCODE op)
{
    return op == XED_ICLASS_JMP || op == XED_ICLASS_CALL_NEAR || op == XED_ICLASS_JMP_FAR || op == XED_ICLASS_CALL_FAR;
}

fpRecord regInFP(INS ins)
{
    if (INS_OperandCount(ins) == 4)
    {
        if (INS_OperandIsReg(ins, 0))
        {
            REG r = INS_OperandReg(ins, 0);
            return aux(r, FPInvalid, 0);
        }
        else if (INS_OperandIsMemory(ins, 0))
        {
            REG r = INS_OperandMemoryBaseReg(ins, 0);
            INT64 d = INS_OperandMemoryDisplacement(ins, 0);
            return aux(r, FPInvalid, d);
        }
        else
            return aux(REG_INVALID_, FPInvalid, 0);
    }
    else
    {
        return aux(REG_INVALID_, FPInvalid, 0);
    }
}


REG regInMemoryRead(INS ins)
{
    if (INS_OperandCount(ins) == 1)
    {
        cout << "unhanded 1 " << INS_Disassemble(ins) << endl;
        return REG_INVALID_;
    }
    else if (INS_OperandCount(ins) == 2)
    {
        if (INS_OperandIsReg(ins, 1))
            return REG_INVALID_;

        else if (INS_OperandIsImmediate(ins, 1))
            return REG_INVALID_;

        else if (INS_OperandIsMemory(ins, 1))
            return INS_OperandMemoryBaseReg(ins, 1);

        else if (INS_OperandIsImplicit(ins, 1))
        {
            cout << " is implicit" << endl;
            return REG_INVALID_;
        }
        else if (INS_OperandIsFixedMemop(ins, 1))
        {
            cout << " is fixed mem op" << endl;
            return REG_INVALID_;
        }
        else if (INS_OperandIsBranchDisplacement(ins, 1))
        {
            cout << " is branch displacement" << endl;
            return REG_INVALID_;
        }

        else {
            cout << "unhanded 2 " << INS_Disassemble(ins) << endl;
            return REG_INVALID_;
        }
    }
    else if (INS_OperandCount(ins) == 3) {
        if (REG_StringShort(INS_OperandReg(ins, 2)) == "rflags")
        {
            if (INS_OperandIsReg(ins, 1))
                return REG_INVALID_;

            else if (INS_OperandIsImmediate(ins, 1))
                return REG_INVALID_;

            else if (INS_OperandIsMemory(ins, 1))
                return INS_OperandMemoryBaseReg(ins, 1);

            else if (INS_OperandIsImplicit(ins, 1))
            {
                cout << " is implicit" << endl;
                return REG_INVALID_;
            }
            else if (INS_OperandIsFixedMemop(ins, 1))
            {
                cout << " is fixed mem op" << endl;
                return REG_INVALID_;
            }
        else if (INS_OperandIsBranchDisplacement(ins, 1))
        {
            cout << " is branch displacement" << endl;
            return REG_INVALID_;
        }

            else {
                cout << "unhanded 3 " << INS_Disassemble(ins) << endl;
                return REG_INVALID_;
            }
        }
        else{
            cout << "unhanded 4 " << INS_Disassemble(ins) << endl;
            return REG_INVALID_;
        }
    }
    else
    {
        /*
        */
        cout << "unhanded 5 " << INS_Disassemble(ins) << endl;
        return REG_INVALID_;
    }
}


REG regInMemoryWrite(INS ins)
{
    if (INS_OperandCount(ins) == 1)
    {
        cout << "unhanded 1 " << INS_Disassemble(ins) << endl;
        return REG_INVALID_;
    }
    else if (INS_OperandCount(ins) == 2)
    {
        if (INS_OperandIsReg(ins, 0))
            return REG_INVALID_;

        else if (INS_OperandIsImmediate(ins, 0))
            return REG_INVALID_;

        else if (INS_OperandIsMemory(ins, 0))
            return INS_OperandMemoryBaseReg(ins, 0);

        else
        {
            cout << "unhanded 2 " << INS_Disassemble(ins) << endl;
            return REG_INVALID_;
        }
    }
    else if (INS_OperandCount(ins) == 3) {
        if (REG_StringShort(INS_OperandReg(ins, 2)) == "rflags")
        {
            if (INS_OperandIsReg(ins, 0))
                return REG_INVALID_;

            else if (INS_OperandIsImmediate(ins, 0))
                return REG_INVALID_;

            else if (INS_OperandIsMemory(ins, 0))
                return INS_OperandMemoryBaseReg(ins, 0);

            else {
                cout << "unhanded 3 " << INS_Disassemble(ins) << endl;
                return REG_INVALID_;
            }
        }
        else{
            cout << "unhanded 4 " << INS_Disassemble(ins) << endl;
            return REG_INVALID_;
        }
    }
    else
    {
        cout << "unhanded 5 " << INS_Disassemble(ins) << endl;
        return REG_INVALID_;
    }
}

bool fixMemRead(INS ins, ADDRINT faddr, CONTEXT *ctx)
{
    REG r = regInMemoryRead(ins);

    if (r == REG_INVALID_)
        return false;
    else
    {

        cout << "fix mem read function" << endl;

        fixErrorByReverseTaintAnalysis(ctx, r);
        return true;
    }
}

bool fixMemWrite(INS ins, ADDRINT faddr, CONTEXT *ctx)
{
    cout << "reg in memory write " << INS_Disassemble(ins) << hex << INS_Address(ins) << endl;
    REG r = regInMemoryWrite(ins);

    if (r == REG_INVALID_)
        return false;
    else
    {
        fixErrorByReverseTaintAnalysis(ctx, r);

        return true;
    }
}


bool fixMemReadNew(REG r, ADDRINT faddr, CONTEXT *ctx)
{
    if (r == REG_INVALID_)
    {
        return false;
    }
    else
    {
        cout << "fix mem read on " << REG_StringShort(r) << endl;

        fixErrorByReverseTaintAnalysis(ctx, r);
        return true;
    }
}

bool fixMemWriteNew(REG r, ADDRINT faddr, CONTEXT *ctx)
{
    if (r == REG_INVALID_)
        return false;
    else
    {
        cout << "fix mem write on " << REG_StringShort(r) << endl;

        fixErrorByReverseTaintAnalysis(ctx, r);
        return true;
    }
}

bool fixFPInstr(fpRecord fpr, CONTEXT *ctx)
{
    if (fpr.regFP == REG_INVALID_)
        return false;
    else
    {
        if (fpr.regFP == LEVEL_BASE::REG_RBP)
        {
            ADDRINT rv = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP);
            ADDRINT des = rv + fpr.offset;
            *(reinterpret_cast<ADDRINT*>(des)) = valueForFP();

            return true;
        }
        else
        {
            PIN_SetContextReg(ctx, fpr.regFP, valueForFP());

            return true;
        }

    }
}



bool fixErrorByReverseTaintAnalysis(CONTEXT *ctx, LEVEL_BASE::REG r)
{

    cout << "fix error by reverse taint analysis" << endl;
    exec("rm ctx.info pin.trace");

    FILE * t = fopen("pin.trace", "w");
    list<std::string>::iterator i;

    for(i = instrTrace.begin(); i != instrTrace.end(); ++i)
        fprintf(t, "%s\n", (*i).c_str());

    fprintf(t, "#eof\n");
    fclose(t);


    t = fopen("ctx.trace", "w");
    list<CONTEXT>::iterator j;
    for(j = ctxTrace.begin(); j != ctxTrace.end(); ++j)
        dumpCTXTrace(&(*j), t);

    fprintf(t, "#eof\n");
    fclose(t);

    instrTrace.clear();
    ctxTrace.clear();


    t = fopen("ctx.info", "w");
    dump_crash_point(ctx, t, r);
    fprintf(t, "#eof\n");
    fclose(t);

    exec("cp ctx.info ~/fuzzing/src/scripts/reverse/");
    exec("cp ctx.trace ~/fuzzing/src/scripts/reverse/");
    exec("cp pin.trace ~/fuzzing/src/scripts/reverse/");

    exec("python adpater.py 1");

    char const * fn = "reverse.output";
    string sss = first_line_file(fn);
    cout << "[ROOT CAUSE] " << sss << endl;
    std::vector<std::string> elems;
    elems = split(sss, ':', elems);

    fix_addr = hexstr_to_int(elems[1]);
    fix_r = get_reg_from_str(elems[0]);

    inputMap[fix_addr] = fix_r;
    inputHasFixMap[fix_addr] = false;
    _resume = true;

    _start_resume = true;

    return false;
}
void loopInstrMap()
{
    cout << endl << endl;
    typedef std::map<ADDRINT, INS>::iterator it_type;

    for(it_type iterator = instrMap.begin(); iterator != instrMap.end(); ++iterator) {
        cout << "addr " << hex << iterator->first << " : "  << INS_Disassemble(iterator->second) << endl;
    }
    cout << endl << endl;
}

void recordInstr(ADDRINT insAddr, INS ins)
{
    loopInstrMap();

    if (instrMap.count(insAddr) > 0)
    {
        return;
    }

    instrMap[insAddr] = ins;
}


INS getInstrByAddr(ADDRINT insAddr)
{
    loopInstrMap();

    INS t = instrMap[insAddr];
    
    return t;
}


void recordInstrOperand(ADDRINT insAddr, INS ins)
{
    if (instrMapNew.count(insAddr) > 0)
    {
        return;
    }

    REG rr = regInMemoryRead(ins);
    REG rw = regInMemoryWrite(ins);
    
    fpRecord rfp = regInFP(ins);
   
    string rs = INS_Disassemble(ins);
    LEVEL_BASE::OPCODE opc = getOP(ins);

    struct instrRecord ir;
    ir.insDis = rs;
    ir.regRead = rr;
    ir.regWrite = rw;
    ir.fpr = rfp;
    ir.op = opc;
    ir.addrNext = INS_NextAddress(ins);

    instrMapNew[insAddr] = ir;

}

void initRecorder()
{
    
    struct instrRecord ir;
    ir.insDis = "dummy";
    ir.op = 0;
    ir.addrNext = 0;

    instrMapNew[1] = ir;
}

instrRecord getInstrByAddrOperand(ADDRINT insAddr)
{
    if (instrMapNew.count(insAddr) > 0)
    {
        instrRecord ir = instrMapNew[insAddr];
        
        return ir;
    }
    else
    {
       
        instrRecord dummy = instrMapNew[1];
        return dummy;
    }
}


VOID recordCall(ADDRINT insAddr, VOID* desAddr)
{
        fprintf(trace,"call:%p\n", desAddr);
}
VOID displayCurrentContext_Full(CONTEXT *ctx, UINT32 flag)
{
  std::cout << "[" << (flag == CONTEXT_FLG ? "CONTEXT" : "SIGSGV")
    << "]=----------------------------------------------------------" << std::endl;
  std::cout << std::hex << std::internal << std::setfill('0')
    << "RAX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX) << " "
    << "RBX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX) << " "
    << "RCX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX) << std::endl
    << "RDX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX) << " "
    << "RDI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI) << " "
    << "RSI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI) << std::endl
    << "RBP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP) << " "
    << "RSP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) << " "
    << "R8 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8) << std::endl
    << "R9 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9) << " "
    << "R10 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R10) << " "
    << "R11 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R11) << std::endl
    << "R12 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R12) << " "
    << "R13 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R13) << " "
    << "R14 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R14) << std::endl
    << "R15 = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_R15) << " "
    << "RIP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP) << std::endl;
  std::cout << "+-------------------------------------------------------------------" << std::endl;
}


VOID displayCurrentContext(CONTEXT *ctx, UINT32 flag)
{
    std::cout << "[" << (flag == CONTEXT_FLG ? "CONTEXT" : "SIGSGV")
    << "]=----------------------------------------------------------" << std::endl;
    std::cout << std::hex << std::internal << std::setfill('0')
    << "RAX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX) << " "
    << "RBX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX) << " "
    << "RCX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX) << std::endl
    << "RDX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX) << " "
    << "RDI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI) << " "
    << "RSI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI) << std::endl
    << "RBP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP) << " "
    << "RSP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) << " "
    << "RIP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP) << std::endl;
  std::cout << "+-------------------------------------------------------------------" << std::endl;
}

VOID dumpCurrentContext(CONTEXT *ctx, UINT32 flag, string prefix)
{
    fprintf(trace, "========================%s=====================\n", prefix.c_str());
    fprintf(trace, "RAX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX));
    fprintf(trace, "RBX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX));
    fprintf(trace, "RDI = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI));
    fprintf(trace, "RSI = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI));
    fprintf(trace, "RDX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX));
    fprintf(trace, "RCX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX));
    fprintf(trace, "RBP = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP));
    fprintf(trace, "RSP = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP));
    fprintf(trace, "R8 = %lu\n",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8));
    fprintf(trace, "R9 = %lu\n",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9));
    fprintf(trace, "======================================================\n");
}


VOID dumpCTXTrace(CONTEXT *ctx, FILE *t)
{
    fprintf(t, "========================START:%lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP));
    fprintf(t, "RAX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX));
    fprintf(t, "RBX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX));
    fprintf(t, "RDI = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI));
    fprintf(t, "RSI = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI));
    fprintf(t, "RDX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX));
    fprintf(t, "RCX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX));
    fprintf(t, "RBP = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP));
    fprintf(t, "RSP = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP));
    fprintf(t, "R8 = %lu\n",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8));
    fprintf(t, "R9 = %lu\n",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9));
    fprintf(t, "========================END============================\n");
}


VOID dump_crash_point(CONTEXT *ctx, FILE *t, LEVEL_BASE::REG r)
{
    fprintf(t, "========================START=====================\n");
    fprintf(t, "RAX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX));
    fprintf(t, "RBX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX));
    fprintf(t, "RDI = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI));
    fprintf(t, "RSI = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI));
    fprintf(t, "RDX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX));
    fprintf(t, "RCX = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX));
    fprintf(t, "RBP = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP));
    fprintf(t, "RSP = %lu\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP));
    fprintf(t, "R8 = %lu\n",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8));
    fprintf(t, "R9 = %lu\n",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9));
    fprintf(t, "taint=%s\n", REG_StringShort(r).c_str());
    fprintf(t, "========================END============================\n");
}


INT32 Usage()
{
    std::cerr << "In-Memory Fuzzing tool to capture input-output relation" << std::endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::string first_line_file(char const * fn)
{
    string sLine;
    ifstream infile(fn);

    if (infile.good())
        getline(infile, sLine);

    infile.close();
    return sLine;
}


ADDRINT hexstr_to_int(string s)
{
    ADDRINT x;
    std::stringstream ss;
    ss << s;
    ss >> x;

    return x;
}


LEVEL_BASE::REG get_reg_from_str(string s)
{
    if (strcmp(s.c_str(), "rdi") == 0)
        return LEVEL_BASE::REG_RDI;
    else if (strcmp(s.c_str(), "rsi") == 0)
        return LEVEL_BASE::REG_RSI;
    else if (strcmp(s.c_str(), "rdx") == 0)
        return LEVEL_BASE::REG_RDX;
    else if (strcmp(s.c_str(), "rcx") == 0)
        return LEVEL_BASE::REG_RCX;
    else if (strcmp(s.c_str(), "r8") == 0)
        return LEVEL_BASE::REG_R8;
    else if (strcmp(s.c_str(), "r9") == 0)
        return LEVEL_BASE::REG_R9;
    else
        return LEVEL_BASE::REG_INVALID_;

}


void initRegBeforeFuzzing(CONTEXT *ctx)
{
  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, KnobStart.Value());

  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDI, 0);
  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_RSI, 0);
  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDX, 0);
  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_RCX, 0);
  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_R8, 0);
  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_R9, 0);

  	PIN_SetContextReg(ctx, LEVEL_BASE::REG_RAX, 0);

}


std::string exec(const char* cmd)
{
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);
    return result;
}


void dataRange()
{
  char const * fn = "data_section.info";
  string sss = first_line_file(fn);
  std::vector<std::string> elems;
  elems = split(sss, ',', elems);

  rodata_b = hexstr_to_int(elems[0]);
  rodata_e = hexstr_to_int(elems[1]);

  gotplt_b = hexstr_to_int(elems[2]);
  gotplt_e = hexstr_to_int(elems[3]);

  data_b = hexstr_to_int(elems[4]);
  data_e = hexstr_to_int(elems[5]);

  bss_b = hexstr_to_int(elems[6]);
  bss_e = hexstr_to_int(elems[7]);

  return;
}


void codeRange()
{
  string a = "python analysis/codesection.py ";
  char* x = new char[a.length() + 4];

  sprintf(x, "%s %d", a.c_str(), PIN_GetPid());
  string rr = exec(x);


  std::vector<std::string> elems;
  elems = split(rr, '-', elems);
  code_b = hexstr_to_int(elems[0]);
  code_e = hexstr_to_int(elems[1]);

  return;
}


void initExecutionFlow(CONTEXT *ctx)
{
    restoreMemory();
    
    initRegBeforeFuzzing(ctx);
    initRecorder();
    dataRange();

    codeRange();

    
    trace = fopen("pinatrace.out", "w");

   
    PIN_ExecuteAt(ctx);
    return;
}


void startOneExecution(CONTEXT *ctx)
{
    if (parIndex >= KnobRegNum.Value())
    {
        cout << "[Finish Execution in Exception Handling]" << endl;
        
        return;
    }
    else
    {
        std::cout << "[Restore Context in Exception Handling]" << std::endl;
        displayCurrentContext(ctx, CONTEXT_FLG);
        PIN_SaveContext(&snapshot, ctx);
        restoreMemory();

        parIndex++;
        
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, 0);
        PIN_ExecuteAt(ctx);

        return;
    }
}


VOID checkRet(UINT64 insAddr, std::string insDis, CONTEXT *ctx)
{
    if (insAddr >= KnobStart.Value() && insAddr <= KnobEnd.Value())
    {
        if(InCur == 0)
        {
            stopFuzzing(ctx);
        }
        else
        {
            InCur--;
        }
    }
}


VOID checkJump(UINT64 insAddr, ADDRINT dst, CONTEXT *ctx)
{

    if (insAddr >= KnobStart.Value() && insAddr <= KnobEnd.Value())
    {
        if (dst < KnobStart.Value() || dst > KnobEnd.Value())
        {
          if (dst >= KnobCodeStart.Value() && dst <= (KnobCodeRange.Value() + KnobCodeStart.Value()))
            stopFuzzing(ctx);
        }
    }
}


VOID checkRecursive(ADDRINT dst, ADDRINT insAddr, CONTEXT *ctx)
{

    ADDRINT funcBegin = KnobStart.Value();
    ADDRINT funcEnd = KnobEnd.Value();

    if (dst >= funcBegin && dst <= funcEnd && insAddr >= funcBegin && insAddr <= funcEnd)
    {
        
        InCur++;
    }
}


ADDRINT getNextAddr(std::string insDis)
{
    ADDRINT nextInsAddr = 0;

    if (insDis.find("call") != std::string::npos)
    {
       
        std::vector<std::string> strs;
        boost::split(strs, insDis, boost::is_any_of("\t "));
        std::stringstream ss;
        ss << std::hex << strs[1];
        ss >> nextInsAddr;
    }
    else if (insDis.find("jmp") != std::string::npos)
    {
        
        std::vector<std::string> strs;
        boost::split(strs, insDis, boost::is_any_of("\t "));
        std::stringstream ss;
        ss << std::hex << strs[1];
        ss >> nextInsAddr;
    }
    else
    {
        nextInsAddr = -1;
    }

    return nextInsAddr;
}
void restoreMemory(void)
{
    list<struct memoryInput>::iterator i;

    for(i = memInput.begin(); i != memInput.end(); ++i){
        *(reinterpret_cast<ADDRINT*>(i->address)) = i->value;
    }
    memInput.clear();
}

bool checkPtrValid(ADDRINT ptr)
{
    if (ptr >= 0x7f0000000000)
        return true;
    else
    {
        return false;
    }
}

VOID WriteMemAll(ADDRINT insAddr, std::string insDis, ADDRINT memOp)
{
    struct memoryInput elem;
    if (checkPtrValid(memOp)) {
        ADDRINT addr = memOp;

        if (_lock == LOCKED)
            return;

        elem.address = addr;
        elem.value = *(reinterpret_cast<ADDRINT*>(addr));

        memInput.push_back(elem);
    }
    else
        return;
}


ADDRINT memAddrForRead()
{
    return (ADDRINT)ptrHeap + 20;
}


ADDRINT memAddrForWrite()
{
    return (ADDRINT)ptrHeap + 20;
}


UINT32 valueForFP()
{
    return 0xa;
}

ADDRINT randMEM(int len, ADDRINT i)
{
    return (rand() % (len)) * 8;
}

void initMemoryRegion()
{
    ptrHeap = new ADDRINT[1073];

    cout << "============= ptrHeap " << hex << ptrHeap << " ==========" << endl;
    ADDRINT i = 0;

    for (i = 0; i < 1073 - 1; i++)
    {
        ADDRINT t = (ADDRINT)ptrHeap + (i + 1)*8;
        *(ptrHeap+i) = t;
    }

    *(ptrHeap+i) = (ADDRINT)ptrHeap;

}

void resetMemoryRegion()
{
  cout << "[RESET MEMORY]" << endl;
  srand(0x232323);

  ADDRINT i = 0;
  for (i = 0; i < 1073; i++)
    {
      ADDRINT t = (ADDRINT)ptrHeap +  randMEM(1073, i);
      *(ptrHeap+i) = t;

      *(ptrHeapWrite+i) = 0;
    }

  ptrHeapReadList.clear();

  cout << "[RESET MEMORY FINISHED]" << endl;
}

void initMemoryRegionRandom()
{
    ptrHeap = new ADDRINT[1073];

    cout << "============= ptrHeap " << hex << ptrHeap << " ==========" << endl;
    ADDRINT i = 0;

    srand(0x232323);

    for (i = 0; i < 1073; i++)
      {
        ADDRINT t = (ADDRINT)ptrHeap +  randMEM(1073, i);
        *(ptrHeap+i) = t;
      }


    ptrHeapWrite = new ADDRINT[1073]();
  
    cout << "============= ptrHeapWrite " << hex << ptrHeapWrite << " ==========" << endl;

    offsetHeap = (long int)ptrHeapWrite - (long int)ptrHeap;

    rewrite_reg[0] = PIN_ClaimToolRegister();
    rewrite_reg[1] = PIN_ClaimToolRegister();
    rewrite_reg[2] = PIN_ClaimToolRegister();
}


bool inPtrheapRegion(ADDRINT ea)
{
  static ADDRINT end1 = (ADDRINT)ptrHeap + 1073 * sizeof(ADDRINT);
  static ADDRINT end2 = (ADDRINT)ptrHeapWrite + 1073 * sizeof(ADDRINT);

  if (ea >= (ADDRINT)ptrHeap && ea < end1)
    return true;

  else if (ea >= (ADDRINT)ptrHeapWrite && ea < end2)
    return true;

  else
    return false;
}


VOID RecordMemRead(VOID * ip, VOID * addr, CONTEXT *ctx)
{
  ADDRINT rsp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) - 128;
  if ((ADDRINT)addr >= code_e && (ADDRINT)addr < rsp && !(inPtrheapRegion((ADDRINT)addr)))
    fprintf(trace,"real heap r: %lu\n", *(ADDRINT*)addr);

  if ((ADDRINT)addr >= rodata_b && (ADDRINT) addr < rodata_e)
    fprintf(trace,"rodata r: %lu\n", (ADDRINT)addr-(ADDRINT)rodata_b);

  else if ((ADDRINT)addr >= data_b && (ADDRINT) addr < data_e)
    fprintf(trace,"data r: %lu\n", (ADDRINT)addr-(ADDRINT)data_b);

  else if ((ADDRINT)addr >= bss_b && (ADDRINT) addr < bss_e)
    fprintf(trace,"bss r: %lu\n", (ADDRINT)addr-(ADDRINT)bss_b);

  else if ((ADDRINT)addr >= gotplt_b && (ADDRINT) addr < gotplt_e)
    fprintf(trace,"gotplt r: %lu\n", (ADDRINT)addr-(ADDRINT)gotplt_b);

  return;
}


void UpdateMemRead(void * ip, void *addr)
{
  if (current_read_ptr != 0)
    {
      ADDRINT offset = (ADDRINT)current_read_ptr - (ADDRINT)ptrHeap;
      ptrHeapReadList.push_back(offset);

      current_read_ptr = 0;
    }
}


VOID RecordMemWrite(VOID * ip, VOID * addr, CONTEXT *ctx)
{

  if ((ADDRINT)addr >= rodata_b && (ADDRINT) addr < rodata_e)
    fprintf(trace,"rodata w: %lu\n", (ADDRINT)addr-(ADDRINT)rodata_b);

  else if ((ADDRINT)addr >= data_b && (ADDRINT) addr < data_e)
    fprintf(trace,"data w: %lu\n", (ADDRINT)addr-(ADDRINT)data_b);

  else if ((ADDRINT)addr >= bss_b && (ADDRINT) addr < bss_e)
    fprintf(trace,"bss w: %lu\n", (ADDRINT)addr-(ADDRINT)bss_b);

  else if ((ADDRINT)addr >= gotplt_b && (ADDRINT) addr < gotplt_e)
    fprintf(trace,"gotplt w: %lu\n", (ADDRINT)addr-(ADDRINT)gotplt_b);

  return;
}


void TranslateMemRead(ADDRINT ea)
{
  static ADDRINT end = (ADDRINT)ptrHeap + 1073 * sizeof(ADDRINT);
  if (ea >= (ADDRINT)ptrHeap && ea < end)
      current_read_ptr = ea;
}


static ADDRINT TranslateMemRef(ADDRINT ea)
{
  static ADDRINT end = (ADDRINT)ptrHeap + 1073 * sizeof(ADDRINT);
  if (ea >= (ADDRINT)ptrHeap && ea < end)
    {
      current_write_ptr = ea;

      return ea + offsetHeap;
    }
  else
    return ea;
}

void DumpHeapMemory()
{
  static int i;
  for (i = 0; i < 1073; i++)
    {
      if(*(ptrHeapWrite+i) != 0)
        {
          fprintf(trace,"heap w: %d %lu\n", i, *(ptrHeapWrite+i));
        }
    }

  list<ADDRINT>::iterator j;

  for(j = ptrHeapReadList.begin(); j != ptrHeapReadList.end(); ++j)
    {
      fprintf(trace,"heap r: %lu\n", *(j));
    }
}


VOID UpdateMem(VOID * ip, VOID * addr, CONTEXT *ctx)
{
  if (current_write_ptr != 0)
    {
      ADDRINT n = current_write_ptr + offsetHeap;
      memcpy((ADDRINT*)n, (ADDRINT*)current_write_ptr, sizeof(ADDRINT));

      current_write_ptr = 0;
    }

  ADDRINT rsp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) - 128;
  if ((ADDRINT)addr >= code_e && (ADDRINT)addr < rsp && !(inPtrheapRegion((ADDRINT)addr)))
    fprintf(trace,"real heap w: %lu\n", *(ADDRINT*)addr);
}


void traceMemory(INS ins)
{
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    ASSERTX(memOperands <= 3);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {

        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_CONTEXT,
                IARG_END);

            INS_InsertPredicatedCall(
                                     ins, IPOINT_BEFORE, (AFUNPTR)TranslateMemRead,
                                     IARG_MEMORYOP_EA, (ADDRINT)memOp,
                                     IARG_END);


            if (INS_HasFallThrough(ins))
              {
                INS_InsertPredicatedCall(
                                         ins, IPOINT_AFTER, (AFUNPTR)UpdateMemRead,
                                         IARG_INST_PTR,
                                         IARG_END);
              }
        }

        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TranslateMemRef,
                         IARG_MEMORYOP_EA, (ADDRINT)memOp,
                         IARG_RETURN_REGS, rewrite_reg[memOp],
                         IARG_END);

          INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                                   IARG_INST_PTR,
                                   IARG_MEMORYOP_EA, memOp,
                                   IARG_CONTEXT,
                                   IARG_END);

          if (INS_HasFallThrough(ins))
            {
              INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)UpdateMem,
                                       IARG_INST_PTR,
                                       IARG_MEMORYOP_EA, memOp,
                                       IARG_CONTEXT,
                                       IARG_END);
            }
        }
    }

    return;
}
bool fixMemoryAccessError(ADDRINT exptaddr, FAULTY_ACCESS_TYPE ty, ADDRINT faddr, CONTEXT *ctx)
{
    instrRecord ir = getInstrByAddrOperand(exptaddr);

    if (ir.insDis == "dummy")
    {

        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, mra);

        return false;
    }
    else
    {
        LEVEL_BASE::OPCODE op = ir.op;

        if (isControlOP(op) == true)
        {
            PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, ir.addrNext);

            return false;
        }
        else
        {
            bool mr = fixMemReadNew(ir.regRead, faddr, ctx);
            bool mw = fixMemWriteNew(ir.regWrite, faddr, ctx);

            if (mr == true && mw == false)
                return false;
            else if (mr == false && mw == true)
                return false;
            else if (mr == true && mw == true)
                return false;
            else
                return true;
        }
    }
}


bool analysisExcept(const EXCEPTION_INFO *pExceptInfo, CONTEXT *ctx)
{
    cout << "AnalysisHandler: Caught exception. " << PIN_ExceptionToString(pExceptInfo) << endl;

    if (PIN_GetExceptionCode(pExceptInfo) == EXCEPTCODE_ACCESS_INVALID_ADDRESS)
    {
        ADDRINT exptAddr = PIN_GetExceptionAddress(pExceptInfo);

        ADDRINT *faddr = new ADDRINT;
        PIN_GetFaultyAccessAddress(pExceptInfo, faddr);
        FAULTY_ACCESS_TYPE ty = PIN_GetFaultyAccessType(pExceptInfo);

        if (exptAddr != 0)
        {
            bool res = fixMemoryAccessError(exptAddr, ty, *faddr, ctx);
            delete faddr;
            return res;
        }
        else
        {
            delete faddr;
            return true;
        }
    }
    else if (PIN_GetExceptionCode(pExceptInfo) == EXCEPTCODE_PRIVILEGED_INS)
    {
        ADDRINT exptAddr = PIN_GetExceptionAddress(pExceptInfo);
        instrRecord ir = getInstrByAddrOperand(exptAddr);
        if (ir.insDis == "dummy")
        {
            PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, mra);
            return false;
        }
        else
        {
            LEVEL_BASE::OPCODE op = ir.op;
            if (isControlOP(op) == true)
            {
                PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, ir.addrNext);
                return false;
            }
            else
            {
                PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, ir.addrNext);
                return false;
            }
        }
    }
    else
    {
        ADDRINT exptAddr = PIN_GetExceptionAddress(pExceptInfo);
        instrRecord ir = getInstrByAddrOperand(exptAddr);
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, ir.addrNext);
        return false;
    }
}


BOOL catchSignalSEGV(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
    if (fuzzProcess == true) {
        std::cout << std::endl << std::endl << "/!\\ SIGSEGV received /!\\" << std::endl;
        displayCurrentContext_Full(ctx, CONTEXT_FLG);

        return analysisExcept(pExceptInfo, ctx);
    }
    else {
        return true;
    }

}


bool fixFPError(ADDRINT exptaddr, CONTEXT *ctx)
{
    instrRecord ir = getInstrByAddrOperand(exptaddr);
    bool fp = fixFPInstr(ir.fpr, ctx);

    if (fp == true)
        return false;
    else
        return true;
}


bool analysisExceptFP(const EXCEPTION_INFO *pExceptInfo, CONTEXT *ctx)
{
    cout << "AnalysisHandlerFP: Caught exception. " << PIN_ExceptionToString(pExceptInfo) << endl;

    if (PIN_GetExceptionCode(pExceptInfo) == EXCEPTCODE_INT_DIVIDE_BY_ZERO)
    {
        ADDRINT exptAddr = PIN_GetExceptionAddress(pExceptInfo);

        if (exptAddr != 0)
        {
            bool res = fixFPError(exptAddr, ctx);
            return res;
        }
        else
        {
            cout << "undefined exception" << endl;
            return true;
        }
    }
    else
    {
        cout << "undefined exception" << endl;
        return true;
    }
}


BOOL catchSignalFP(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
    if (fuzzProcess == true) {
        std::cout << std::endl << std::endl << "/!\\ SIGSEGV received /!\\" << std::endl;

        return analysisExceptFP(pExceptInfo, ctx);
    }
    else {
        return true;
    }
}
VOID randomMutation()
{
    sleep(1);
    srand(time(NULL));
    fuzzValue = (rand() % (0xffffffff - KnobStartValue.Value())) + KnobStartValue.Value();
}


VOID stepMutation()
{
    cout << "fuzzing value " << fuzzValue << endl;
    fuzzValue += 0x10;
    cout << "fuzzing value " << fuzzValue << endl;
}


VOID mutateREG(CONTEXT *ctx, ADDRINT nextInsAddr, ADDRINT callAddr)
{
  if (KnobFuzzType.Value() == "random")
      randomMutation();
  else if (KnobFuzzType.Value() == "inc")
      fuzzValue++;
  else
      fuzzValue = fuzzValue;

  PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, KnobStart.Value());
}


void update_context(CONTEXT *ctx, int parindex, int fuzzcount)
{
  int index = parindex*6 + fuzzcount;
  cout << "i am " << index << endl;
  
  UINT64 *arr = fuzzing_context[index];

  cout << "i am " << arr << endl;
  int i = 0;
  int l = sizeof(parList)/sizeof(UINT32);

  for (i = 0; i< l; i++)
    {
      REG r = intputRegsRef[i];
      UINT64 fv = arr[i];

      PIN_SetContextReg(ctx, r, fv);
    }

  displayCurrentContext(ctx, CONTEXT_FLG);
  return;
}


void mutate_ctx(CONTEXT *ctx)
{
  cout << "FUZZCOUNT " << fuzzCount << " PARINDEX " << parIndex << endl;
  if (fuzzCount == 0)
    {
      if (parIndex >= sizeof(parList)/sizeof(UINT32))
        {
          PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, KnobStart.Value());
          return;
        }
    }

  update_context(ctx, parIndex, fuzzCount);

  fuzzCount++;
  if (fuzzCount == KnobFuzzCount.Value())
    {
      parIndex++;
      fuzzCount = 0;
    }
}

VOID mutate(CONTEXT *ctx)
{
    cout << "FUZZCOUNT " << fuzzCount << " PARINDEX " << parIndex << endl;
    if (fuzzCount == 0)
    {
        if (parIndex >= sizeof(parList)/sizeof(UINT32))
        {
            PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, KnobStart.Value());
            return;
        }

        REG r = regsRef[parList[parIndex]].ref;
        fuzzValue = PIN_GetContextReg(ctx, r);
    }

    if (KnobFuzzType.Value() == "random")
        randomMutation();
    else if (KnobFuzzType.Value() == "inc")
        fuzzValue++;
    else if (KnobFuzzType.Value() == "step")
        stepMutation();
    else
        fuzzValue = fuzzValue;

    REG r = regsRef[parList[parIndex]].ref;
    PIN_SetContextReg(ctx, r, fuzzValue);
    fuzzCount++;
    if (fuzzCount == KnobFuzzCount.Value())
    {
        parIndex++;
        fuzzCount = 0;
    }
}
void finishFuzzing(CONTEXT *ctx)
{
    std::cout << "[IN-MEMORY FUZZING STOPPED]" << std::endl;
    fprintf(trace,"MEMORY TRACING FINISHED\n");

    fuzzProcess = false;

    Fini(0, 0);

    return PIN_RemoveInstrumentation();
}

void resumeFromStart(CONTEXT *ctx)
{
    _resume = true;
    std::cout << "[RESTART FUZZING, RESTORE CONTEXT]" << std::endl;

    instrTrace.clear();

    typedef std::map<ADDRINT, bool>::iterator it_type;
    for(it_type iterator = inputHasFixMap.begin(); iterator != inputHasFixMap.end(); iterator++) {
        ADDRINT k = iterator->first;
	inputHasFixMap[k] = false;
    }

    PIN_SaveContext(&lastFuzzingCTX, ctx);
    restoreMemory();

    resetMemoryRegion();
    PIN_ExecuteAt(ctx);
}


void startFuzzing(CONTEXT *ctx, ADDRINT nextInsAddr, ADDRINT callNext)
{
    std::cout << "[START FUZZING, SAVE CONTEXT]" << std::endl;

    PIN_SaveContext(ctx, &snapshot);
    mutate_ctx(ctx);
    
    dumpCurrentContext(ctx, CONTEXT_FLG, "START");

    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, KnobStart.Value());

    typedef std::map<ADDRINT, bool>::iterator it_type;
    for(it_type iterator = inputHasFixMap.begin(); iterator != inputHasFixMap.end(); iterator++) {
        ADDRINT k = iterator->first;
	inputHasFixMap[k] = false;
    }
    
    PIN_SaveContext(ctx, &lastFuzzingCTX);
    _lock = UNLOCKED;
    resetMemoryRegion();
    instrTrace.clear();
    PIN_ExecuteAt(ctx);
}


void stopFuzzing(CONTEXT *ctx)
{
    _lock = LOCKED;
    std::cout << "[STOP FUZZING, RESTORE CONTEXT]" << std::endl;
    
    DumpHeapMemory();
    dumpCurrentContext(ctx, CONTEXT_FLG, "END");
    PIN_SaveContext(&snapshot, ctx);
    restoreMemory();

    PIN_ExecuteAt(ctx);
}
void audit(ADDRINT insAddr, std::string insDis, CONTEXT *ctx)
{
      if (inputMap.find(insAddr) != inputMap.end() && inputHasFixMap[insAddr] == false)
        {
            cout << "[FOUND AUDIT TARGET]" << endl;
            LEVEL_BASE::REG cr = inputMap[insAddr];
            PIN_SetContextReg(ctx, cr, memAddrForRead());

	    inputHasFixMap[insAddr] = true;
            cout << "[FIX MEMORY ERROR] : " << hex << insAddr << " : " << insDis << endl;
            _resume = false;
            PIN_ExecuteAt(ctx);
        }
}

VOID resumeExecute(ADDRINT insAddr, std::string insDis, CONTEXT *ctx, ADDRINT nextInsAddr)
{
    if (_start_resume == true)
    {
        cout << "[RESUME EXECUTION] : " << hex << insAddr << insDis << endl;
        _start_resume = false;
        resumeFromStart(ctx);
    }
    else
        return;
}


VOID insCallBack(bool check, ADDRINT insAddr, std::string insDis, CONTEXT *ctx, ADDRINT nextInsAddr)
{
    resumeExecute(insAddr, insDis, ctx, nextInsAddr);

    if (_first == true)
    {
        _first = false;
        cout << "[INIT FUZZING ENV]" << endl;

        initExecutionFlow(ctx);
        return;
    }

    ADDRINT callNext = nextInsAddr;
    if (analyzed == false)
    {
        
        if (InCur == 0)
        {
            if (_resume == false)
            {
                
                if (insAddr == KnobStart.Value())
                {
                    if (parIndex >= sizeof(parList)/sizeof(UINT32))
                        
                        finishFuzzing(ctx);
                    else
                    {
                       
                        analyzed = true;
                        startFuzzing(ctx, nextInsAddr, callNext);
                    }
                }
            }
        }
    }
    else
        analyzed = false;


    if (_lock == LOCKED)
        return;

    
    audit(insAddr, insDis, ctx);

    std::cout << "+--> " << std::hex << insAddr << ": " << insDis << std::endl;
   

    std::stringstream out;
    out << insAddr;
    instrTrace.push_back(out.str() + ": " + insDis);
    ctxTrace.push_back(*ctx);

    if (insAddr >= KnobStart.Value() && insAddr <= KnobEnd.Value())
        mra = callNext;
}


VOID Instruction(INS ins, VOID *v)
{
    PIN_LockClient();
    IMG img = IMG_FindByAddress(INS_Address(ins));
    PIN_UnlockClient();

    bool check = INS_HasFallThrough(ins);
    if (IMG_Valid(img) && IMG_IsMainExecutable(img)){
        
        traceMemory(ins);

        recordInstrOperand(INS_Address(ins), ins);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)insCallBack,
                       IARG_BOOL, check,
                       IARG_ADDRINT, INS_Address(ins),
                       IARG_PTR, new string(INS_Disassemble(ins)),
                       IARG_CONTEXT,
                       IARG_ADDRINT, INS_NextAddress(ins),
                       IARG_END);


           if (INS_MemoryOperandIsWritten(ins, 0)){
               INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMemAll,
                              IARG_ADDRINT, INS_Address(ins),
                              IARG_PTR, new string(INS_Disassemble(ins)),
                              IARG_MEMORYOP_EA, 0,
                              IARG_END);
           }


        if (INS_IsRet(ins)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)checkRet,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_END);
        }

        if (INS_IsDirectBranchOrCall(ins) || INS_IsIndirectBranchOrCall(ins)){
            if(INS_IsCall(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) checkRecursive,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_BRANCH_TARGET_ADDR,
                               IARG_CONTEXT,
                               IARG_END);

                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) recordCall,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_BRANCH_TARGET_ADDR,
                               IARG_END);
            }
            else
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) checkJump,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_BRANCH_TARGET_ADDR,
                               IARG_CONTEXT,
                               IARG_END);
            }
        }

    }

    return;
}
