#import pypatt
from z3 import *

def check_reg_taint(r, sym):
    return r in sym.regs_tainted


def remove_mem_tainted(addr, sym):
    del sym.addr_tainted[addr]
    print (">>>>>>>", addr, " is now freed")


def add_mem_tainted(addr, sym):
    sym.addr_tainted[addr] = sym.get_cur_addr()
    print (">>>>>>>>", addr, " is now tainted")

def taint_reg(reg, sym):
    addr = sym.get_cur_addr()
    return taint_reg_true(reg, addr, sym)

def taint_reg_true(reg, addr, sym):

    if reg ==  "rax":
        sym.regs_tainted["rax"] = addr
        sym.regs_tainted["eax"] = addr
        sym.regs_tainted["ax"] = addr
        sym.regs_tainted["ah"] = addr
        sym.regs_tainted["al"] = addr
    elif reg ==  "eax":
        sym.regs_tainted["eax"] = addr
        sym.regs_tainted["ax"] = addr
        sym.regs_tainted["ah"] = addr
        sym.regs_tainted["al"] = addr
    elif reg ==  "ax":
        sym.regs_tainted["ax"] = addr
        sym.regs_tainted["ah"] = addr
        sym.regs_tainted["al"] = addr
    elif reg ==  "ah":
        sym.regs_tainted["ah"] = addr
    elif reg ==  "al":
        sym.regs_tainted["al"] = addr

    elif reg ==  "rbx":
        sym.regs_tainted["rbx"] = addr
        sym.regs_tainted["ebx"] = addr
        sym.regs_tainted["bx"] = addr
        sym.regs_tainted["bh"] = addr
        sym.regs_tainted["bl"] = addr
    elif reg ==  "ebx":
        sym.regs_tainted["ebx"] = addr
        sym.regs_tainted["bx"] = addr
        sym.regs_tainted["bh"] = addr
        sym.regs_tainted["bl"] = addr
    elif reg ==  "bx":
        sym.regs_tainted["bx"] = addr
        sym.regs_tainted["bh"] = addr
        sym.regs_tainted["bl"] = addr
    elif reg ==  "bh":
        sym.regs_tainted["bh"] = addr
    elif reg ==  "bl":
        sym.regs_tainted["bl"] = addr

    elif reg ==  "rcx":
        sym.regs_tainted["rcx"] = addr
        sym.regs_tainted["ecx"] = addr
        sym.regs_tainted["cx"] = addr
        sym.regs_tainted["ch"] = addr
        sym.regs_tainted["cl"] = addr
    elif reg ==  "ecx":
        sym.regs_tainted["ecx"] = addr
        sym.regs_tainted["cx"] = addr
        sym.regs_tainted["ch"] = addr
        sym.regs_tainted["cl"] = addr
    elif reg ==  "cx":
        sym.regs_tainted["cx"] = addr
        sym.regs_tainted["ch"] = addr
        sym.regs_tainted["cl"] = addr
    elif reg ==  "ch":
        sym.regs_tainted["ch"] = addr
    elif reg ==  "cl":
        sym.regs_tainted["cl"] = addr

    elif reg ==  "rdx":
        sym.regs_tainted["rdx"] = addr
        sym.regs_tainted["edx"] = addr
        sym.regs_tainted["dx"] = addr
        sym.regs_tainted["dh"] = addr
        sym.regs_tainted["dl"] = addr
    elif reg ==  "edx":
        sym.regs_tainted["edx"] = addr
        sym.regs_tainted["dx"] = addr
        sym.regs_tainted["dh"] = addr
        sym.regs_tainted["dl"] = addr
    elif reg ==  "dx":
        sym.regs_tainted["dx"] = addr
        sym.regs_tainted["dh"] = addr
        sym.regs_tainted["dl"] = addr
    elif reg ==  "dh":
        sym.regs_tainted["dh"] = addr
    elif reg ==  "dl":
        sym.regs_tainted["dl"] = addr

    elif reg ==  "r8":
        sym.regs_tainted["r8"] = addr
        sym.regs_tainted["r8d"] = addr
        sym.regs_tainted["r8w"] = addr
        sym.regs_tainted["r8b"] = addr
    elif reg ==  "r8d":
        sym.regs_tainted["r8d"] = addr
        sym.regs_tainted["r8w"] = addr
        sym.regs_tainted["r8b"] = addr
    elif reg ==  "r8w":
        sym.regs_tainted["r8w"] = addr
        sym.regs_tainted["r8b"] = addr
    elif reg ==  "r8b":
        sym.regs_tainted["r8b"] = addr

    elif reg ==  "r9":
        sym.regs_tainted["r9"] = addr
        sym.regs_tainted["r9d"] = addr
        sym.regs_tainted["r9w"] = addr
        sym.regs_tainted["r9b"] = addr
    elif reg ==  "r9d":
        sym.regs_tainted["r9d"] = addr
        sym.regs_tainted["r9w"] = addr
        sym.regs_tainted["r9b"] = addr
    elif reg ==  "r9w":
        sym.regs_tainted["r9w"] = addr
        sym.regs_tainted["r9b"] = addr
    elif reg ==  "r9b":
        sym.regs_tainted["r9b"] = addr

    elif reg ==  "r10":
        sym.regs_tainted["r10"] = addr
        sym.regs_tainted["r10d"] = addr
        sym.regs_tainted["r10w"] = addr
        sym.regs_tainted["r10b"] = addr
    elif reg ==  "r10d":
        sym.regs_tainted["r10d"] = addr
        sym.regs_tainted["r10w"] = addr
        sym.regs_tainted["r10b"] = addr
    elif reg ==  "r10w":
        sym.regs_tainted["r10w"] = addr
        sym.regs_tainted["r10b"] = addr
    elif reg ==  "r10b":
        sym.regs_tainted["r10b"] = addr

    elif reg ==  "r11":
        sym.regs_tainted["r11"] = addr
        sym.regs_tainted["r11d"] = addr
        sym.regs_tainted["r11w"] = addr
        sym.regs_tainted["r11b"] = addr
    elif reg ==  "r11d":
        sym.regs_tainted["r11d"] = addr
        sym.regs_tainted["r11w"] = addr
        sym.regs_tainted["r11b"] = addr
    elif reg ==  "r11w":
        sym.regs_tainted["r11w"] = addr
        sym.regs_tainted["r11b"] = addr
    elif reg ==  "r11b":
        sym.regs_tainted["r11b"] = addr

    elif reg ==  "r12":
        sym.regs_tainted["r12"] = addr
        sym.regs_tainted["r12d"] = addr
        sym.regs_tainted["r12w"] = addr
        sym.regs_tainted["r12b"] = addr
    elif reg ==  "r12d":
        sym.regs_tainted["r12d"] = addr
        sym.regs_tainted["r12w"] = addr
        sym.regs_tainted["r12b"] = addr
    elif reg ==  "r12w":
        sym.regs_tainted["r12w"] = addr
        sym.regs_tainted["r12b"] = addr
    elif reg ==  "r12b":
        sym.regs_tainted["r12b"] = addr

    elif reg ==  "r13":
        sym.regs_tainted["r13"] = addr
        sym.regs_tainted["r13d"] = addr
        sym.regs_tainted["r13w"] = addr
        sym.regs_tainted["r13b"] = addr
    elif reg ==  "r13d":
        sym.regs_tainted["r13d"] = addr
        sym.regs_tainted["r13w"] = addr
        sym.regs_tainted["r13b"] = addr
    elif reg ==  "r13w":
        sym.regs_tainted["r13w"] = addr
        sym.regs_tainted["r13b"] = addr
    elif reg ==  "r13b":
        sym.regs_tainted["r13b"] = addr

    elif reg ==  "r14":
        sym.regs_tainted["r14"] = addr
        sym.regs_tainted["r14d"] = addr
        sym.regs_tainted["r14w"] = addr
        sym.regs_tainted["r14b"] = addr
    elif reg ==  "r14d":
        sym.regs_tainted["r14d"] = addr
        sym.regs_tainted["r14w"] = addr
        sym.regs_tainted["r14b"] = addr
    elif reg ==  "r14w":
        sym.regs_tainted["r14w"] = addr
        sym.regs_tainted["r14b"] = addr
    elif reg ==  "r14b":
        sym.regs_tainted["r14b"] = addr

    elif reg ==  "r15":
        sym.regs_tainted["r15"] = addr
        sym.regs_tainted["r15d"] = addr
        sym.regs_tainted["r15w"] = addr
        sym.regs_tainted["r15b"] = addr
    elif reg ==  "r15d":
        sym.regs_tainted["r15d"] = addr
        sym.regs_tainted["r15w"] = addr
        sym.regs_tainted["r15b"] = addr
    elif reg ==  "r15w":
        sym.regs_tainted["r15w"] = addr
        sym.regs_tainted["r15b"] = addr
    elif reg ==  "r15b":
        sym.regs_tainted["r15b"] = addr

    elif reg ==  "rdi":
        sym.regs_tainted["rdi"] = addr
        sym.regs_tainted["edi"] = addr
        sym.regs_tainted["di"] = addr
        sym.regs_tainted["dil"] = addr
    elif reg ==  "edi":
        sym.regs_tainted["edi"] = addr
        sym.regs_tainted["di"] = addr
        sym.regs_tainted["dil"] = addr
    elif reg ==  "di":
        sym.regs_tainted["di"] = addr
        sym.regs_tainted["dil"] = addr
    elif reg ==  "dil":
        sym.regs_tainted["dil"] = addr

    elif reg ==  "rsi":
        sym.regs_tainted["rsi"] = addr
        sym.regs_tainted["esi"] = addr
        sym.regs_tainted["si"] = addr
        sym.regs_tainted["sil"] = addr
    elif reg ==  "esi":
        sym.regs_tainted["esi"] = addr
        sym.regs_tainted["si"] = addr
        sym.regs_tainted["sil"] = addr
    elif reg ==  "si":
        sym.regs_tainted["si"] = addr
        sym.regs_tainted["sil"] = addr
    elif reg ==  "sil":
        sym.regs_tainted["sil"] = addr

    elif reg ==  "t0":
        sym.regs_tainted["t0"] = addr
    elif reg ==  "t1":
        sym.regs_tainted["t1"] = addr

    elif reg ==  "rbp":
        sym.regs_tainted["rbp"] = addr
        sym.regs_tainted["ebp"] = addr
    elif reg ==  "ebp":
        sym.regs_tainted["ebp"] = addr

    elif reg ==  _:
        print (">>>>>>", reg, " can't be tainted")
        return False

    print ">>>>>> " + reg + " is tainted now"
    return True

'''#@pypatt.transform
def taint_reg_true(reg, addr, sym):

    with match(reg):
        with "rax":
            sym.regs_tainted["rax"] = addr
            sym.regs_tainted["eax"] = addr
            sym.regs_tainted["ax"] = addr
            sym.regs_tainted["ah"] = addr
            sym.regs_tainted["al"] = addr
        with "eax":
            sym.regs_tainted["eax"] = addr
            sym.regs_tainted["ax"] = addr
            sym.regs_tainted["ah"] = addr
            sym.regs_tainted["al"] = addr
        with "ax":
            sym.regs_tainted["ax"] = addr
            sym.regs_tainted["ah"] = addr
            sym.regs_tainted["al"] = addr
        with "ah":
            sym.regs_tainted["ah"] = addr
        with "al":
            sym.regs_tainted["al"] = addr

        with "rbx":
            sym.regs_tainted["rbx"] = addr
            sym.regs_tainted["ebx"] = addr
            sym.regs_tainted["bx"] = addr
            sym.regs_tainted["bh"] = addr
            sym.regs_tainted["bl"] = addr
        with "ebx":
            sym.regs_tainted["ebx"] = addr
            sym.regs_tainted["bx"] = addr
            sym.regs_tainted["bh"] = addr
            sym.regs_tainted["bl"] = addr
        with "bx":
            sym.regs_tainted["bx"] = addr
            sym.regs_tainted["bh"] = addr
            sym.regs_tainted["bl"] = addr
        with "bh":
            sym.regs_tainted["bh"] = addr
        with "bl":
            sym.regs_tainted["bl"] = addr

        with "rcx":
            sym.regs_tainted["rcx"] = addr
            sym.regs_tainted["ecx"] = addr
            sym.regs_tainted["cx"] = addr
            sym.regs_tainted["ch"] = addr
            sym.regs_tainted["cl"] = addr
        with "ecx":
            sym.regs_tainted["ecx"] = addr
            sym.regs_tainted["cx"] = addr
            sym.regs_tainted["ch"] = addr
            sym.regs_tainted["cl"] = addr
        with "cx":
            sym.regs_tainted["cx"] = addr
            sym.regs_tainted["ch"] = addr
            sym.regs_tainted["cl"] = addr
        with "ch":
            sym.regs_tainted["ch"] = addr
        with "cl":
            sym.regs_tainted["cl"] = addr

        with "rdx":
            sym.regs_tainted["rdx"] = addr
            sym.regs_tainted["edx"] = addr
            sym.regs_tainted["dx"] = addr
            sym.regs_tainted["dh"] = addr
            sym.regs_tainted["dl"] = addr
        with "edx":
            sym.regs_tainted["edx"] = addr
            sym.regs_tainted["dx"] = addr
            sym.regs_tainted["dh"] = addr
            sym.regs_tainted["dl"] = addr
        with "dx":
            sym.regs_tainted["dx"] = addr
            sym.regs_tainted["dh"] = addr
            sym.regs_tainted["dl"] = addr
        with "dh":
            sym.regs_tainted["dh"] = addr
        with "dl":
            sym.regs_tainted["dl"] = addr

        with "r8":
            sym.regs_tainted["r8"] = addr
            sym.regs_tainted["r8d"] = addr
            sym.regs_tainted["r8w"] = addr
            sym.regs_tainted["r8b"] = addr
        with "r8d":
            sym.regs_tainted["r8d"] = addr
            sym.regs_tainted["r8w"] = addr
            sym.regs_tainted["r8b"] = addr
        with "r8w":
            sym.regs_tainted["r8w"] = addr
            sym.regs_tainted["r8b"] = addr
        with "r8b":
            sym.regs_tainted["r8b"] = addr

        with "r9":
            sym.regs_tainted["r9"] = addr
            sym.regs_tainted["r9d"] = addr
            sym.regs_tainted["r9w"] = addr
            sym.regs_tainted["r9b"] = addr
        with "r9d":
            sym.regs_tainted["r9d"] = addr
            sym.regs_tainted["r9w"] = addr
            sym.regs_tainted["r9b"] = addr
        with "r9w":
            sym.regs_tainted["r9w"] = addr
            sym.regs_tainted["r9b"] = addr
        with "r9b":
            sym.regs_tainted["r9b"] = addr

        with "r10":
            sym.regs_tainted["r10"] = addr
            sym.regs_tainted["r10d"] = addr
            sym.regs_tainted["r10w"] = addr
            sym.regs_tainted["r10b"] = addr
        with "r10d":
            sym.regs_tainted["r10d"] = addr
            sym.regs_tainted["r10w"] = addr
            sym.regs_tainted["r10b"] = addr
        with "r10w":
            sym.regs_tainted["r10w"] = addr
            sym.regs_tainted["r10b"] = addr
        with "r10b":
            sym.regs_tainted["r10b"] = addr

        with "r11":
            sym.regs_tainted["r11"] = addr
            sym.regs_tainted["r11d"] = addr
            sym.regs_tainted["r11w"] = addr
            sym.regs_tainted["r11b"] = addr
        with "r11d":
            sym.regs_tainted["r11d"] = addr
            sym.regs_tainted["r11w"] = addr
            sym.regs_tainted["r11b"] = addr
        with "r11w":
            sym.regs_tainted["r11w"] = addr
            sym.regs_tainted["r11b"] = addr
        with "r11b":
            sym.regs_tainted["r11b"] = addr

        with "r12":
            sym.regs_tainted["r12"] = addr
            sym.regs_tainted["r12d"] = addr
            sym.regs_tainted["r12w"] = addr
            sym.regs_tainted["r12b"] = addr
        with "r12d":
            sym.regs_tainted["r12d"] = addr
            sym.regs_tainted["r12w"] = addr
            sym.regs_tainted["r12b"] = addr
        with "r12w":
            sym.regs_tainted["r12w"] = addr
            sym.regs_tainted["r12b"] = addr
        with "r12b":
            sym.regs_tainted["r12b"] = addr

        with "r13":
            sym.regs_tainted["r13"] = addr
            sym.regs_tainted["r13d"] = addr
            sym.regs_tainted["r13w"] = addr
            sym.regs_tainted["r13b"] = addr
        with "r13d":
            sym.regs_tainted["r13d"] = addr
            sym.regs_tainted["r13w"] = addr
            sym.regs_tainted["r13b"] = addr
        with "r13w":
            sym.regs_tainted["r13w"] = addr
            sym.regs_tainted["r13b"] = addr
        with "r13b":
            sym.regs_tainted["r13b"] = addr

        with "r14":
            sym.regs_tainted["r14"] = addr
            sym.regs_tainted["r14d"] = addr
            sym.regs_tainted["r14w"] = addr
            sym.regs_tainted["r14b"] = addr
        with "r14d":
            sym.regs_tainted["r14d"] = addr
            sym.regs_tainted["r14w"] = addr
            sym.regs_tainted["r14b"] = addr
        with "r14w":
            sym.regs_tainted["r14w"] = addr
            sym.regs_tainted["r14b"] = addr
        with "r14b":
            sym.regs_tainted["r14b"] = addr

        with "r15":
            sym.regs_tainted["r15"] = addr
            sym.regs_tainted["r15d"] = addr
            sym.regs_tainted["r15w"] = addr
            sym.regs_tainted["r15b"] = addr
        with "r15d":
            sym.regs_tainted["r15d"] = addr
            sym.regs_tainted["r15w"] = addr
            sym.regs_tainted["r15b"] = addr
        with "r15w":
            sym.regs_tainted["r15w"] = addr
            sym.regs_tainted["r15b"] = addr
        with "r15b":
            sym.regs_tainted["r15b"] = addr

        with "rdi":
            sym.regs_tainted["rdi"] = addr
            sym.regs_tainted["edi"] = addr
            sym.regs_tainted["di"] = addr
            sym.regs_tainted["dil"] = addr
        with "edi":
            sym.regs_tainted["edi"] = addr
            sym.regs_tainted["di"] = addr
            sym.regs_tainted["dil"] = addr
        with "di":
            sym.regs_tainted["di"] = addr
            sym.regs_tainted["dil"] = addr
        with "dil":
            sym.regs_tainted["dil"] = addr

        with "rsi":
            sym.regs_tainted["rsi"] = addr
            sym.regs_tainted["esi"] = addr
            sym.regs_tainted["si"] = addr
            sym.regs_tainted["sil"] = addr
        with "esi":
            sym.regs_tainted["esi"] = addr
            sym.regs_tainted["si"] = addr
            sym.regs_tainted["sil"] = addr
        with "si":
            sym.regs_tainted["si"] = addr
            sym.regs_tainted["sil"] = addr
        with "sil":
            sym.regs_tainted["sil"] = addr

        with "t0":
            sym.regs_tainted["t0"] = addr
        with "t1":
            sym.regs_tainted["t1"] = addr

        with "rbp":
            sym.regs_tainted["rbp"] = addr
            sym.regs_tainted["ebp"] = addr
        with "ebp":
            sym.regs_tainted["ebp"] = addr

        with _:
            print (">>>>>>", reg, " can't be tainted")
            return False

    print ">>>>>> " + reg + " is tainted now"
    return True'''


def read_mem(r, mem_addr, sym):
    ins_addr = sym.get_cur_addr()

    if mem_addr in sym.addr_tainted:
        print ("[READ in ", mem_addr, "]\t", ins_addr)

        taint_reg(r, sym)
        remove_mem_tainted(mem_addr, sym)
        return

    if check_reg_taint(r, sym):
        print ("[READ in ", mem_addr, "]\t", ins_addr)

        remove_taint_reg(r, sym)



def write_mem(r, mem_addr, sym):
    ins_addr = sym.get_cur_addr()

    if mem_addr in sym.addr_tainted:
        print ("[WRITE in ", mem_addr, "]\t", ins_addr)

        if check_reg_taint(r, sym):
            remove_mem_tainted(mem_addr, sym)

    if check_reg_taint(r, sym):
        print ("[WRITE in ", mem_addr, "]\t", ins_addr)

        add_mem_tainted(mem_addr, sym)

        remove_taint_reg(r, sym)


def spread_reg_taint(reg_r, reg_w, sym):
    ins_addr = sym.get_cur_addr()

    if check_reg_taint(reg_w, sym) and not (check_reg_taint(reg_r, sym)):
        print ("[SPREAD]", ins_addr)
        print (">>>>>>>> output: ", reg_w, " | input : ", reg_r)

        taint_reg(reg_w, sym)


    elif (not check_reg_taint(reg_w, sym)) and check_reg_taint(reg_r, sym):
        print ("[SPREAD]", ins_addr)
        print (">>>>>>>> output: ", reg_w, " | input : ", reg_r)

        taint_reg(reg_w, sym)
        remove_taint_reg(reg_r, sym)

def remove_taint_reg(reg, sym):
    if not (check_reg_taint(reg, sym)):
        print (reg, " is not tainted")
        return False

    if reg == "rax":
        del sym.regs_tainted["rax"]
        del sym.regs_tainted["eax"]
        del sym.regs_tainted["ax"]
        del sym.regs_tainted["ah"]
        del sym.regs_tainted["al"]
    elif reg == "eax":
        del sym.regs_tainted["eax"]
        del sym.regs_tainted["ax"]
        del sym.regs_tainted["ah"]
        del sym.regs_tainted["al"]
    elif reg == "ax":
        del sym.regs_tainted["ax"]
        del sym.regs_tainted["ah"]
        del sym.regs_tainted["al"]
    elif reg == "ah":
        del sym.regs_tainted["ah"]
    elif reg == "al":
        del sym.regs_tainted["al"]

    elif reg == "rbx":
        del sym.regs_tainted["rbx"]
        del sym.regs_tainted["ebx"]
        del sym.regs_tainted["bx"]
        del sym.regs_tainted["bh"]
        del sym.regs_tainted["bl"]
    elif reg == "ebx":
        del sym.regs_tainted["ebx"]
        del sym.regs_tainted["bx"]
        del sym.regs_tainted["bh"]
        del sym.regs_tainted["bl"]
    elif reg == "bx":
        del sym.regs_tainted["bx"]
        del sym.regs_tainted["bh"]
        del sym.regs_tainted["bl"]
    elif reg == "bh":
        del sym.regs_tainted["bh"]
    elif reg == "bl":
        del sym.regs_tainted["bl"]

    elif reg == "rcx":
        del sym.regs_tainted["rcx"]
        del sym.regs_tainted["ecx"]
        del sym.regs_tainted["cx"]
        del sym.regs_tainted["ch"]
        del sym.regs_tainted["cl"]
    elif reg == "ecx":
        del sym.regs_tainted["ecx"]
        del sym.regs_tainted["cx"]
        del sym.regs_tainted["ch"]
        del sym.regs_tainted["cl"]
    elif reg == "cx":
        del sym.regs_tainted["cx"]
        del sym.regs_tainted["ch"]
        del sym.regs_tainted["cl"]
    elif reg == "ch":
        del sym.regs_tainted["ch"]
    elif reg == "cl":
        del sym.regs_tainted["cl"]

    elif reg == "rdx":
        del sym.regs_tainted["rdx"]
        del sym.regs_tainted["edx"]
        del sym.regs_tainted["dx"]
        del sym.regs_tainted["dh"]
        del sym.regs_tainted["dl"]
    elif reg == "edx":
        del sym.regs_tainted["edx"]
        del sym.regs_tainted["dx"]
        del sym.regs_tainted["dh"]
        del sym.regs_tainted["dl"]
    elif reg == "dx":
        del sym.regs_tainted["dx"]
        del sym.regs_tainted["dh"]
        del sym.regs_tainted["dl"]
    elif reg == "dh":
        del sym.regs_tainted["dh"]
    elif reg == "dl":
        del sym.regs_tainted["dl"]

    elif reg == "rdi":
        del sym.regs_tainted["rdi"]
        del sym.regs_tainted["edi"]
        del sym.regs_tainted["di"]
        del sym.regs_tainted["dil"]
    elif reg == "edi":
        del sym.regs_tainted["edi"]
        del sym.regs_tainted["di"]
        del sym.regs_tainted["dil"]
    elif reg == "di":
        del sym.regs_tainted["di"]
        del sym.regs_tainted["dil"]
    elif reg == "dil":
        del sym.regs_tainted["dil"]

    elif reg == "rsi":
        del sym.regs_tainted["rsi"]
        del sym.regs_tainted["esi"]
        del sym.regs_tainted["si"]
        del sym.regs_tainted["sil"]
    elif reg == "esi":
        del sym.regs_tainted["esi"]
        del sym.regs_tainted["si"]
        del sym.regs_tainted["sil"]
    elif reg == "si":
        del sym.regs_tainted["si"]
        del sym.regs_tainted["sil"]
    elif reg == "sil":
        del sym.regs_tainted["sil"]

    elif reg == "t0":
        del sym.regs_tainted["t0"]
    elif reg == "t1":
        del sym.regs_tainted["t1"]

    elif reg == "rbp":
        del sym.regs_tainted["rbp"]
        del sym.regs_tainted["ebp"]
    elif reg == "ebp":
        del sym.regs_tainted["ebp"]

    elif reg == "r8":
        del sym.regs_tainted["r8"]
        del sym.regs_tainted["r8d"]
        del sym.regs_tainted["r8w"]
        del sym.regs_tainted["r8b"]
    elif reg == "r8d":
        del sym.regs_tainted["r8d"]
        del sym.regs_tainted["r8w"]
        del sym.regs_tainted["r8b"]
    elif reg == "r8w":
        del sym.regs_tainted["r8w"]
        del sym.regs_tainted["r8b"]
    elif reg == "r8b":
        del sym.regs_tainted["r8b"]

    elif reg == "r9":
        del sym.regs_tainted["r9"]
        del sym.regs_tainted["r9d"]
        del sym.regs_tainted["r9w"]
        del sym.regs_tainted["r9b"]
    elif reg == "r9d":
        del sym.regs_tainted["r9d"]
        del sym.regs_tainted["r9w"]
        del sym.regs_tainted["r9b"]
    elif reg == "r9w":
        del sym.regs_tainted["r9w"]
        del sym.regs_tainted["r9b"]
    elif reg == "r9b":
        del sym.regs_tainted["r9b"]

    elif reg == "r10":
        del sym.regs_tainted["r10"]
        del sym.regs_tainted["r10d"]
        del sym.regs_tainted["r10w"]
        del sym.regs_tainted["r10b"]
    elif reg == "r10d":
        del sym.regs_tainted["r10d"]
        del sym.regs_tainted["r10w"]
        del sym.regs_tainted["r10b"]
    elif reg == "r10w":
        del sym.regs_tainted["r10w"]
        del sym.regs_tainted["r10b"]
    elif reg == "r10b":
        del sym.regs_tainted["r10b"]

    elif reg == "r11":
        del sym.regs_tainted["r11"]
        del sym.regs_tainted["r11d"]
        del sym.regs_tainted["r11w"]
        del sym.regs_tainted["r11b"]
    elif reg == "r11d":
        del sym.regs_tainted["r11d"]
        del sym.regs_tainted["r11w"]
        del sym.regs_tainted["r11b"]
    elif reg == "r11w":
        del sym.regs_tainted["r11w"]
        del sym.regs_tainted["r11b"]
    elif reg == "r11b":
        del sym.regs_tainted["r11b"]

    elif reg == "r12":
        del sym.regs_tainted["r12"]
        del sym.regs_tainted["r12d"]
        del sym.regs_tainted["r12w"]
        del sym.regs_tainted["r12b"]
    elif reg == "r12d":
        del sym.regs_tainted["r12d"]
        del sym.regs_tainted["r12w"]
        del sym.regs_tainted["r12b"]
    elif reg == "r12w":
        del sym.regs_tainted["r12w"]
        del sym.regs_tainted["r12b"]
    elif reg == "r12b":
        del sym.regs_tainted["r12b"]

    elif reg == "r13":
        del sym.regs_tainted["r13"]
        del sym.regs_tainted["r13d"]
        del sym.regs_tainted["r13w"]
        del sym.regs_tainted["r13b"]
    elif reg == "r13d":
        del sym.regs_tainted["r13d"]
        del sym.regs_tainted["r13w"]
        del sym.regs_tainted["r13b"]
    elif reg == "r13w":
        del sym.regs_tainted["r13w"]
        del sym.regs_tainted["r13b"]
    elif reg == "r13b":
        del sym.regs_tainted["r13b"]

    elif reg == "r14":
        del sym.regs_tainted["r14"]
        del sym.regs_tainted["r14d"]
        del sym.regs_tainted["r14w"]
        del sym.regs_tainted["r14b"]
    elif reg == "r14d":
        del sym.regs_tainted["r14d"]
        del sym.regs_tainted["r14w"]
        del sym.regs_tainted["r14b"]
    elif reg == "r14w":
        del sym.regs_tainted["r14w"]
        del sym.regs_tainted["r14b"]
    elif reg == "r14b":
        del sym.regs_tainted["r14b"]

    elif reg == "r15":
        del sym.regs_tainted["r15"]
        del sym.regs_tainted["r15d"]
        del sym.regs_tainted["r15w"]
        del sym.regs_tainted["r15b"]
    elif reg == "r15d":
        del sym.regs_tainted["r15d"]
        del sym.regs_tainted["r15w"]
        del sym.regs_tainted["r15b"]
    elif reg == "r15w":
        del sym.regs_tainted["r15w"]
        del sym.regs_tainted["r15b"]
    elif reg == "r15b":
        del sym.regs_tainted["r15b"]

    elif reg == _:
        print (reg, " can't remove taint")
        return False

    print ">>>>>> " + reg + " is free now"
    return True

'''#@pypatt.transform
def remove_taint_reg(reg, sym):
    if not (check_reg_taint(reg, sym)):
        print (reg, " is not tainted")
        return False

    with match(reg):
        with "rax":
            del sym.regs_tainted["rax"]
            del sym.regs_tainted["eax"]
            del sym.regs_tainted["ax"]
            del sym.regs_tainted["ah"]
            del sym.regs_tainted["al"]
        with "eax":
            del sym.regs_tainted["eax"]
            del sym.regs_tainted["ax"]
            del sym.regs_tainted["ah"]
            del sym.regs_tainted["al"]
        with "ax":
            del sym.regs_tainted["ax"]
            del sym.regs_tainted["ah"]
            del sym.regs_tainted["al"]
        with "ah":
            del sym.regs_tainted["ah"]
        with "al":
            del sym.regs_tainted["al"]

        with "rbx":
            del sym.regs_tainted["rbx"]
            del sym.regs_tainted["ebx"]
            del sym.regs_tainted["bx"]
            del sym.regs_tainted["bh"]
            del sym.regs_tainted["bl"]
        with "ebx":
            del sym.regs_tainted["ebx"]
            del sym.regs_tainted["bx"]
            del sym.regs_tainted["bh"]
            del sym.regs_tainted["bl"]
        with "bx":
            del sym.regs_tainted["bx"]
            del sym.regs_tainted["bh"]
            del sym.regs_tainted["bl"]
        with "bh":
            del sym.regs_tainted["bh"]
        with "bl":
            del sym.regs_tainted["bl"]

        with "rcx":
            del sym.regs_tainted["rcx"]
            del sym.regs_tainted["ecx"]
            del sym.regs_tainted["cx"]
            del sym.regs_tainted["ch"]
            del sym.regs_tainted["cl"]
        with "ecx":
            del sym.regs_tainted["ecx"]
            del sym.regs_tainted["cx"]
            del sym.regs_tainted["ch"]
            del sym.regs_tainted["cl"]
        with "cx":
            del sym.regs_tainted["cx"]
            del sym.regs_tainted["ch"]
            del sym.regs_tainted["cl"]
        with "ch":
            del sym.regs_tainted["ch"]
        with "cl":
            del sym.regs_tainted["cl"]

        with "rdx":
            del sym.regs_tainted["rdx"]
            del sym.regs_tainted["edx"]
            del sym.regs_tainted["dx"]
            del sym.regs_tainted["dh"]
            del sym.regs_tainted["dl"]
        with "edx":
            del sym.regs_tainted["edx"]
            del sym.regs_tainted["dx"]
            del sym.regs_tainted["dh"]
            del sym.regs_tainted["dl"]
        with "dx":
            del sym.regs_tainted["dx"]
            del sym.regs_tainted["dh"]
            del sym.regs_tainted["dl"]
        with "dh":
            del sym.regs_tainted["dh"]
        with "dl":
            del sym.regs_tainted["dl"]

        with "rdi":
            del sym.regs_tainted["rdi"]
            del sym.regs_tainted["edi"]
            del sym.regs_tainted["di"]
            del sym.regs_tainted["dil"]
        with "edi":
            del sym.regs_tainted["edi"]
            del sym.regs_tainted["di"]
            del sym.regs_tainted["dil"]
        with "di":
            del sym.regs_tainted["di"]
            del sym.regs_tainted["dil"]
        with "dil":
            del sym.regs_tainted["dil"]

        with "rsi":
            del sym.regs_tainted["rsi"]
            del sym.regs_tainted["esi"]
            del sym.regs_tainted["si"]
            del sym.regs_tainted["sil"]
        with "esi":
            del sym.regs_tainted["esi"]
            del sym.regs_tainted["si"]
            del sym.regs_tainted["sil"]
        with "si":
            del sym.regs_tainted["si"]
            del sym.regs_tainted["sil"]
        with "sil":
            del sym.regs_tainted["sil"]

        with "t0":
            del sym.regs_tainted["t0"]
        with "t1":
            del sym.regs_tainted["t1"]

        with "rbp":
            del sym.regs_tainted["rbp"]
            del sym.regs_tainted["ebp"]
        with "ebp":
            del sym.regs_tainted["ebp"]

        with "r8":
            del sym.regs_tainted["r8"]
            del sym.regs_tainted["r8d"]
            del sym.regs_tainted["r8w"]
            del sym.regs_tainted["r8b"]
        with "r8d":
            del sym.regs_tainted["r8d"]
            del sym.regs_tainted["r8w"]
            del sym.regs_tainted["r8b"]
        with "r8w":
            del sym.regs_tainted["r8w"]
            del sym.regs_tainted["r8b"]
        with "r8b":
            del sym.regs_tainted["r8b"]

        with "r9":
            del sym.regs_tainted["r9"]
            del sym.regs_tainted["r9d"]
            del sym.regs_tainted["r9w"]
            del sym.regs_tainted["r9b"]
        with "r9d":
            del sym.regs_tainted["r9d"]
            del sym.regs_tainted["r9w"]
            del sym.regs_tainted["r9b"]
        with "r9w":
            del sym.regs_tainted["r9w"]
            del sym.regs_tainted["r9b"]
        with "r9b":
            del sym.regs_tainted["r9b"]

        with "r10":
            del sym.regs_tainted["r10"]
            del sym.regs_tainted["r10d"]
            del sym.regs_tainted["r10w"]
            del sym.regs_tainted["r10b"]
        with "r10d":
            del sym.regs_tainted["r10d"]
            del sym.regs_tainted["r10w"]
            del sym.regs_tainted["r10b"]
        with "r10w":
            del sym.regs_tainted["r10w"]
            del sym.regs_tainted["r10b"]
        with "r10b":
            del sym.regs_tainted["r10b"]

        with "r11":
            del sym.regs_tainted["r11"]
            del sym.regs_tainted["r11d"]
            del sym.regs_tainted["r11w"]
            del sym.regs_tainted["r11b"]
        with "r11d":
            del sym.regs_tainted["r11d"]
            del sym.regs_tainted["r11w"]
            del sym.regs_tainted["r11b"]
        with "r11w":
            del sym.regs_tainted["r11w"]
            del sym.regs_tainted["r11b"]
        with "r11b":
            del sym.regs_tainted["r11b"]

        with "r12":
            del sym.regs_tainted["r12"]
            del sym.regs_tainted["r12d"]
            del sym.regs_tainted["r12w"]
            del sym.regs_tainted["r12b"]
        with "r12d":
            del sym.regs_tainted["r12d"]
            del sym.regs_tainted["r12w"]
            del sym.regs_tainted["r12b"]
        with "r12w":
            del sym.regs_tainted["r12w"]
            del sym.regs_tainted["r12b"]
        with "r12b":
            del sym.regs_tainted["r12b"]

        with "r13":
            del sym.regs_tainted["r13"]
            del sym.regs_tainted["r13d"]
            del sym.regs_tainted["r13w"]
            del sym.regs_tainted["r13b"]
        with "r13d":
            del sym.regs_tainted["r13d"]
            del sym.regs_tainted["r13w"]
            del sym.regs_tainted["r13b"]
        with "r13w":
            del sym.regs_tainted["r13w"]
            del sym.regs_tainted["r13b"]
        with "r13b":
            del sym.regs_tainted["r13b"]

        with "r14":
            del sym.regs_tainted["r14"]
            del sym.regs_tainted["r14d"]
            del sym.regs_tainted["r14w"]
            del sym.regs_tainted["r14b"]
        with "r14d":
            del sym.regs_tainted["r14d"]
            del sym.regs_tainted["r14w"]
            del sym.regs_tainted["r14b"]
        with "r14w":
            del sym.regs_tainted["r14w"]
            del sym.regs_tainted["r14b"]
        with "r14b":
            del sym.regs_tainted["r14b"]

        with "r15":
            del sym.regs_tainted["r15"]
            del sym.regs_tainted["r15d"]
            del sym.regs_tainted["r15w"]
            del sym.regs_tainted["r15b"]
        with "r15d":
            del sym.regs_tainted["r15d"]
            del sym.regs_tainted["r15w"]
            del sym.regs_tainted["r15b"]
        with "r15w":
            del sym.regs_tainted["r15w"]
            del sym.regs_tainted["r15b"]
        with "r15b":
            del sym.regs_tainted["r15b"]

        with _:
            print (reg, " can't remove taint")
            return False

    print ">>>>>> " + reg + " is free now"
    return True
'''