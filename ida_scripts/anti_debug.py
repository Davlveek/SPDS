from idaapi import *
from idautils import *
from idc import *

import json

antiDebug = dict()

isDebuggerPresent = checkRemoteDebuggerPresent = GetVersionExA = False
NtQueryInformationProcess = GetThreadContext = NtSetInformationThread = False
NtCreateThreadEx = False

def good_bad(value):
    return "[BAD]" if value else "[GOOD]"

def trick_sort():
    list_d = list(antiDebug.items())
    list_d.sort(key=lambda i: i[1])

    return list_d

def print_inst(hb, SEH, TrapFlag, get_PEB_cond, NtGlobalFlag_offsets, HeapFlags):
    sorted_tricks = trick_sort()

    filename = get_root_filename()
    filename = filename.replace('.exe', '')
    f = open("E:\\SPDS\\reports\\" + filename + "[AntiDbg]" + ".txt", 'w')

    f.write("------------------------[Anti-Debugger Detection]------------------------\n")
    f.write("IsDebuggerPresent\t\t\t\t" + good_bad(isDebuggerPresent)+'\n')
    f.write("CheckRemoteDebuggerPresent\t\t\t" + good_bad(checkRemoteDebuggerPresent) + '\n')
    f.write("GetVersionExA\t\t\t\t\t" + good_bad(GetVersionExA) + '\n')
    f.write("NtQueryInformationProcess\t\t\t" + good_bad(NtQueryInformationProcess) + '\n')
    f.write("GetThreadContext\t\t\t\t" + good_bad(GetThreadContext) + '\n')
    f.write("NtSetInformationThread\t\t\t\t" + good_bad(NtSetInformationThread) + '\n')
    f.write("NtCreateThreadEx\t\t\t\t" + good_bad(NtCreateThreadEx) + '\n')
    f.write("Get PEB\t\t\t\t\t\t" + good_bad(get_PEB_cond) + '\n')
    f.write("NtGlobalFlag\t\t\t\t\t" + good_bad(NtGlobalFlag_offsets and get_PEB_cond) + '\n')
    f.write("TrapFlag\t\t\t\t\t" + good_bad(TrapFlag) + '\n')
    f.write("Heap Flags\t\t\t\t\t" + good_bad(get_PEB_cond and HeapFlags) + '\n')
    f.write("Hardware Breakpoints\t\t\t\t" + good_bad(hb and GetThreadContext) + '\n')
    f.write("SEH\t\t\t\t\t\t" + good_bad(SEH) + '\n')
    f.write("VEH\t\t\t\t\t\t" + good_bad(hb) + '\n')
    f.write("-------------------------------------------------------------------------\n")

    anti_dbg_dict = {
        'IsDebuggerPresent': isDebuggerPresent,
        'CheckRemoteDebuggerPresent': checkRemoteDebuggerPresent,
        'GetVersionExA': GetVersionExA,
        'NtQueryInformationProcess': NtQueryInformationProcess,
        'GetThreadContext': GetVersionExA,
        'NtSetInformationThread': NtSetInformationThread,
        'Get PEB': get_PEB_cond,
        'NtGlobalFlag': NtGlobalFlag_offsets and HeapFlags,
        'TrapFlag': TrapFlag,
        'Heap Flags': get_PEB_cond and HeapFlags,
        'Hardware Breakpoints': hb and GetThreadContext,
        'SEH': SEH,
        'VEH': hb,
    }

    anti_dbg_report_file = open("E:\\SPDS\\reports\\" + filename + "[AntiDbg]" + ".json", 'w')
    json.dump(anti_dbg_dict, anti_dbg_report_file, sort_keys=False, indent=4)
    anti_dbg_report_file.close()

    for i in sorted_tricks:
        disasmStr = GetDisasm(i[0])
        f.write("0x%08x [%s]" % (i[0], disasmStr))
        f.write(' ' + i[1] + '\n')

    f.close()        

def set_api(disasm, head):
    global isDebuggerPresent, checkRemoteDebuggerPresent, GetVersionExA 
    global NtQueryInformationProcess, GetThreadContext, NtSetInformationThread 
    global NtCreateThreadEx

    if "IsDebuggerPresent" in disasm:
        isDebuggerPresent = True
        antiDebug[head] = "IsDebuggerPresent"
    if "CheckRemoteDebuggerPresent" in disasm:
        checkRemoteDebuggerPresent = True
        antiDebug[head] = "CheckRemoteDebuggerPresent"
    if "GetVersionExA" in disasm:
        GetVersionExA = True
        antiDebug[head] = "GetVersionExA"
    if "NtQueryInformationProcess" in disasm:
        NtQueryInformationProcess = True
        antiDebug[head] = "NtQueryInformationProcess"
    if "GetThreadContext" in disasm:
        GetThreadContext = True
        antiDebug[head] = "GetThreadContext"
    if "NtSetInformationThread" in disasm:
        NtSetInformationThread = True
        antiDebug[head] = "NtSetInformationThread"
    if "NtCreateThreadEx" in disasm:
        NtCreateThreadEx = True
        antiDebug[head] = "NtCreateThreadEx"

def check_API_anti_debug():
    for seg in Segments():
        for head in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(head)):
                disasm = GetDisasm(head)
                if disasm.startswith("call") == True:
                    set_api(disasm, head)
                # check get params to GetProcAddress
                elif disasm.startswith("push") == True:
                   set_api(disasm, head)

def check_get_PEB():
    get_PEB = False
    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "mov" and "large fs:30h" in GetOpnd(x, 1):
                    get_PEB = True
                    antiDebug[x] = "Get PEB"

    return get_PEB

def check_NtGlobalFlag():
    NtGlobalFlag = False
    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "test" and "+68h]" in GetOpnd(x, 0):
                    NtGlobalFlag = True
                    antiDebug[x] = "NtGlobalFlag"
                elif GetMnem(x) == "test" and "+BCh]" in GetOpnd(x, 0):
                    NtGlobalFlag = True
                    antiDebug[x] = "NtGlobalFlag"

    return NtGlobalFlag

def check_TrapFlag():
    TrapFlag = False
    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

    flag1 = False
    flag2 = False
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "pushf" or GetMnem(x) == "pushfd":
                    flag1 = True
                    continue
                if flag1:
                    if GetMnem(x) == "or" and "[esp" in GetOpnd(x, 0) and GetOpnd(x, 1) == "100h":
                        flag1 = False
                        flag2 = True
                        continue
                if flag2:
                    if GetMnem(x) == "popfd" or GetMnem(x) == "popf":
                        TrapFlag = True
                        antiDebug[x] = "Trap Flag"
                        flag2 = False
    
    return TrapFlag

def check_HeapFlags():
    HeapFlags = False
    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "mov" and "18h]" in  GetOpnd(x, 1):
                    HeapFlags = True
                    antiDebug[x] = "Heap Flags"
                elif GetMnem(x) == "mov" and "30h]" in  GetOpnd(x, 1):
                    HeapFlags = True
                    antiDebug[x] = "Heap Flags"
    
    return HeapFlags

def check_hardware_breakpoints():
    dr = False
    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "lea" or GetMnem(x) == "mov" or GetMnem(x) == "cmp" and ("Dr0]" or "Dr1]" or "Dr2]" or "Dr0]") in GetOpnd(x, 1):
                   if "Dr0]" in GetOpnd(x, 1) or "Dr1]" in GetOpnd(x, 1) or "Dr2]" in GetOpnd(x, 1) or "Dr3]" in GetOpnd(x, 1):
                    dr = True
                    antiDebug[x] = "Hardware Breakpoints"

    return dr

def check_SEH():
    seh = False
    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

    flag = False
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "push" and GetOpnd(x, 0) == "large dword ptr fs:0":
                    flag = True
                    continue
                if flag:    
                    if GetMnem(x) == "mov" and GetOpnd(x, 0) == "large fs:0" and GetOpnd(x, 1) == "esp":
                        seh = True
                        antiDebug[x] = "SEH"
                        flag = False

    return seh 

def main():
    check_API_anti_debug()
    get_PEB_cond = check_get_PEB()
    NtGlobalFlag_offsets = check_NtGlobalFlag()
    HeapFlags = check_HeapFlags()
    hb = check_hardware_breakpoints()
    SEH = check_SEH()
    TrapFlag = check_TrapFlag()
    print_inst(hb, SEH, TrapFlag, get_PEB_cond, NtGlobalFlag_offsets, HeapFlags)

    print "------------------------[Anti-Debugger Detection]------------------------"
    print "IsDebuggerPresent\t\t\t\t", good_bad(isDebuggerPresent)
    print "CheckRemoteDebuggerPresent\t\t\t", good_bad(checkRemoteDebuggerPresent)   
    print "GetVersionExA\t\t\t\t", good_bad(GetVersionExA)
    print "NtQueryInformationProcess\t\t\t", good_bad(NtQueryInformationProcess)
    print "GetThreadContext\t\t\t\t", good_bad(GetThreadContext)
    print "NtSetInformationThread\t\t\t\t", good_bad(NtSetInformationThread)
    print "NtCreateThreadEx\t\t\t\t", good_bad(NtCreateThreadEx)
    print "Get PEB\t\t\t\t\t", good_bad(get_PEB_cond)
    print "NtGlobalFlag\t\t\t\t", good_bad(NtGlobalFlag_offsets and get_PEB_cond)
    print "TrapFlag\t\t\t\t\t", good_bad(TrapFlag)
    print "Heap Flags\t\t\t\t\t", good_bad(get_PEB_cond and HeapFlags)
    print "Hardware Breakpoints\t\t\t\t", good_bad(hb and GetThreadContext)
    print "SEH\t\t\t\t\t", good_bad(SEH)
    print "VEH\t\t\t\t\t", good_bad(hb)
    print "-------------------------------------------------------------------------"

main()