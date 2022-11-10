import idc
import idautils
import ctypes

OBFU_JMP1 = [[0x55],                                      # push    rbb
             [0x48, 0x8D, 0x2D, None, None, None, None],  # lea     rbp, TARGET_LOCATION
             [0x48, 0x87, 0x2C, 0x24],                    # xchg    rbp, [rsp]
             [0xC3]]                                      # retn

OBFU_JMP2 = [[0x48, 0x8D, 0x64, 0x24, 0xF8],              # lea     rsp, [rsp-8]
             [0x48, 0x89, 0x2C, 0x24],                    # mov     [rsp], rbp
             [0x48, 0x8D, 0x2D, None, None, None, None],  # lea     rbp, TARGET_LOCATION
             [0x48, 0x87, 0x2C, 0x24],                    # xchg    rbp, [rsp]
             [0x48, 0x8D, 0x64, 0x24, 0x08],              # lea     rsp, [rsp+8]
             [0xFF, 0x64, 0x24, 0xF8]]                    # jmp     qword ptr [rsp-8]

OBFU_JMP3 = [[0x48, 0x89, 0x6C, 0x24, 0xF8],              # mov     [rsp-8], rbp
             [0x48, 0x8D, 0x64, 0x24, 0xF8],              # lea     rsp, [rsp-8]
             [0x48, 0x8D, 0x2D, None, None, None, None],  # lea     rbp, TARGET_LOCATION
             [0x48, 0x87, 0x2C, 0x24],                    # xchg    rbp, [rsp]
             [0x48, 0x8D, 0x64, 0x24, 0x08],              # lea     rsp, [rsp+8]
             [0xFF, 0x64, 0x24, 0xF8]]                    # jmp     qword ptr [rsp-8]

OBFU_CALL1 = [[0x48, 0x8D, 0x64, 0x24, 0xF8],             # lea     rsp, [rsp-8]
              [0x48, 0x89, 0x2C, 0x24],                   # mov     [rsp], rbp
              [0x48, 0x8D, 0x2D, None, None, None, None], # lea     rbp, TARGET_JUMP
              [0x48, 0x87, 0x2C, 0x24],                   # xchg    rbp, [rsp]
              [0x55],                                     # push    rbb
              [0x48, 0x8D, 0x2D, None, None, None, None], # lea     rbp, TARGET_CALL
              [0x48, 0x87, 0x2C, 0x24],                   # xchg    rbp, [rsp]
              [0xC3]]                                     # retn

# PATTERN MIGHT NEED WORK
OBFU_RET1 = [[0x48, 0x8D, 0x64, 0x24, 0x08], # lea     rsp, [rsp+8]
             [0xFF, 0x64, 0x24, 0xF8]]       # jmp     qword ptr [rsp-8]

def is_rel_jmp(ea):
    return idc.GetDisasm(ea).startswith("jmp") and idc.get_operand_type(ea, 0) == idc.o_near

def is_rel32_lea_rbp(disasm, ea):
    return disasm.startswith("lea") and ((idc.get_wide_dword(ea) & 0xFFFFFF) == 0x2D8D48) # 48 8D 2D ? ? ? ?    lea rbp, LOCATION

def get_rel_jmp_dest(ea):
    return idc.get_operand_value(ea, 0)

def get_rel32_lea(ea):
    return ctypes.c_long(idc.get_wide_dword(ea + 3)).value + ea + 7

def test_pattern(ea, on_inst_match, PATTERN):
    TOTAL = len(PATTERN)
    matched = 0
    while matched < TOTAL:
        disasm = idc.GetDisasm(ea)
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue
        
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            return False
        
        if decoded.size != len(PATTERN[matched]):
            return False
        for i, x in enumerate(PATTERN[matched]):
            if x is None:
                continue
            if idc.get_wide_byte(ea + i) != x:
                return False
        if callable(on_inst_match):
                on_inst_match(ea, disasm)
        matched += 1
        ea = idc.next_head(ea)
    return True

def is_obfu_ret1(ea):
    return test_pattern(ea, None, OBFU_RET1)

def get_if_obfuscated_jmp(ea, JMP_PATTERN):
    lea = None
    def callback(e, d):
        if is_rel32_lea_rbp(d, e):
            nonlocal lea
            lea = get_rel32_lea(e) 
    test_pattern(ea, callback, JMP_PATTERN)
    return lea

def get_if_obfuscated_call(ea, CALL_PATTERN):
    lea = []
    def callback(e, d):
        if is_rel32_lea_rbp(d, e):
            nonlocal lea
            lea.append(get_rel32_lea(e)) 
    if not test_pattern(ea, callback, CALL_PATTERN):
        return None
    return lea

def get_if_obfu_jmp(ea):
    temp = get_if_obfuscated_jmp(ea, OBFU_JMP1)
    if temp is not None:
        return temp
    temp = get_if_obfuscated_jmp(ea, OBFU_JMP2)
    if temp is not None:
        return temp
    temp = get_if_obfuscated_jmp(ea, OBFU_JMP3)
    if temp is not None:
        return temp
    return None

def get_if_obfu_call(ea):
    return get_if_obfuscated_call(ea, OBFU_CALL1)

def deob_print(ea):
    while True:
        disasm = idc.GetDisasm(ea)
        
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue

        obfuj = get_if_obfu_jmp(ea)
        if obfuj is not None:
            ea = obfuj
            continue

        obfuc = get_if_obfu_call(ea)
        if (obfuc is not None) and (len(obfuc) == 2):
            print("{:016X} OBFUCALL {:016X}".format(ea, obfuc[1]))
            ea = obfuc[0]
            continue

        if is_obfu_ret1(ea):
            print("{:016X} retn".format(ea))
            break
        
        if not disasm.startswith("nop"):
            print("{:016X} {}".format(ea, disasm))
        if disasm.startswith("retn"):
            break
        
        ea = idc.next_head(ea)
    return
