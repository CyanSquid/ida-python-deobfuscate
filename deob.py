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

def get_if_obfuscated_jmp(ea, JMP_PATTERN):
    TOTAL = len(JMP_PATTERN)
    matched = 0
    lea = None
    while matched < TOTAL:
        disasm = idc.GetDisasm(ea)
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue
        
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            return None
        
        if decoded.size != len(JMP_PATTERN[matched]):
            return None
        for i, x in enumerate(JMP_PATTERN[matched]):
            if x is None:
                continue
            if idc.get_wide_byte(ea + i) != x:
                return None
        matched += 1
        if is_rel32_lea_rbp(disasm, ea):
            lea = get_rel32_lea(ea)
        ea = idc.next_head(ea)
    return lea

def get_if_obfuscated_call(ea, CALL_PATTERN):
    TOTAL = len(CALL_PATTERN)
    matched = 0
    lea = []
    while matched < TOTAL:
        disasm = idc.GetDisasm(ea)
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue
        
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            return None
        
        if decoded.size != len(CALL_PATTERN[matched]):
            return None
        for i, x in enumerate(CALL_PATTERN[matched]):
            if x is None:
                continue
            if idc.get_wide_byte(ea + i) != x:
                return None
        matched += 1
        if is_rel32_lea_rbp(disasm, ea):
            lea.append(get_rel32_lea(ea))
        ea = idc.next_head(ea)
    return lea

def is_obfuscated_ret(ea, RET_PATTERN):
    TOTAL = len(RET_PATTERN)
    matched = 0
    lea = None
    while matched < TOTAL:
        disasm = idc.GetDisasm(ea)
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue
        
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            return False
        
        if decoded.size != len(RET_PATTERN[matched]):
            return False
        for i, x in enumerate(RET_PATTERN[matched]):
            if x is None:
                continue
            if idc.get_wide_byte(ea + i) != x:
                return False
        matched += 1
        ea = idc.next_head(ea)
    return True

def is_obfu_ret1(ea):
    return is_obfuscated_ret(ea, OBFU_RET1)

def get_if_obfu_jmp1(ea):
    return get_if_obfuscated_jmp(ea, OBFU_JMP1)

def get_if_obfu_jmp2(ea):
    return get_if_obfuscated_jmp(ea, OBFU_JMP2)

def get_if_obfu_jmp3(ea):
    return get_if_obfuscated_jmp(ea, OBFU_JMP3)

def get_if_obfu_call1(ea):
    return get_if_obfuscated_call(ea, OBFU_CALL1)

def deob_print(ea):
    while True:
        disasm = idc.GetDisasm(ea)
        
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue

        obfuj = get_if_obfu_jmp1(ea)
        if obfuj is not None:
            ea = obfuj
            continue

        obfuj = get_if_obfu_jmp2(ea)
        if obfuj is not None:
            ea = obfuj
            continue

        obfuj = get_if_obfu_jmp3(ea)
        if obfuj is not None:
            ea = obfuj
            continue

        obfuc = get_if_obfu_call1(ea)
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
