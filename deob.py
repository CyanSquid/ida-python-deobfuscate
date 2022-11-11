import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs
import ctypes

# Obfuscation patterns
#
# Each pattern is a list of instructions, with "None"
# representing wild-card bytes.

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
              [0x55],                                     # push    rbp
              [0x48, 0x8D, 0x2D, None, None, None, None], # lea     rbp, TARGET_CALL
              [0x48, 0x87, 0x2C, 0x24],                   # xchg    rbp, [rsp]
              [0xC3]]                                     # retn

OBFU_RET1 = [[0x48, 0x8D, 0x64, 0x24, 0x08],              # lea     rsp, [rsp+8]
             [0xFF, 0x64, 0x24, 0xF8]]                    # jmp     qword ptr [rsp-8]

# test_pattern
# Check if a given obfuscation pattern is matched at ea.
#
# Each pattern is matched one instruction at a time.
# If we encounter a jmp, we follow the jmp then continue
# to match the pattern.
#
# Jumps are essentially treated as if they don't exist.
def test_instruction_pattern(ea, on_inst_match, PATTERN):
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

def is_obfu_ret(ea):
    return test_instruction_pattern(ea, None, OBFU_RET1)

def get_if_obfuscated_jmp(ea, JMP_PATTERN):
    lea = None
    def callback(e, d):
        if is_rel32_lea_rbp(d, e):
            nonlocal lea
            lea = get_rel32_lea(e) 
    test_instruction_pattern(ea, callback, JMP_PATTERN)
    return lea

def get_if_obfuscated_call(ea, CALL_PATTERN):
    lea = []
    def callback(e, d):
        if is_rel32_lea_rbp(d, e):
            nonlocal lea
            lea.append(get_rel32_lea(e)) 
    if not test_instruction_pattern(ea, callback, CALL_PATTERN):
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

# ==================== patching funcs ====================

def patch_bytes(ea, patch):
    patch_as_bytes = None
    if isinstance(patch, int):
        patch = [patch]
    try:
        patch_as_bytes = bytes(patch)
    except:
        print("[patch_bytes] patch couldn't be converted to bytes")
        return

    patch_length = len(patch_as_bytes)
    fixup = idaapi.get_next_fixup_ea(ea - 1)
    while fixup < ea + patch_length:
        print("[patch_bytes] Deleting fixup ({:X}) for ea: {:X}".format(fixup, ea))
        idaapi.del_fixup(fixup)
        fixup = idaapi.get_next_fixup_ea(fixup)

    idaapi.patch_bytes(ea, patch_as_bytes)
    idc.auto_wait()

def patch_place_rel32_jmp(ea, target):
    patch_bytes(ea, 0xE9)
    patch_bytes(ea + 1, ctypes.c_int32((target - (ea + 5)) & 0xFFFFFFFF))

# ==================== util funcs ====================

def is_rel_jmp(ea):
    return idc.GetDisasm(ea).startswith("jmp") and idc.get_operand_type(ea, 0) == idc.o_near

def is_rel32_lea_rbp(disasm, ea):
    return disasm.startswith("lea") and ((idc.get_wide_dword(ea) & 0xFFFFFF) == 0x2D8D48) # 0x2D8D48 = 48 8D 2D ? ? ? ?    lea rbp, LOCATION

def get_rel_jmp_dest(ea):
    return idc.get_operand_value(ea, 0)

def get_rel32_lea(ea):
    return idc.get_operand_value(ea, 1)


# ==================== main funcs ====================

def add_function_chunk(ea, start, end):
    print("chunk: {:X} : {:X}".format(start, end))
    idaapi.append_func_tail(idaapi.get_func(ea), start, end)

# deobfuscates a section of code, turns it into a chunk and
# adds it to a functions chunk list.
def process_chunk(fea, cea):
    chunk_end = None
    ea = cea
    while True:
        if is_rel_jmp(ea):
            decoded = idautils.DecodeInstruction(ea)
            chunk_end = ea + decoded.size
            break

        obfuj = get_if_obfu_jmp(ea)
        if obfuj is not None:
            patch_place_rel32_jmp(ea, obfuj)
            idc.set_cmt(ea, "[5fcc3e45 - deob] Deob has modified this code", 0)
            chunk_end = ea + 5 # 5 = sizeof rel32 jmp
            break

        if is_obfu_ret(ea):
            patch_bytes(ea, 0xC3)
            idc.set_cmt(ea, "[5fcc3e45 - deob] Deob has modified this code", 0)
            chunk_end = ea + 1 # 1 = sizeof retn
            break

        if idc.GetDisasm(ea).startswith("ret"):
            decoded = idautils.DecodeInstruction(ea)
            chunk_end = ea + decoded.size
            break
        ea = idc.next_head(ea)
    idc.auto_wait()
    if (chunk_end is None) or (chunk_end == cea):
        print("[process_chunk] Error processing chunk!")
        return False
    func = idaapi.get_func(cea)
    if (func is not None) and (func.start_ea != fea):
        ida_funcs.del_func(func.start_ea)
    add_function_chunk(fea, cea, chunk_end)
    return True

def deob(ea):
    function = ea
    chunk = function
    while True:
        if not idc.is_code(ida_bytes.get_full_flags(ea)):
            print("[deob_print] Encountered none code at {:X}".format(ea))
            break
        
        if not process_chunk(function, chunk):
            break
        
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            chunk = ea
            continue
        
        if idc.GetDisasm(ea).startswith("ret"):
            break   
        ea = idc.next_head(ea)
    print("[deob] Done")

def deob_print(ea):
    while True:
        if not idc.is_code(ida_bytes.get_full_flags(ea)):
            print("[deob_print] Encountered none code at {:X}".format(ea))
            break
        
        disasm = idc.GetDisasm(ea)
        
        if is_rel_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue

        obfuj = get_if_obfu_jmp(ea)
        if obfuj is not None:
            ea = obfuj
            continue

        obfuc = get_if_obfu_call(ea)
        if obfuc is not None:
            print("{:016X} call {:016X}".format(ea, obfuc[1]))
            ea = obfuc[0]
            continue

        if is_obfu_ret(ea):
            print("{:016X} retn".format(ea))
            break
        
        if not disasm.startswith("nop"):
            print("{:016X} {}".format(ea, disasm))
        if disasm.startswith("ret"):
            break
        
        ea = idc.next_head(ea)
    return
