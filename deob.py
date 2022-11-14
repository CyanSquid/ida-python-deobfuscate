import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs
import ctypes

class obfuscated_conditional_jmp:
    def __init__(self, con_tgt, uncon_tgt, con_type):
        self.con_tgt = con_tgt
        self.uncon_tgt = uncon_tgt
        self.con_type = con_type

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

OBFU_CONJ = [[0x55],                                                       # push    rbp
             [0x48, None, None, None, None, None, None, None, None, None], # mov     *, offset TARGET_LOCATION1
             [0x48, 0x87, 0x2C, None],                                     # xchg    *, *
             [None],                                                       # push    *
             [None],                                                       # push    *
             [0x48, 0x8B, None, 0x24, 0x10],                               # mov     *, [rsp+10h]
             [0x48, None, None, None, None, None, None, None, None, None], # mov     *, offset TARGET_LOCATION2
             [None, None, None, None],                                     # cmovz   *, * 
             [0x48, 0x89, None, 0x24, 0x10],                               # mov     [rsp+10h], *
             [None],                                                       # pop     *
             [None],                                                       # pop     *
             [0xC3]]                                                       # retn

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

# ==================== util funcs ====================

def is_rel_unconditional_jmp(ea):
    return idc.GetDisasm(ea).startswith("jmp") and idc.get_operand_type(ea, 0) == idc.o_near

def is_rel_conditional_jmp(ea):
    disasm = idc.GetDisasm(ea)
    return disasm.startswith("j") and (not disasm.startswith("jmp")) and (idc.get_operand_type(ea, 0) == idc.o_near)

def is_rel32_lea_rbp(disasm, ea):
    return disasm.startswith("lea") and ((idc.get_wide_dword(ea) & 0xFFFFFF) == 0x2D8D48) # 0x2D8D48 = 48 8D 2D ? ? ? ?    lea rbp, LOCATION

def get_rel_jmp_dest(ea):
    return idc.get_operand_value(ea, 0)

def get_rel32_lea(ea):
    return idc.get_operand_value(ea, 1)

# test_pattern
# Check if a given obfuscation pattern is matched at ea.
#
# Each pattern is matched one instruction at a time.
# If we encounter a jmp, we follow the jmp then continue
# to match the pattern.
#
# Jumps are essentially treated as if they don't exist.
# If the pattern is matched, the function returns
# a list containing the addresses of each of the segments
# of the pattern. [x, y, z, etc]
def test_instruction_pattern(ea, PATTERN):
    TOTAL = len(PATTERN)
    matched = 0
    results = []
    while matched < TOTAL:
        disasm = idc.GetDisasm(ea)
        if is_rel_unconditional_jmp(ea) and not ((idc.get_wide_byte(ea) == 0xEB) and (matched == 0)): # jmp short
            ea = get_rel_jmp_dest(ea)
            continue
        
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            return None
        
        if decoded.size != len(PATTERN[matched]):
            return None
        for i, x in enumerate(PATTERN[matched]):
            if x is None:
                continue
            if idc.get_wide_byte(ea + i) != x:
                return None
        results.append(ea)
        matched += 1
        ea = idc.next_head(ea)
    return results

def is_obfu_ret(ea):
    return test_instruction_pattern(ea, OBFU_RET1) is not None

def get_if_obfuscated_conditional_jmp(ea, CONJ_PATTERN):
    result = test_instruction_pattern(ea, CONJ_PATTERN)
    if not result:
        return None
    mov = []
    mov.append(idc.get_operand_value(result[6], 1))
    mov.append(idc.get_operand_value(result[1], 1))

    cmov = idc.GetDisasm(result[7]).split()[0]
    r = obfuscated_conditional_jmp(mov[0], mov[1], cmov[4:])
    return r

def get_target_if_obfu_uncon_jmp(ea):
    temp = test_instruction_pattern(ea, OBFU_JMP1)
    if temp is not None:
        return idc.get_operand_value(temp[1], 1)
    temp = test_instruction_pattern(ea, OBFU_JMP2)
    if temp is not None:
        return idc.get_operand_value(temp[2], 1)
    temp = test_instruction_pattern(ea, OBFU_JMP3)
    if temp is not None:
        return idc.get_operand_value(temp[2], 1)
    return None

def get_if_obfu_call(ea):
    result = test_instruction_pattern(ea, OBFU_CALL1)
    return (idc.get_operand_value(result[5], 0), idc.get_operand_value(result[2], 0))\
        if result is not None else None

def get_if_obfu_con_jmp(ea):
    return get_if_obfuscated_conditional_jmp(ea, OBFU_CONJ)

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
    ida_bytes.del_items(ea, 0, 5)
    idc.auto_wait()
    patch_bytes(ea, 0xE9)
    patch_bytes(ea + 1, ctypes.c_int32((target - (ea + 5)) & 0xFFFFFFFF))
    idc.create_insn(ea)

def patch_place_rel32_je(ea, target):
    ida_bytes.del_items(ea, 0, 6)
    idc.auto_wait()
    patch_bytes(ea, [0x0F, 0x84])
    patch_bytes(ea + 2, ctypes.c_int32((target - (ea + 6)) & 0xFFFFFFFF))
    idc.create_insn(ea)

def patch_place_rel32_jne(ea, target):
    ida_bytes.del_items(ea, 0, 6)
    idc.auto_wait()
    patch_bytes(ea, [0x0F, 0x85])
    patch_bytes(ea + 2, ctypes.c_int32((target - (ea + 6)) & 0xFFFFFFFF))
    idc.create_insn(ea)

# ==================== main funcs ====================

def get_block_size(ea):
    size = 0
    while True:
        decoded = idautils.DecodeInstruction(ea)
        size += decoded.size
        disasm = idc.GetDisasm(ea)
        if disasm.startswith("jmp"):
            break
        if disasm.startswith("ret"):
            break
        ea = idc.next_head(ea)
    return size

def find_block(search_from, block_size):
    block = search_from
    while True:
        if get_block_size(block) >= block_size:
            return block
        
        ea = block
        while True:
            if idc.GetDisasm(ea).startswith("ret"):
                return None
            if is_rel_conditional_jmp(ea):
                block = get_rel_jmp_dest(ea)
                break
            ea = idc.next_head(ea)

def handle_obfuscated_con_jmp(ea, cj):
    block_size = get_block_size(ea)
    place_where = ea
    if block_size < 11: # need enough remaining bytes for j* and jmp (rel32)
        print("Not enough space... Searching for a bigger block!")

        place_where = find_block(ea, 11)
    if not place_where:
        print("Couldn't find a block big enough for (j* ... jmp) (11 bytes)")
        return
    if ea != place_where:
        patch_place_rel32_jmp(ea, place_where)
        idc.create_insn(ea)
        idc.set_cmt(ea, "[5fcc3e45 - deob] Deob has modified this code", 0)
    if cj.con_type == "z":
        patch_place_rel32_je(place_where, cj.con_tgt)
    elif cj.con_type == "nz":
        patch_place_rel32_jne(place_where, cj.con_tgt)
    else:
        print("[handle_obfuscated_con_jmp] Unknown j*: j{}".format(cj.con_type))
        return
    patch_place_rel32_jmp(place_where + 6, cj.uncon_tgt) # 6 = sizeof j*
    idc.set_cmt(place_where, "[5fcc3e45 - deob] Deob has modified this code", 0)
    idc.set_cmt(place_where + 6, "[5fcc3e45 - deob] Deob has modified this code", 0)

def patchy_any_obfu(ea):
    temp = get_target_if_obfu_uncon_jmp(ea)
    if temp:
        place_where = ea
        if get_block_size(ea) < 5:
            place_where = find_block(ea, 5)
        if not place_where:
            print("error")
        patch_place_rel32_jmp(place_where, temp)
        idc.set_cmt(place_where, "[5fcc3e45 - deob] Deob has modified this code", 0)
    
    elif (temp := get_if_obfu_con_jmp(ea)):
        handle_obfuscated_con_jmp(ea, temp)
    
    elif is_obfu_ret(ea):
        patch_bytes(ea, 0xC3) # ret
        idc.set_cmt(ea, "[5fcc3e45 - deob] Deob has modified this code", 0)

def simplify(ea, visited):
    while True:
        if ea in visited:
            return
        visited.append(ea)
        if not idc.is_code(ida_bytes.get_full_flags(ea)):
            print("[deob-simplify] Encountered none code: {:X}".format(ea))
            return

        patchy_any_obfu(ea)

        if is_rel_conditional_jmp(ea):
            simplify(get_rel_jmp_dest(ea), visited)

        elif is_rel_unconditional_jmp(ea):
            ea = get_rel_jmp_dest(ea)
            continue

        if idautils.DecodeInstruction(ea).itype in [idaapi.NN_retn]:
            print("[deob-simplify] Encountered return: {:X}".format(ea))
            return
        ea = idc.next_head(ea)
    return

def build_function(fea, ea, visited):
    chunk_end = ea + get_block_size(ea)
    if chunk_end == ea:
        print("[process_chunk] Error processing chunk!")
        return False
    print("chunk: ({:X}->{:X}) size({})".format(ea, chunk_end, chunk_end - ea))
    func = idaapi.get_func(ea)
    if func and (func.start_ea != fea):
        ida_funcs.del_func(func.start_ea)
    if ea != fea:
        idaapi.append_func_tail(idaapi.get_func(fea), ea, chunk_end)

    while True:
        if ea in visited:
            return
        visited.append(ea)

        if not idc.is_code(ida_bytes.get_full_flags(ea)):
            print("[deob-simplify] Encountered none code: {:X}".format(ea))
            return

        if is_rel_conditional_jmp(ea):
            build_function(fea, get_rel_jmp_dest(ea), visited)

        elif is_rel_unconditional_jmp(ea):
            build_function(fea, get_rel_jmp_dest(ea), visited)
            return

        if idautils.DecodeInstruction(ea).itype in [idaapi.NN_retn]:
            print("[deob-build_function] Encountered return: {:X}".format(ea))
            return
        ea = idc.next_head(ea)

# Deobfuscates a function
# 3 steps:
# 1) Simplify. Replace obfuscated expressions with their unobfuscated equivilents
# 2) Skip jump chains. Skip long chains of jmps, make the first jump go straight to the final destination
# 3) Build function. Add function chunks etc
def deob(ea):
    # 1
    simplify(ea, [])

    #2
    # not yet

    #3
    build_function(ea, ea, [])

    print("[deob] Done!")
    return
