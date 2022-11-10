# IDA-Python-Deobfuscate  
  
Very much a work in progress. At the time of writing only a few hours have gone into this.

Targeted towards Arxan obfuscation.

Currently only supports deobfuscation of basic instructions: `jmp, call, ret`

Load file in ida via `File > Script file...`

In the python command box type `deob_print(address_to_deob)` to output basic deobfuscated code.


For example:
```
0000000140A614CC jmp     sub_1437363C4
00000001437363C4 push    rbp
00000001437363C5 lea     rbp, loc_1413CF0B6
00000001437363CC xchg    rbp, [rsp]
00000001437363D0 retn
00000001413CF0B6 lea     rsp, [rsp-8]
00000001413CF0BB mov     [rsp], rbp
00000001413CF0BF lea     rbp, sub_140CB7EC6
00000001413CF0C6 xchg    rbp, [rsp]
00000001413CF0CA jmp     loc_1437B239F
00000001437B239F lea     rsp, [rsp+8]
00000001437B23A4 jmp     qword ptr [rsp-8]
0000000140CB7EC6 sub     rsp, 38h
0000000140CB7ECA jmp     loc_143B6AEC1
0000000143B6AEC1 mov     rax, [rcx+10h]
0000000143B6AEC5 jmp     loc_1434393E1
00000001434393E1 xor     r10d, r10d
00000001434393E4 cmp     [rax+20h], r10d
00000001434393E8 jmp     loc_143C5CF9A
0000000143C5CF9A mov     ecx, [rax]
0000000143C5CF9C lea     rdx, [rax+8]
0000000143C5CFA0 jmp     loc_1435BC015
00000001435BC015 setnz   r8b
00000001435BC019 cmp     [rax+28h], r10d
00000001435BC01D jmp     loc_1438A3CEA
00000001438A3CEA setnz   r9b
00000001438A3CEE cmp     [rax+30h], r10d
00000001438A3CF2 setnz   al
00000001438A3CF5 mov     [rsp+20h], al
00000001438A3CF9 jmp     loc_140A614F8
0000000140A614F8 call    sub_140A7A080
0000000140A614FD nop
0000000140A614FE jmp     short loc_140A61493
0000000140A61493 jmp     sub_143794CA0
0000000143794CA0 nop
0000000143794CA1 jmp     loc_1435D896A
00000001435D896A push    rbp
00000001435D896B lea     rbp, loc_140A6148E
00000001435D8972 xchg    rbp, [rsp+8+var_8]
00000001435D8976 retn
0000000140A6148E jmp     sub_143635C6F
0000000143635C6F push    rbp
0000000143635C70 lea     rbp, loc_140A84DEA
0000000143635C77 xchg    rbp, [rsp+8+var_8]
0000000143635C7B retn
0000000140A84DEA nop
0000000140A84DEB mov     [rsp-8], rbp
0000000140A84DF0 jmp     sub_143C7F33D
0000000143C7F33D lea     rsp, [rsp-8]
0000000143C7F342 lea     rbp, loc_140A61489
0000000143C7F349 xchg    rbp, [rsp]
0000000143C7F34D lea     rsp, [rsp+8]
0000000143C7F352 jmp     loc_143B1766D
0000000143B1766D jmp     [rsp+var_8]
0000000140A61489 jmp     sub_14391CC82
000000014391CC82 push    rbp
000000014391CC83 lea     rbp, loc_14392A6DB
000000014391CC8A xchg    rbp, [rsp+8+var_8]
000000014391CC8E retn
000000014392A6DB lea     rsp, [rsp-8]
000000014392A6E0 jmp     loc_140CF0061
0000000140CF0061 mov     [rsp], rbp
0000000140CF0065 jmp     loc_14354ABD1
000000014354ABD1 lea     rbp, sub_14360DFC8
000000014354ABD8 xchg    rbp, [rsp]
000000014354ABDC lea     rsp, [rsp+8]
000000014354ABE1 jmp     qword ptr [rsp-8]
000000014360DFC8 add     rsp, 38h
000000014360DFCC lea     rsp, [rsp+8]
000000014360DFD1 jmp     [rsp-40h+arg_30]
```

The above code is obfuscated. Running `deob_print(0x140A614CC)` we can output significantly simplified assembly:

```
Python>deob_print(0x140A614CC)
0000000140CB7EC6 sub     rsp, 38h
0000000143B6AEC1 mov     rax, [rcx+10h]
00000001434393E1 xor     r10d, r10d
00000001434393E4 cmp     [rax+20h], r10d
0000000143C5CF9A mov     ecx, [rax]
0000000143C5CF9C lea     rdx, [rax+8]
00000001435BC015 setnz   r8b
00000001435BC019 cmp     [rax+28h], r10d
00000001438A3CEA setnz   r9b
00000001438A3CEE cmp     [rax+30h], r10d
00000001438A3CF2 setnz   al
00000001438A3CF5 mov     [rsp+20h], al
0000000140A614F8 call    sub_140A7A080
000000014360DFC8 add     rsp, 38h
000000014360DFCC retn
```

This simplified assembly results in the following pseudo-c (type casting removed):

```c
bool sub_140A614CC(__int64 a1)
{
  return sub_140A7A080(
           **(a1 + 16),
           (*(a1 + 16) + 8i64),
           *(*(a1 + 16) + 0x20i64) != 0,
           *(*(a1 + 16) + 0x28i64) != 0,
           *(*(a1 + 16) + 0x30i64) != 0);
}
```
