# IDA-Python-Deobfuscate  
  
Very much a work in progress. At the time of writing only a few hours have gone into this.

Targeted towards Arxan obfuscation.

Currently only supports deobfuscation of basic instructions: `jmp, call, ret`

Load file in ida via `File > Script file...`

In the python command box type `deob_print(address_to_deob)` to output basic deobfuscated code.
