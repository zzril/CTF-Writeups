checkpass
=========

We're given a binary, `checkpass`. Running a quick `strings` finds a bunch of  
Rust-typical stuff. By piping to `grep`, we also find something interesting:
```
$ strings * | grep pico
picoCTF{H9
        picoCTF{Success
```

On executing, it tells us it expects a command-line argument. Supplying a random  
one yields "Invalid length". Using brute force, we can quickly find out the  
correct length: 41 or 0x29 characters.
```
$ ./checkpass
Usage:
        ./checkpass <password>
$ ./checkpass test
Invalid length
$ for i in {1..64}; do echo $i; ./checkpass $(python -c "print('A'*$i)"); echo; done
1
Invalid length

2
Invalid length
[...]
41
Invalid password
```

On to Ghidra... Searching for the `pico` string leads us to `FUN_00105960`.  
The `picoCTF{` string is used in this code which looks like an initial input  
validation:
```c
  if (local_78 == 2) {
    if (*(long *)(local_88[0] + 0x28) == 0x29) {
      plVar3 = *(long **)(local_88[0] + 0x18);
      if (((plVar3 == (long *)&DAT_00139d78) || (*plVar3 == 0x7b4654436f636970)) &&
         ((plVar1 = plVar3 + 5, plVar1 == (long *)&DAT_00139d94 || (*(char *)plVar1 == '}')))) {
```
(Both the first `DAT` and the first stack string are the `picoCTF{`, whereas the  
second `DAT` string is a `}`.)

The corresponding assembly begins:
```asm
001059b3 48 83 f8 02     CMP        RAX,0x2
001059b7 0f 85 91        JNZ        LAB_00105a4e
         00 00 00
001059bd 48 8b 84        MOV        RAX,qword ptr [RSP + local_88]
         24 a0 00
         00 00
```

We check our hypothesis in gdb. The offset it adds to the addresses in `.text`  
is `0x555555300000`. So...
```
(gdb) b *0x5555554059b3
Breakpoint 1 at 0x5555554059b3
(gdb) r
[...]
Breakpoint 1, 0x00005555554059b3 in ?? ()
(gdb) si
0x00005555554059b7 in ?? ()
(gdb) si
0x0000555555405a4e in ?? ()
```
(Ok, with 1 argument, it takes the branch.)
```
(gdb) r picoCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
[...]
Breakpoint 1, 0x00005555554059b3 in ?? ()
(gdb) si
0x00005555554059b7 in ?? ()
(gdb) si
0x00005555554059bd in ?? ()
```
... and with 2 arguments it does not jump. So, this is indeed the `argc` check.

We rename the function to `main` and also rename some variables:
```c
if (argc == 2) {
  if (*(long *)(local_88[0] + 0x28) == 0x29) {
    password = *(long **)(local_88[0] + 0x18);
    if (((password == (long *)&flag_start) || (*password == 0x7b4654436f636970)) &&
       ((plVar1 = password + 5, plVar1 == (long *)&flag_end || (*(char *)plVar1 == '}')))) {
```

Unfortunately, the rest of the code is still quite a mess to read. However, this  
stands out:
```c
if (lStack_b0 == 0) {
  local_128 = (undefined **)*local_c0;
  uStack_120 = local_c0[1];
  local_118 = local_c0[2];
  uStack_110 = *(undefined4 *)(local_c0 + 3);
  uStack_10c = *(undefined4 *)((long)local_c0 + 0x1c);
          /* try { // try from 00105b77 to 001065c2 has its CatchHandler @ 001065d7 */
  lStack_b0 = lStack_b0 + 0x20;
  FUN_001054e0(local_70,&local_128,0);
  uStack_110 = uStack_58;
  uStack_10c = uStack_54;
  FUN_001054e0(local_50,&local_128,1);
  uStack_110 = uStack_38;
  uStack_10c = uStack_34;
  FUN_001054e0(&local_a8,&local_128,2);
  uStack_110 = uStack_90;
  uStack_10c = uStack_8c;
  FUN_001054e0(&local_e0,&local_128,3);
  local_e9 = local_dd;
  local_e3 = local_dc;
  local_ec = local_db;
  local_e1 = local_da;
  local_f0 = local_d9;
  local_e7 = local_d8;
  local_e2 = local_d6;
  local_ee = local_d5;
  local_e5 = local_d3;
  local_f1 = local_d1;
  local_ed = local_d0;
  local_e6 = local_cf;
  local_e4 = local_ce;
  local_ea = local_cc;
  local_eb = local_cb;
  local_ef = local_ca;
  local_e8 = local_c4;
  local_f2 = local_c2;
  local_128 = (undefined **)0x19;
  local_f5 = local_de;
  if ((((((local_c7 == -0x1a) && (local_128 = (undefined **)0x0, local_e0 == '\x1f')) &&
        (local_128 = (undefined **)0xe, local_d2 == -0x3f)) &&
       ((local_128 = (undefined **)0x13, local_cd == ':' &&
        (local_128 = (undefined **)0x17, local_c9 == -0x62)))) &&
      ((((local_128 = (undefined **)0x1, local_df == '+' &&
         ((local_128 = (undefined **)0x1d, local_c3 == '\x01' &&
          (local_128 = (undefined **)0x1b, local_c5 == -0x62)))) &&
        ((local_128 = (undefined **)0x1a, local_c6 == 'w' &&
         (((((local_128 = (undefined **)0xc, local_d4 == -0x52 &&
             (local_128 = (undefined **)0x1f, local_c1 == '{')) &&
            (local_128 = (undefined **)0x6, local_da == ':')) &&
           ((local_128 = (undefined **)0xa, local_d6 == -0x52 &&
            (local_128 = (undefined **)0xf, local_d1 == 'H')))) &&
          (local_128 = (undefined **)0x1e, local_c2 == 'z')))))) &&
       (((((local_128 = (undefined **)0x7, local_d9 == -0x35 &&
           (local_128 = (undefined **)0xb, local_d5 == -0x35)) &&
          ((local_128 = (undefined **)0x5, local_db == '\"' &&
           (((local_128 = (undefined **)0x16, local_ca == 'F' &&
             (local_128 = (undefined **)0x10, local_d0 == '\x05')) &&
            (local_128 = (undefined **)0x15, local_cb == -0x48)))))) &&
         ((local_128 = (undefined **)0x3, local_dd == 'F' &&
          (local_128 = (undefined **)0x14, local_cc == -0x33)))) &&
        (local_128 = (undefined **)0x8, local_d8 == -0x44)))))) &&
     ((((local_128 = (undefined **)0x1c, local_c4 == -0x59 &&
        (local_128 = (undefined **)0xd, local_d3 == ' ')) &&
       ((local_128 = (undefined **)0x11, local_cf == '{' &&
        (((local_128 = (undefined **)0x2, local_de == 'P' &&
          (local_128 = (undefined **)0x9, local_d7 == 'z')) &&
         (local_128 = (undefined **)0x4, local_dc == -0x48)))))) &&
      ((local_128 = (undefined **)0x18, local_c8 == -0x31 &&
       (local_128 = (undefined **)0x12, local_ce == '{')))))) {
    FUN_001066a0();
  }
  else {
    FUN_00106650();
  }
}
```
The assembly of this huge mess starts at `0x105b5e`.

Alright, what is this?  
We call the same function, `FUN_001054e0`, 4 times, with only the last argument  
increasing by 1 each time.  
Next, we do a bunch of reassigns.  
And finally, there's a long series of comparisons, all chained with an `&&`.  
This could indeed be our password check!

Let's have a look at that function that's called 4 times.  
It starts with a long series of assignments like this:
```c
local_20[1] = (&DAT_00139560)[(ulong)param_2[1] + param_3];
local_20[2] = (&DAT_00139560)[(ulong)param_2[2] + param_3];
```
So it iterates over the entries in `param_2` and uses the values found there as  
an index for a lookup in a global table at `DAT_00139560`.  
The values it looks up there are then stored in a local array, `local_20`.

Next, we have a bunch of nested `if`s of this kind:
```c
if (uVar1 < 0x20) {
  param_1[1][9] = local_20[uVar1];
  uVar1 = *(ulong *)(&DAT_00139a48 + param_3);
  if (uVar1 < 0x20) {
    param_1[1][0xb] = local_20[uVar1];
    uVar1 = *(ulong *)(&DAT_00139a50 + param_3);
```
(When executing this dynamically, it turns out the `if`s always evaluate to  
true, probably just some array bounds check.)

Basically, this is just a transposition of the `local_20` array.  
In each step, some index is loaded from the data section into `uVar1`, then the  
entry in the `local_20` array at index `uVar1` is written to the `param_1` array  
at some other index.

We rename `FUN_001054e0` to `substitute_and_transpose` and check our findings in  
gdb:  
(The "in" array lies at `rsp+0x8`, the "out" array is pointed to by `rdi`.)
```
(gdb) b *0x5555554054e0
Breakpoint 1 at 0x5555554054e0
(gdb) r picoCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
[...]
Breakpoint 1, 0x00005555554054e0 in ?? ()
(gdb) x/32bx $rsp+0x8
0x7fffffffdb80: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffdb88: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffdb90: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffdb98: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
(gdb) fin
Run till exit from #0  0x00005555554054e0 in ?? ()
0x0000555555405b89 in ?? ()
(gdb) x/32bx $rdi
0x7fffffffdc38: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdc40: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdc48: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdc50: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
(gdb) c
Continuing.

Breakpoint 1, 0x00005555554054e0 in ?? ()
(gdb) x/32bx $rsp+0x8
0x7fffffffdb80: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdb88: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdb90: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdb98: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
(gdb) fin
Run till exit from #0  0x00005555554054e0 in ?? ()
0x0000555555405bb7 in ?? ()
(gdb) x/32bx $rdi
0x7fffffffdc58: 0x48    0x48    0x48    0x48    0x48    0x48    0x48    0x48
0x7fffffffdc60: 0x48    0x48    0x48    0x48    0x48    0x48    0x48    0x48
0x7fffffffdc68: 0x48    0x48    0x48    0x48    0x48    0x48    0x48    0x48
0x7fffffffdc70: 0x48    0x48    0x48    0x48    0x48    0x48    0x48    0x48
```

We can also check how modifications on the input change the output:
```
(gdb) r picoCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB}
[...]
Breakpoint 1, 0x00005555554054e0 in ?? ()
(gdb) x/32bx $rsp+0x8
0x7fffffffdb80: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffdb88: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffdb90: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffdb98: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x42
(gdb) fin
Run till exit from #0  0x00005555554054e0 in ?? ()
0x0000555555405b89 in ?? ()
(gdb) x/32bx $rdi
0x7fffffffdc38: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdc40: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdc48: 0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
0x7fffffffdc50: 0x0c    0x21    0x0c    0x0c    0x0c    0x0c    0x0c    0x0c
```

Alright, so this indeed just does a substitution (using that global table)  
followed by a transposition.

Looking back at `main`, we realize that after calling `substitute_and_transpose`  
4 times, it does a final round of swapping some variables around, then starts  
comparing them to hardcoded values.  
Basically, this behaves on no way different from a single round of substitution,  
followed by a single round of transposition.

We can crack the substitution part by supplying inputs of the form  
`picoCTF{abbcccddddeeeeeffffffggggggggggg}` (containing each character a  
different number of times, so we can recognize in the output which went where).  
This mechanism is implemented in `solve.py`.

The script finds for each possible byte in the ciphertext what input character  
would have been transformed to it, and prints that out as a dictionary:
```
{'0x1': 'f', '0xb8': 'g', '0x22': 'e', '0xd': 'c', '0xcf': 'd', '0xd7': 'b', '0x5': 'a', '0x48': 'm', '0x7b': 'n', '0xae': 'l', '0x43': 'j', '0x2d': 'k', '0xcd': 'i', '0xe6': 'h', '0x20': 't', '0x6b': 'u', '0xdb': 's', '0xc7': 'q', '0xf4': 'r', '0xdd': 'p', '0x25': 'o', '0x3e': 'A', '0x49': 'B', '0x84': 'z', '0xc1': 'x', '0x8b': 'y', '0x62': 'w', '0x34': 'v', '0x57': 'H', '0x58': 'I', '0x77': 'G', '0x83': 'E', '0xbc': 'F', '0x30': 'D', '0x50': 'C', '0x74': 'O', '0x2b': 'P', '0xce': 'N', '0x40': 'L', '0xd0': 'M', '0xa3': 'K', '0xa7': 'J', '0x7a': 'V', '0x31': 'W', '0x6f': 'U', '0x46': 'S', '0x4': 'T', '0xc2': 'R', '0x9e': 'Q', '0x12': '2', '0x3a': '3', '0xcb': '1', '0xb5': 'Z', '0xd9': '0', '0xda': 'Y', '0x45': 'X', '0x99': '9', '0x1f': '_', '0xb2': '8', '0x8d': '6', '0xd3': '7', '0xf9': '5', '0x68': '4'}
```

Now that we know which input character is going to get replaced by which output  
character eventually, we need to crack the transposition / swapping of the  
characters.  
We can do that dynamically again, by supplying a password with all different  
characters (of which we know the corresponding substitution results) and keeping  
track of what they eventually get compared to.

The comparisons start after `0x105d0b`, so we set a breakpoint there. Future  
comparisons can be found using single-stepping and comparing each instruction to  
a regex. The comparisons all look like this:
```asm
CMP	BL,byte ptr [RDI + RBP*0x1]
```
(The registers sometimes change.)

In this case, `bl` would contain a character from the password (after applying  
the substitutions and transpositions), whereas the memory argument would be the  
hard-coded "ciphertext" value it's compared to.

As we have already cracked the substitution part, we know what character in the  
password caused the current value in `bl`. Since the chosen password does not  
contain duplicate characters, we also know what index in the password leads to  
the current comparison!  
Having cracked the substitution part also allows us to find the character that  
would get substituted by the compare value at `[rdi + rbp*0x1]`. This is the  
character that would lead to the comparison being evaluated to true, so this  
must be the correct value at the found index in the password.

`solve.py` implements this mechanism and spits out the flag:  
`picoCTF{t1mingS1deChann3l_gVQSfJxl3VPFGQ}`

(Not sure where the timing side channel is here.)


