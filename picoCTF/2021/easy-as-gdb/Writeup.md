Easy as GDB
===========

We're given a binary, `brute`.  
`file` tells us it's a 32-bit Linux x86 executable. `strings` and `objdump` do  
not yield us any additional interesting information as of now.

A quick test run shows us that it expects input from stdin:
```
$ ./brute
input the flag: test
checking solution...
Incorrect.
```

Alright, on to Ghidra...  
In the `.rodata` section, we find the `input the flag` string, which is  
referenced from the main function.  
After some quick renaming, the main function looks like this:
```c
int main(void)

{
  char *input_buffer;
  size_t flag_len;
  undefined4 uVar1;
  int input_ok;
  
  input_buffer = (char *)calloc(0x200,1);
  printf("input the flag: ");
  fgets(input_buffer,0x200,stdin);
  flag_len = strnlen(&global_flag_encrypted,0x200);
  uVar1 = FUN_0001082b(input_buffer,flag_len);
  FUN_000107c2(uVar1,flag_len,1);
  input_ok = check(uVar1,flag_len);
  if (input_ok == 1) {
    puts("Correct!");
  }
  else {
    puts("Incorrect.");
  }
  return 0;
}
```
(With `global_flag_encrypted` being a bit of a guess at this point.)

Alright, so there are 3 functions to look at: `FUN_0001082b`, `FUN_000107c2` and  
`check` (which we already renamed for readability).

Starting with the first one, `FUN_0001082b`, we get this after some renaming:
```c
char * FUN_0001082b(char *buffer,uint length_raw)

{
  size_t length_padded;
  char *copy_buffer;
  uint i;
  undefined4 _0x10837;
  
  _0x10837 = 0x10837;
  length_padded = (length_raw & 0xfffffffc) + 4;
  copy_buffer = (char *)malloc((length_raw & 0xfffffffc) + 5);
  strncpy(copy_buffer,buffer,length_padded);
  for (i = 0xabcf00d; i < 0xdeadbeef; i = i + 0x1fab4d) {
    FUN_000106bd(copy_buffer,length_padded,i,_0x10837);
  }
  return copy_buffer;
}
```

Ok, so `FUN_000106bd` is repeatedly called on a copy of the input buffer.  
What does that function do?  
It seems to xor its first argument (a buffer) with a 4-byte key which is  
supplied as the 3rd parameter. However, the key is transformed to BigEndian  
first. After some renaming, the function looks like this:  
```c
void xor_big_endian(char *buffer,uint length,uint key)

{
  int in_GS_OFFSET;
  uint i;
  byte key_big_endian [4];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  key_big_endian[0] = (byte)(key >> 0x18);
  key_big_endian[1] = (char)(key >> 0x10);
  key_big_endian[2] = (char)(key >> 8);
  key_big_endian[3] = (char)key;
  for (i = 0; i < length; i = i + 1) {
    buffer[i] = buffer[i] ^ key_big_endian[i & 3];
  }
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
    fail();
  }
  return;
}
```

We rename the outer function to `repeated_xor` and look at it again:
```c
char * repeated_xor(char *buffer,uint length_raw)

{
  size_t length_padded;
  char *copy_buffer;
  uint i;
  
  length_padded = (length_raw & 0xfffffffc) + 4;
  copy_buffer = (char *)malloc((length_raw & 0xfffffffc) + 5);
  strncpy(copy_buffer,buffer,length_padded);
  for (i = 0xabcf00d; i < 0xdeadbeef; i = i + 0x1fab4d) {
    xor_big_endian(copy_buffer,length_padded,i);
  }
  return copy_buffer;
}
```
From what we know about xor and its associativity, this is essentially nothing  
different from a xor with a single 4-byte constant.

Anyway, back to main...
```c
int main(void)

{
  char *input_buffer;
  size_t flag_len;
  char *input_xored;
  int input_ok;
  
  input_buffer = (char *)calloc(0x200,1);
  printf("input the flag: ");
  fgets(input_buffer,0x200,stdin);
  flag_len = strnlen(&global_flag_encrypted,0x200);
  input_xored = (char *)repeated_xor(input_buffer,flag_len);
  FUN_000107c2(input_xored,flag_len,1);
  input_ok = check(input_xored,flag_len);
  if (input_ok == 1) {
    puts("Correct!");
  }
  else {
    puts("Incorrect.");
  }
  return 0;
}
```

What's up with that `FUN_000107c2` function? Let's check that out...  
It iterates through the buffer supplied as first argument, calling `FUN_00010751`  
on each byte. The 3rd argument decides in which direction to iterate.
```c
void FUN_000107c2(char *buffer,uint length,int direction)

{
  uint j;
  int i;
  
  if (direction < 1) {
    for (i = length - 1; 0 < i; i = i + -1) {
      FUN_00010751(buffer,length,i);
    }
  }
  else {
    for (j = 1; j < length; j = j + 1) {
      FUN_00010751(buffer,length,j);
    }
  }
  return;
}
```

Fine, onto `FUN_00010751`... That one just swaps some bytes around.  
After renaming:
```c
void swap_outer_bytes_blockwise(char *buffer,int length,int block_width)

{
  uint i;
  char tmp;
  
  for (i = 0; i < (length - block_width) + 1U; i = i + block_width) {
    tmp = buffer[i];
    buffer[i] = buffer[block_width + i + -1];
    buffer[block_width + i + -1] = tmp;
  }
  return;
}
```

We rename its caller:
```c
void repeated_byteswap(char *buffer,uint length,int direction)

{
  uint j;
  int i;
  
  if (direction < 1) {
    for (i = length - 1; 0 < i; i = i + -1) {
      swap_outer_bytes_blockwise(buffer,length,i);
    }
  }
  else {
    for (j = 1; j < length; j = j + 1) {
      swap_outer_bytes_blockwise(buffer,length,j);
    }
  }
  return;
}
```

Back to main:
```c
int main(void)

{
  char *input_buffer;
  size_t flag_len;
  char *input_xored;
  int input_ok;
  
  input_buffer = (char *)calloc(0x200,1);
  printf("input the flag: ");
  fgets(input_buffer,0x200,stdin);
  flag_len = strnlen(&global_flag_encrypted,0x200);
  input_xored = (char *)repeated_xor(input_buffer,flag_len);
  repeated_byteswap(input_xored,flag_len,1);
  input_ok = check(input_xored,flag_len);
  if (input_ok == 1) {
    puts("Correct!");
  }
  else {
    puts("Incorrect.");
  }
  return 0;
}
```

What does `check` do again?  
(Some renaming later:)
```c
int check(char *buffer,uint length)

{
  char *enc_input_copy;
  char *enc_flag_copy;
  uint i;
  
  enc_input_copy = (char *)calloc(length + 1,1);
  strncpy(enc_input_copy,buffer,length);
  repeated_byteswap(enc_input_copy,length,0xffffffff);
  enc_flag_copy = (char *)calloc(length + 1,1);
  strncpy(enc_flag_copy,&global_flag_encrypted,length);
  repeated_byteswap(enc_flag_copy,length,0xffffffff);
  puts("checking solution...");
  i = 0;
  while( true ) {
    if (length <= i) {
      return 1;
    }
    if (enc_input_copy[i] != enc_flag_copy[i]) break;
    i = i + 1;
  }
  return -1;
}
```

So... what does this mean?  
`main` reads user input into a buffer. This is then repeatedly xor'ed with some  
constant. (Effectively one xor operation.)  
Then, on the resulting ("encrypted") input, some bytes are swapped around.  
However, the very next thing we do is call the `check` function which starts by  
calling the swapping function again, with the reverse direction parameter,  
effectively undoing the previous byte swapping. Nice.  
Next, the "encrypted flag" is also fed once into that byte swapping function.  
Finally, the "encrypted" / xor'ed input is compared byte-wise to the flag after  
performing the byte-swapping on it.

Long story short: The user input is xored with some 4-byte key. Then, the result  
of that xor is compared to a value that we can inspect live/dynamically.  
However, because the xor operation is symmetric, if we simply input the value  
its result is compared to, then we should get back the expected initial input!

Well, let's try that. We need to find a moment to read the final compare value  
in memory. The value is last modified in this function call:
```
00010943 83 ec 04        SUB        ESP,0x4
00010946 6a ff           PUSH       -0x1
00010948 ff 75 0c        PUSH       dword ptr [EBP + length]
0001094b ff 75 f4        PUSH       dword ptr [EBP + local_10]
0001094e e8 6f fe        CALL       repeated_byteswap
         ff ff
00010953 83 c4 10        ADD        ESP,0x10
```
So, the '953 looks like a good breakpoint.

We fire up GDB, run the program once to have it calculate all the addresses and  
then set the breakpoint:
```
$ gdb brute
[...]
(gdb) r
[...]
[Inferior 1 [...] exited normally]
(gdb) info file
[...]
0x56555580 - 0x56555b34 is .text
[...]
(gdb) b *0x56555953
Breakpoint 1 at 0x56555953
(gdb) r
[...]
input the flag: a

Breakpoint 1, 0x56555953 in ?? ()
```

Let's check out what was the first argument to `repeated_byteswap`:
```
(gdb) x/a $esp
0xffffcf80:     0x56558c30
(gdb) x/64bx 0x56558c30
0x56558c30:     0x2e    0x6e    0x40    0x68    0x1d    0x53    0x65    0x7c
0x56558c38:     0x17    0x58    0x16    0x43    0x6d    0x58    0x62    0x36
0x56558c40:     0x6f    0x43    0x62    0x30    0x01    0x34    0x16    0x3f
0x56558c48:     0x3f    0x3e    0x12    0x32    0x6e    0x7a    0x00    0x00
0x56558c50:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x56558c58:     0x00    0x00    0x00    0x00    0xa9    0x13    0x02    0x00
0x56558c60:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x56558c68:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```
We guess that the first 30 / 0x1e bytes are relevant. (Can also verify that in  
Ghidra, looking at the `global_flag_encrypted` variable.)  
Let's copy them into vim and nicely reformat them.

We also need to find a good moment to read the final version of the user input.  
It is last touched here:
```
00010901 83 ec 04        SUB        ESP,0x4
00010904 6a ff           PUSH       -0x1
00010906 ff 75 0c        PUSH       dword ptr [EBP + length]
00010909 ff 75 f0        PUSH       dword ptr [EBP + local_14]
0001090c e8 b1 fe        CALL       repeated_byteswap
         ff ff
00010911 83 c4 10        ADD        ESP,0x10
```
So, '911 would be the breakpoint to choose here.  
(And the address of the buffer should still be on the stack, as the first argument.)

We also need a moment to actually set the bytes, as we can't neccessarily write  
them. After the return of the `fgets` call should do.
```
(gdb) b *0x56555911
Breakpoint 2 at 0x56555911
(gdb) b fgets
Breakpoint 3 at 0xf7c73234
```

Alright, let's go.
```
(gdb) r
[...]
Breakpoint 3, 0xf7c73234 in fgets () from /lib32/libc.so.6
(gdb) fin
[...]
input the flag: a
0x56555a10 in ?? ()
(gdb) x/s $eax
0x565581a0:     "a\n"
(gdb) set*(char [30] *) 0x565581a0 = {0x2e,0x6e,0x40,0x68,0x1d,0x53,0x65,0x7c,0x17,0x58,0x16,0x43,0x6d,0x58,0x62,0x36,0x6f,0x43,0x62,0x30,0x01,0x34,0x16,0x3f,0x3f,0x3e,0x12,0x32,0x6e,0x7a}
(gdb) c
Continuing.

Breakpoint 2, 0x56555911 in ?? ()
(gdb) x/a $esp
0xffffcf80:     0x56558c00
(gdb) x/s 0x56558c00
0x56558c00:     "picoCTF{I_5D3_A11DA7_358a9150}"
```

We did it! The flag is: `picoCTF{I_5D3_A11DA7_358a9150}`

Now we need to find out why the binary was called `brute`...


