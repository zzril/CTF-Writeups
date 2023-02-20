Let's get dynamic
=================

We're given an assembler file in AT&T syntax, `chall.S`.

We could analyze this file directly, but we decide to first compile/assemble it  
with GCC, then have a look at it with `objdump`.
```sh
$ gcc chall.S
$ objdump -M intel -d a.out
```
This already gives us a nice view of the PLT and shows us some interesting  
function imports: `puts`, `strlen`, `memcmp`, `fgets`.  
The `memcmp` looks interesting. Might be a quick one!

But alright, let's run it first. It seems to expect input via stdin.
```
$ ./a.out
test
Correct! You entered the flag.
$ ./a.out
AAAABBBBCCCCDDDD
Correct! You entered the flag.
```
Huh? Looks like the author has messed up sthg here.

Let's have a look at it in Ghidra...  
Looking at the `.rodata` section, we can find our "success" message as well as a  
supposed failure message, "No, that's not right.".  
Checking their usages leads us to the supposed main function, which ends:
```c
iVar1 = memcmp(local_d8,local_118,0x31);
if (iVar1 == 0) {
  puts("No, that\'s not right.");
}
else {
  puts("Correct! You entered the flag.");
}
```
Alright, so indeed the `memcmp` seems to be used for checking the input at some  
point, and apparently the author just made an off-by-one error.  
(`memcmp` returns 0 if both memory regions are identical, so we would probably  
want to output the success message in that case.)

Enough of that, let's fire up GDB.
```
$ gdb a.out
[...]
(gdb) r
[...]
AAAABBBBCCCCDDDD
Correct! You entered the flag.
[Inferior 1 (process [...]) exited normally]
(gdb) b memcmp
Breakpoint 1 at [...] (2 locations)
(gdb) r
[...]
AAAABBBBCCCCDDDD
Breakpoint 1, memcmp_ifunc_selector () at ../sysdeps/x86_64/multiarch/ifunc-memcmp.h:34
```
(Don't forget that the "Correct!" string actually means we failed.)

Unfortunately, this is not where we wanted to break. We apparently landed in  
some dynamic linker magic where it attempts to choose the "best" `memcmp`  
implementation for our architecture. That's what we get for just blindly  
compiling the given source file without any special flags!  

Anyway, using `layout asm` and some `si` later, we end up at the start of the  
actual `memcmp` implementation, with our registers set up as expected.  
Let's check the arguments passed to `memcmp`:
```
__memcmp_sse2 () at ../sysdeps/x86_64/multiarch/memcmp-sse2.S:71
(gdb) x/s $rdi
[...] "AAAABBBBCCCCDDDD\n"
(gdb) x/s $rsi
[...] "picoCTF{dyn4"
(gdb) p/d $rdx
$1 = 49
```

Huh? Is the program broken once again? Why is only half of the flag compared  
to the user input?  
Let's have a look at it in Ghidra again...  
Going back to the main function, we first see some encrypted string being  
created on the stack:
```c
local_98 = 0x33bd6dc7f9c4ca87;
local_90 = 0xcc5d9900411d5626;
local_88 = 0x4d0b7fe395e5157e;
local_80 = 0xfa69a6474a531c8c;
local_78 = 0x84576a1b40331a16;
local_70 = 0x709e54e8917dc9f8;
local_68 = 0x72;
local_58 = 0x5cee2f9386b6b1e4;
local_50 = 0x8f23b6726d6a3559;
local_48 = 0x167d489df9d07949;
local_40 = 0x8457d83d770565b6;
local_38 = 0xef0e294a43715d7a;
local_30 = 0x7e9b0bb19f72c1fa;
local_28 = 0x2c;
```
Next, we get the user input:
```c
fgets(local_d8,0x31,stdin);
```
Then there's some loop that is probably decrypting the string:
```c
local_11c = 0;
while( true ) {
  sVar2 = strlen((char *)&local_98);
  if (sVar2 <= (ulong)(long)local_11c) break;
  local_118[local_11c] =
       (byte)local_11c ^
       *(byte *)((long)&local_98 + (long)local_11c) ^ *(byte *)((long)&local_58 + (long)local_11c)
       ^ 0x13;
  local_11c = local_11c + 1;
}
```
And finally, there's the buggy `memcmp` call...

The `strlen` call in the loop is odd. It is called on the encrypted stack  
string, which contains null bytes in the middle.  
The result of the `strlen` call, `sVar2`, is compared to our counter variable,  
`local_11c`, to decide if we break out of the loop.  
Maybe this should be replaced by the hardcoded, known length of the flag? (0x31,  
the size of the input buffer as well as the length argument passed to `memcmp`.)

We could try to change the variable inside GDB or patch the binary. But this  
could also be the time for a different solving technique: Inject our own version  
of the called functions using `LD_PRELOAD`.

We write our own custom version of `strlen`, which always returns 0x31.  
As we're at it, we also write our own `memcmp`, which nicely prints the buffers  
passed to it on stdout (and always returns 0). This should avoid the hassle with  
finding the actual `memcmp` start after all that dynamic linker magic...  
(For the actual code, see `debug.c`.)

Let's try it...:
```
$ LD_PRELOAD=./debug.so ./a.out
test
test
picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_9266fa82}No, that's not right.
```
Voilà! the flag is: `picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_9266fa82}`


