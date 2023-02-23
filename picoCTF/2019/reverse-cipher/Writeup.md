reverse_cipher
==============

We're given a binary, `rev`, and a text file, `rev_this`.
```
$ file *
rev:      ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=523d51973c11197605c76f84d4afb0fe9e59338c, not stripped
rev_this: ASCII text, with no line terminators
$ cat rev_this
picoCTF{w1{1wq8/7376j.:}
```
Looks like `rev_this` is some kind of encrypted flag, probably encrypted using  
the `rev` program.  

What happens if we run the binary?
```
$ chmod u+x rev
$ ./rev
No flag found, please make sure this is run on the server
zsh: segmentation fault  ./rev
```

Huh? Alright, let's have a look at in Ghidra then... The `file` command told us  
the binary is not stripped, so chances are we actually get something readable.

Indeed, Ghidra finds the `main` function and it actually looks quite readable.  
We give the variables more meaningful names and adjust an array size and it  
looks like this:
```c
void main(void)

{
  FILE *flag_fp;
  FILE *ciphertext_fp;
  ssize_t bytes_read;
  char buffer [24];
  int j;
  int i;
  char curr_char_encrypted;
  
  flag_fp = fopen("flag.txt","r");
  ciphertext_fp = fopen("rev_this","a");
  if (flag_fp == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (ciphertext_fp == (FILE *)0x0) {
    puts("please run this on the server");
  }
  bytes_read = fread(buffer,0x18,1,flag_fp);
  if ((int)bytes_read < 1) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  for (i = 0; i < 8; i = i + 1) {
    fputc((int)buffer[i],ciphertext_fp);
  }
  for (j = 8; j < 0x17; j = j + 1) {
    if ((j & 1U) == 0) {
      curr_char_encrypted = buffer[j] + '\x05';
    }
    else {
      curr_char_encrypted = buffer[j] + -2;
    }
    fputc((int)curr_char_encrypted,ciphertext_fp);
  }
  fputc((int)buffer[23],ciphertext_fp);
  fclose(ciphertext_fp);
  fclose(flag_fp);
  return;
}
```

Alright, so it reads 24 chars from a file called `flag.txt`, and then "encrypts"  
them by alternately adding the value 0x05 or subtracting 0x02.  
The first 8 and the very last character (i.e. the `picoCTF{` and the trailing `}`)  
from the flag are left untouched.  
The result of this "encryption" is then appended to a file `rev_this`.  
This also supports our hypothesis that the given text file is indeed the  
encrypted flag.

We notice that decrypting this cipher will be very similar to encrypting.  
The program expects its input via a `flag.txt` file, so let's create one:
```
$ mv rev_this flag.txt
```

Now in order to decrypt instead of encrypt, we need to replace the `add`  
instruction in the loop with a `sub` instruction and vice-versa:
```c
  for (j = 8; j < 0x17; j = j + 1) {
    if ((j & 1U) == 0) {
      curr_char_encrypted = buffer[j] + '\x05';
    }
    else {
      curr_char_encrypted = buffer[j] + -2;
    }
    fputc((int)curr_char_encrypted,ciphertext_fp);
  }
```
These are the relevant lines in the assembly:
```asm
00101267 83 c0 05        ADD        bytes_read,0x5
[...]
00101273 83 e8 02        SUB        bytes_read,0x2
```
The trailing `05` and `02` must be the operands, so we basically want to swap  
the `c0` and the `e8`.  
We can do so for example in `hexedit`, or using `vim`/`xxd`.

Let's try...
```
$ xxd -p rev rev.hex
$ sed -e 's/83c005/83e805/g;s/83e802/83c002/g' rev.hex > patch.hex
$ xxd -r -p patch.hex patch && chmod u+x patch
$ ./patch && cat rev_this
picoCTF{r3v3rs312528e05}
```

Voilà! The flag is `picoCTF{r3v3rs312528e05}`.


