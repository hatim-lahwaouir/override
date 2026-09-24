# Level 03 virek

## 1- Recon
### - Source code was given
### - existing of tow vulnerabilities double free and use after free
### - PIE was enabled
### - we can see inside the code there is win function that we can use to spawn a shell 
### - There is a function pointer inside the admin struct. If we successfully overwrite it with the win function, we can spawn a shell when that pointer is called
### - libc version 2.39
```markdown
/lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.9) stable release version 2.39.
```
### - this libc version use safe link when adding a free chunk to the tcache linked list  


## 2- Definitions 
### - how bins works 
 - bins  are explicit linked lists managed inside heap  to track freed memory chunks globally across threads
 - bins are used inside the program when you free a portion of memory and you want to allocate new portion of memory if they were the same size malloc where not allocate new memory it will use the one inside the tcache 

### - for how malloc chunk look like you can check this 
[documentation](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/malloc_chunk)


## 3- Exploit
- The program gives us functionalities to manage memory.
- The goal is to trick malloc into returning the address of the gadmin struct by poisoning the tcache.
- Then, overwrite the function pointer with our win function (the program already outputs the win function address, which we use to bypass PIE and locate the function).
- We need the safe-linking key to set the address that malloc will return.
- We can leak it by reading the pointer after the chunk is freed.
- Malloc and free use this key to make it harder to poison the tcache. It doesn't store the raw address in the tcache linked list; it always XORs it as: (chunk_address >> 12) ^ target_address.
- So, after leaking this key, we will use it to trick malloc into returning the address of the gadmin struct.
- Then, we will overwrite the pointer with our win function to spawn a shell.


