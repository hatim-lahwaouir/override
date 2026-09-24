# Level 08: husk

## 1 - Recon
- The source code is leaking the address of the win function
- There is a use-after-free in the code: `free(g_ops);` frees g_ops but we can still use it
- The goal is to overwrite its function pointer with the win function to spawn a shell

## 2 - Exploit
- We can use the tcache and the use-after-free to overwrite the function pointer
- First we free g_ops, then we allocate a new note with the same size as g_ops
- malloc will return the first free chunk in the tcache, which is the former g_ops chunk
- Then we use the write functionality to overwrite the function pointer with the win function
- Finally we trigger format to call the function pointer through g_ops and spawn a shell+