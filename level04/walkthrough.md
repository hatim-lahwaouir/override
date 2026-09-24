# Level 04 marly

## 1- Recon
- Source code was given
- There is a heap buffer overflow
- There is a win function inside the source code


## 2- Exploit
- There is a heap overflow in the annotate functionality

- We can write out of bounds of the title inside the struct

- We can allocate two structs and use the heap overflow to overwrite a function pointer in the second struct

- Then we can use the display functionality on the second struct after overwriting its function pointer with the win function and spawn the shell





```

(first piece)  [metadata] [(function pointer), title [40 bytes]] 
(second piece) [metadata] [(function pointer), title [40 bytes]]
                            ----------------
                                |- by using the heap overflow we can overwrite this address and point it to the win function and spawn a shell
```

