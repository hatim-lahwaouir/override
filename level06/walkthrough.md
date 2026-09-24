# Level 06: Legba

## 1 - Recon
- The source code is provided.
- We have control over which address gets freed.
- We can write to any address returned by `malloc`.
- There is a struct containing a function pointer that calls the `default_path` function.
- We have a `win` function that can spawn a shell.
- The binary leaks both the address of the `win` function and the address of the function pointer inside the struct.

## 2 - Exploit
- The goal is to overwrite the function pointer inside the struct with the address of the `win` function.
- We can perform a Tcache poisoning attack to trick `malloc` into returning the address of the function pointer.
- We can poison the Tcache by passing the address of the `gate_s.path` function pointer to `free()`. This tricks the program into treating the struct as a heap chunk allocated by `malloc`.
- Because we control the first 16 bytes of the struct, we can fake a valid chunk header. This tricks the heap manager into treating our C struct as a valid `malloc_chunk`.
- Once the Tcache is poisoned, a subsequent call to `malloc` will return the address of the function pointer as if it were dynamically allocated heap memory.
- We can then overwrite the function pointer with the address of our `win` function to achieve code execution.