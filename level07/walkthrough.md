# Level 07: fsop

## 1 - Recon
- The source code is leaking the address of the win function
- We have an option to write in the data section of a stream
- The user can control the number of bytes that can be written in the stream.data
- There is a heap overflow in the binary
- There is a win function that spawns a shell
- There are function pointers inside the stream struct that we can call
- Overwriting the function pointer with the address of the win function will solve this level

## 2 - Exploit
- We can use the heap overflow to overwrite the vtable pointer of the next stream
- Allocating two streams and then writing to the first stream  data until we reach the next stream and overwrite its vtable pointer to point to the win function will spawn a shell