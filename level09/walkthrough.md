# level09 - 3Jane

### A challenge related to a Use-After-Free exploit. The source code was already provided.

```c
static void obj_release(void) {
    printf("slot: "); fflush(stdout); long i = rd_long();
    if (i < 0 || i >= MAX_OBJS || !heap[i]) return;
    free(heap[i]);
}
```

### We can free a chunk and still read it. The code doesn't set the pointer to NULL, and it still allows us to read the freed chunk, which lets us leak the Safe-Linking key.

```c
static void obj_view(void) {
    printf("slot: "); fflush(stdout); long i = rd_long();
    if (i < 0 || i >= MAX_OBJS || !heap[i]) return;
    printf("[3JANE] trace: ");
    write(STDOUT_FILENO, heap[i], sizeof(obj_t));
    puts("");
}
```

### We can also leak the PIE base address because the struct holds an address to a function in our code.

```c
typedef struct obj_s {
    void (*finalize)(struct obj_s *); // <-- here
    unsigned long id;
    char data[DATA_SIZE];
} obj_t;

...

heap[i]->finalize = default_finalize; // <-- here
```

### We can call the function through functionality provided by the program. `g_final` is a global function pointer. If we can trick malloc into returning its address, we can overwrite it with the address of our `win` function.

```c
static void (*g_final)(void) __attribute__((aligned(16)));

__attribute__((used)) static void win(void) {
    system("/bin/sh");
}

...

static void obj_commit(void) {
    g_final();
}
```

We know the addresses of all these functions and the global function pointer. By leaking the PIE base address, we can calculate their addresses at runtime.

# The Exploit Steps

1. Leak the PIE base address.
2. Leak the Safe-Linking key to perform tcache poisoning.
3. Trick malloc into returning the address of our global function pointer.
4. Overwrite it with the address of `win`.
5. Trigger `obj_commit()` to execute our `win` function and get the flag.
