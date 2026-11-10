# level07

### first the code leak the win function
```c
    put(fd, "  [FSOP] Stream multiplexer v1.2\033[0m\n");
    snprintf(line, sizeof line, "[FSOP] loader @ %p\n", (void *)win); <--here
```

### there is heap buffer overflow the user control how many bytes is going to be writen so bytes more the how much the buffer can have
```c
        case 2: {
            put(fd, "slot: ");
            long i = rd_long(fd);
            if (i < 0 || i >= MAX_STREAMS || !streams[i]) break;
            put(fd, "len: ");
            long n = rd_long(fd); <-- n is user controlled data
            put(fd, "data: ");
            read(fd, streams[i]->data, n); <-- here
            break;
        }
```

### this the struct that we can controlle using heap buffer overflow, plus the struct has some function pointers that we can use to call win function if we succed to overwite it's function pointer

``` c
struct stream;
struct vtable {
    void (*flush)(struct stream *);
    void (*close)(struct stream *);
};
struct stream {
    struct vtable *vt;
    char data[DATA_SIZE];
};
```

### the problem is the strut derefrence it's vtable pointer and treat the first 8 bytes as function pointer
### the solution will will put address of win function in a knowed address and overwrite the struct pointer to that knowen address so that when binary try to call the first 8 bytes after derefencing the pointer it will can our win function

### we can do that by allocating two chunks and to do the buffer overflow in the first one and then call the flush function of the second struct and trigger the win function
