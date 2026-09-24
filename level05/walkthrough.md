# Level 05 angie

## 1- Recon
- Source code was given
- There is a direct struct overwrite 
- There is a win function inside the source code


## 2- Exploit
- There is a direct struct overwrite 
- we can use it to overwrite the function pointer with the win function 


```

typedef struct signal_s {
    void (*process)(struct signal_s *);
    char data[DATA_SIZE];
} signal_t;


static void write_signal(void) {
    printf("slot: "); fflush(stdout); long i = rd_long();
    if (i < 0 || i >= MAX_SIGNALS || !signals[i]) return;
    printf("len: "); fflush(stdout); size_t n = (size_t)rd_long();
    if (n > sizeof(signal_t)) n = sizeof(signal_t);
    printf("data: "); fflush(stdout);
    read(STDIN_FILENO, signals[i], n);
                       --------
}                      |- here you have access to the whole struct so we can overwrite the process 
                       | with address of win function  
```

- the we will call the process_signal function to trigger the win function 
