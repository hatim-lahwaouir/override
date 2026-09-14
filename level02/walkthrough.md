# Level 02 finn

## 1- Recon
### - Source code was given
### - Use of the unsafe function `gets`
### - PIE was disabled
### - addreses of GOT,PLT table are fixed
### - NX enabled we can't run code in the stack, no RELRO we can overwrite GOT 
``` markdown
  checksec finn
[*] '/home/level02/finn'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled

```



## 2- Exploit
### - we can use the PLT/GOT leak technique 
### - first GOT contains runtime addresses of dynamically linked functions
### - we will call the puts@plt and give puts@got address as argument so that it print where puts exists in libc
### - we need also the program to not shutdown so we will return the execution to the start of the main function  

### - so then we will use our ROP gadget plus the offset to the libc that we know to spawn a shell 


```markdown
 first payload = "A" * (offset) +  (our rop gadget) + (puts@got) + (dummy args) + (return gadget) + (address of puts@plt) + (address of main function)
```
```markdown
 second payload = "A" * (offset) +  (our rop gadget) + (bin sh address) + (dummy args) + (system function) 
 ```

### - after calculating the pie we can call any ROP gadget inside libc plus any function to give us shell execution
### - we need to find the sting "/bin/sh" inside libc, two ROP gadget (pop rdi) to set up argument of system call and (ret) to align stack


```


