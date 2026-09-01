# level 00 blind service running at port 4243

## 1- Recon
### - The service uses a forked process to communicate with the client (the PID of the process doesn't change after a segfault, and the canary of the child process doesn't change).
### - There is a buffer overflow in the child process
### - PIE is disabled inside the binary because the instruction addresses don't change after a shutdown.



## 2- Assumptions
### 1- First one there is a dummy function inside the code that already spawns a shell
### 2- There is a blind ROP chain




## 3- First Assumption
### 1- First find where the buffer overflow exists (after 72 bytes)
### 2- 2- I brute-forced the canary from the child by sending one byte at a time. If the child is still running, the byte sent is part of the canary; if it shuts down, we have a false canary prediction.
### 3- Find a stop gadget: the address of an instruction that hangs the program and doesn't segfault it.

### 4- Use the stop gadget to find a ret instruction that we need to use for brute-forcing. If there is a function that spawns a shell inside the code, it is used to 16-byte realign the stack.

```markdown
(offset 72 bytes) + (canary) + (prediction of ret instruction) + (stop gadget) -> If the program segfaults, it's not a ret gadget. If it doesn't, it's probably a ret gadget that still needs to be checked (it may just be another stop gadget).
```

### 5- Then, after some brute-forcing, we found that the address at 0x40137f spawns the shell, and from there we got the flag and moved to the next level.

