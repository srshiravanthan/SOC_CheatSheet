# Assembly Language

## Assembly and Disassembly

| **Command**                                                        | **Description**               |
| ------------------------------------------------------------------ | ----------------------------- |
| `nasm -f elf64 helloWorld.s`                                       | Assemble code                 |
| `ld -o helloWorld helloWorld.o`                                    | Link code                     |
| `ld -o fib fib.o -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2` | Link code with libc functions |
| `objdump -M intel -d helloWorld`                                   | Disassemble `.text` section   |
| `objdump -M intel --no-show-raw-insn --no-addresses -d helloWorld` | Show binary assembly code     |
| `objdump -sj .data helloWorld`                                     | Disassemble `.data` section   |

## GDB

| **Command**                             | **Description**                                   |
| --------------------------------------- | ------------------------------------------------- |
| `gdb -q ./helloWorld`                   | Open binary in gdb                                |
| `info functions`                        | View binary functions                             |
| `info variables`                        | View binary variables                             |
| `registers`                             | View registers                                    |
| `disas _start`                          | Disassemble label/function                        |
| `b _start`                              | Break label/function                              |
| `b *0x401000`                           | Break address                                     |
| `r`                                     | Run the binary                                    |
| `x/4xg $rip`                            | Examine register "x/ count-format-size $register" |
| `si`                                    | Step to the next instruction                      |
| `s`                                     | Step to the next line of code                     |
| `ni`                                    | Step to the next function                         |
| `c`                                     | Continue to the next break point                  |
| `patch string 0x402000 "Patched!\\x0a"` | Patch address value                               |
| `set $rdx=0x9`                          | Set register value                                |
