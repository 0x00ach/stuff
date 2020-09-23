
```
6A 40 68 00 30 00 00 68 00 00 01 00 6A 00 E8 D7 C0 C7 74 8B F0 6A 00 68 43 3A 5C 41 8B C4 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 50 E8 84 A0 C8 74 6A 00 55 68 00 00 01 00 56 50 E8 05 A4 C8 74 FF E6
```

```asm
push 40
push 3000
push 10000
push 0
call <kernel32.VirtualAlloc>   ; please patch
mov esi,eax
push 0
push 415C3A43                  ; C:\A => place your bin file here
mov eax,esp
push 0
push 80
push 3
push 0
push 0
push 80000000
push eax
call <kernel32.CreateFileA>   ; please patch
push 0
push ebp
push 10000
push esi
push eax
call <kernel32.ReadFile>      ; please patch
jmp esi
```
