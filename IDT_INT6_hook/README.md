INT3 / INT6 IDT hook

Really dirty code :]

Driver
- INT3 : just dbgprint info
- INT6 : dbgprint info and updates EIP to EIP+4

User app
- print messages then run 0xFFFFFFFFC3 (C3 = RET opcode)

The drivers will catch the INT6 (system wide, no checks), update EIP and IRETD which will let the user app continue without crash.
