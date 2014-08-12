INT3 / INT6 IDT hook

Really dirty code :]

Driver
> INT3 : just dbgprint
> INT6 : updates EIP to EIP+4

User app
> runs 0xFFFFFFFFC3 (C3 = RET opcode)

The drivers will catch the INT6 (system wide, no checks), update EIP and IRETD which will let the user app continue without crash.
