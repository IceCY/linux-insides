Interrupts and Interrupt Handling. Part 3.
================================================================================

Exception Handling
--------------------------------------------------------------------------------

This is the third part of the [chapter](https://0xax.gitbook.io/linux-insides/summary/interrupts) about an interrupts and an exceptions handling in the Linux kernel and in the previous [part](https://0xax.gitbook.io/linux-insides/summary/interrupts) we stopped at the `setup_arch` function from the [arch/x86/kernel/setup.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/kernel/setup.c) source code file.

We already know that this function executes initialization of architecture-specific stuff. In our case the `setup_arch` function does [x86_64](https://en.wikipedia.org/wiki/X86-64) architecture related initializations. The `setup_arch` is big function, and in the previous part we stopped on the setting of the two exceptions handlers for the two following exceptions:

* `#DB` - debug exception, transfers control from the interrupted process to the debug handler;
* `#BP` - breakpoint exception, caused by the `int 3` instruction.

These exceptions allow the `x86_64` architecture to have early exception processing for the purpose of debugging via the [kgdb](https://en.wikipedia.org/wiki/KGDB).

As you can remember we set these exceptions handlers in the `idt_setup_early_traps` function:

```C
void __init idt_setup_early_traps(void)
{
	idt_setup_from_table(idt_table, early_idts, ARRAY_SIZE(early_idts),
			     true);
	load_idt(&idt_descr);
}
```

from the [arch/x86/kernel/idt.c](https://github.com/torvalds/linux/tree/master/arch/x86/kernel/idt.c). Now we will look on the implementation of these two exceptions handlers.

Debug and Breakpoint exceptions
--------------------------------------------------------------------------------

Ok, we setup exception handlers in the `idt_setup_early_traps` function for the `#DB` and `#BP` exceptions and now time is to consider their implementations. But before we will do this, first of all let's look on details of these exceptions.

The first exceptions - `#DB` or `debug` exception occurs when a debug event occurs. For example - attempt to change the contents of a [debug register](http://en.wikipedia.org/wiki/X86_debug_register). Debug registers are special registers that were presented in `x86` processors starting from the [Intel 80386](http://en.wikipedia.org/wiki/Intel_80386) processor and as you can understand from name of this CPU extension, main purpose of these registers is debugging.

These registers allow to set breakpoints on the code and read or write data to trace it. Debug registers may be accessed only in the privileged mode and an attempt to read or write the debug registers when executing at any other privilege level causes a [general protection fault](https://en.wikipedia.org/wiki/General_protection_fault) exception. That's why we specify the ` DPL` field of  `#DB`'s  IDT descriptor as `0`. 

The verctor number of the `#DB` exceptions is `1` (we pass it as `X86_TRAP_DB`) and as we may read in specification, this exception has no error code:

```
+-----------------------------------------------------+
|Vector|Mnemonic|Description         |Type |Error Code|
+-----------------------------------------------------+
|1     | #DB    |Reserved            |F/T  |NO        |
+-----------------------------------------------------+
```

The second exception is `#BP` or `breakpoint` exception occurs when processor executes the [int 3](http://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT_3) instruction. Unlike the `DB` exception, the `#BP` exception may occur in userspace. We can add it anywhere in our code, for example let's look on the simple program:

```C
// breakpoint.c
#include <stdio.h>

int main() {
    int i;
    while (i < 6){
	    printf("i equal to: %d\n", i);
	    __asm__("int3");
		++i;
    }
}
```

If we will compile and run this program, we will see following output:

```
$ gcc breakpoint.c -o breakpoint
i equal to: 0
Trace/breakpoint trap
```

But if will run it with gdb, we will see our breakpoint and can continue execution of our program:

```
$ gdb breakpoint
...
...
...
(gdb) run
Starting program: /home/alex/breakpoints 
i equal to: 0

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:	83 45 fc 01	add    DWORD PTR [rbp-0x4],0x1
(gdb) c
Continuing.
i equal to: 1

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:	83 45 fc 01	add    DWORD PTR [rbp-0x4],0x1
(gdb) c
Continuing.
i equal to: 2

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:	83 45 fc 01	add    DWORD PTR [rbp-0x4],0x1
...
...
...
```

From this moment we know a little about these two exceptions and we can move on to consideration of their handlers.

Preparation before an exception handler
--------------------------------------------------------------------------------

The exception handler is specified in the second parameter of the `INTG` or `SYSG` macro. In our case two exception handlers will be:

* `debug`;
* `int3`.

You will not find these functions in the C code. all of that could be found in the kernel's `*.c/*.h` files only definition of these functions which are located in the [arch/x86/include/asm/traps.h](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/include/asm/traps.h) kernel header file:

```C
asmlinkage void debug(void);
```

and

```C
asmlinkage void int3(void);
```

You may note `asmlinkage` directive in definitions of these functions. The directive is the special specificator of the [gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection). Actually for a `C` functions which are called from assembly, we need in explicit declaration of the function calling convention. In our case, if function made with `asmlinkage` descriptor, then `gcc` will compile the function to retrieve parameters from stack.

So, both handlers are defined in the [arch/x86/entry/entry_64.S](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/entry/entry_64.S) assembly source code file with the `idtentry` macro:

```assembly
idtentry debug			do_debug		has_error_code=0	paranoid=1 shift_ist=IST_INDEX_DB ist_offset=DB_STACK_OFFSET
```

and

```assembly
idtentry int3			do_int3			has_error_code=0	create_gap=1
```

Each exception handler may be consists from two parts. The first part is generic part and it is the same for all exception handlers. An exception handler should to save  [general purpose registers](https://en.wikipedia.org/wiki/Processor_register) on the stack, switch to kernel stack if an exception came from userspace and transfer control to the second part of an exception handler. The second part of an exception handler does certain work depends on certain exception. For example page fault exception handler should find virtual page for given address, invalid opcode exception handler should send `SIGILL` [signal](https://en.wikipedia.org/wiki/Unix_signal) and etc.

As we just saw, an exception handler starts from definition of the `idtentry` macro from the [arch/x86/entry/entry_64.S](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/entry/entry_64.S) assembly source code file, so let's look at implementation of this macro. As we may see, the `idtentry` macro takes multiple arguments:

* `sym` - defines global symbol which will be an entry of exception handler;
* `do_sym` - symbol name which represents a secondary entry of an exception handler and It represents a C function;
* `has_error_code` - information about existence of an error code of exception.

The other parameters are optional:

* `paranoid` - non-zero means that this vector may be invoked from kernel mode with user GSBASE and/or user CR3
  * Only `debug` & `machine check` exceptions have `1`
  * `2` is special: stack is never switched. This is for `double fault` exception
* `shift_ist` - shows us is an exception running at `Interrupt Stack Table`.
* `ist_offset` - **TODO**
* `create_gap` - create a 6-word stack gap when coming from kernel mode. It is used to allow the `int3` handler to emulate a call instruction.

Definition of the `.idtentry` macro looks:

```assembly
.macro idtentry sym do_sym has_error_code:req paranoid=0 shift_ist=-1 ist_offset=0 create_gap=0 read_cr2=0
SYM_CODE_START(\sym)
...
...
...
_ASM_NOKPROBE(\sym)
SYM_CODE_END(\sym)
.endm
```

Before we will consider internals of the `idtentry` macro, we should to know state of stack when an exception occurs. As we may read in the [Intel® 64 and IA-32 Architectures Software Developer’s Manual 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html), the state of stack when an exception occurs is following:

```
    +------------+
+40 | %SS        |
+32 | %RSP       |
+24 | %RFLAGS    |
+16 | %CS        |
 +8 | %RIP       |
  0 | ERROR CODE | <-- %RSP
    +------------+
```

Now we may start to consider implementation of the `idtmacro`. Both `#DB` and `BP` exception handlers are defined as:

```assembly
idtentry debug			do_debug		has_error_code=0	paranoid=1 shift_ist=IST_INDEX_DB ist_offset=DB_STACK_OFFSET
idtentry int3			do_int3			has_error_code=0	create_gap=1
```

If we will look at these definitions, we may know that compiler will generate two routines with `debug` and `int3` names and both of these exception handlers will call `do_debug` and `do_int3` secondary handlers after some preparation. The third parameter defines existence of error code and as we may see both our exception do not have them. As we may see on the diagram above, processor pushes error code on stack if an exception provides it. In our case, the `debug` and `int3` exception do not have error codes. This may bring some difficulties because stack will look differently for exceptions which provides error code and for exceptions which not. That's why implementation of the `idtentry` macro starts from putting a fake error code to the stack if an exception does not provide it:

```assembly
.ifeq \has_error_code
    pushq	$-1
.endif
```

But it is not only fake error-code. Moreover the `-1` also represents invalid system call number, so that the system call restart logic will not be triggered.

Another two parameters of the `idtentry` macro `shift_ist` and `paranoid` allow to know do an exception handler runned at stack from `Interrupt Stack Table` or not. You already may know that each kernel thread in the system has own stack. In addition to these stacks, there are some specialized stacks associated with each processor in the system. One of these stacks is - exception stack. The [x86_64](https://en.wikipedia.org/wiki/X86-64) architecture provides special feature which is called - `Interrupt Stack Table`. This feature allows to switch to a new stack for designated events such as an atomic exceptions like `double fault` and etc. So the `shift_ist` parameter allows us to know do we need to switch on `IST` stack for an exception handler or not.

The second parameter - `paranoid`  indicates whether this exception can be invoked from kernel mode with user `GSBASE` and/or user `CR3`. The easiest way to determine this is to via `CPL` or `Current Privilege Level` in `CS` segment register. If it is equal to `3`, we came from userspace, if zero we came from kernel space:

```assembly
testb	$3, CS-ORIG_RAX(%rsp)		/* If coming from userspace, switch stacks */
jnz	.Lfrom_usermode_switch_stack_\@
...
...
...
```

But unfortunately this method does not give a 100% guarantee. As described in the kernel documentation:

> if we are in an NMI/MCE/DEBUG/whatever super-atomic entry context,
> which might have triggered right after a normal entry wrote CS to the
> stack but before we executed SWAPGS, then the only safe way to check
> for GS is the slower method: the RDMSR.

In other words for example `NMI` could happen inside the critical section of a [swapgs](http://www.felixcloutier.com/x86/SWAPGS.html) instruction. In this way we should check value of the `MSR_GS_BASE` [model specific register](https://en.wikipedia.org/wiki/Model-specific_register) which stores pointer to the start of per-cpu area. So to check did we come from userspace or not, we should to check value of the `MSR_GS_BASE` model specific register and if it is negative we came from kernel space, in other way we came from userspace:

```assembly
movl $MSR_GS_BASE,%ecx
rdmsr
testl %edx,%edx
js 1f
```

In first two lines of code we read value of the `MSR_GS_BASE` model specific register into `edx:eax` pair. We can't set negative value to the `gs` from userspace. But from other side we know that direct mapping of the physical memory starts from the `0xffff880000000000` virtual address. In this way, `MSR_GS_BASE` will contain an address from `0xffff880000000000` to `0xffffc7ffffffffff`. After the `rdmsr` instruction will be executed, the smallest possible value in the `%edx` register will be - `0xffff8800` which is `-30720` in unsigned 4 bytes. That's why kernel space `gs` which points to start of `per-cpu` area will contain negative value.

Finally, the `idtentry` macro would invoke the `idtentry` macro. There are different cases based on `paranoid` and whether an exception comes from userspace or not: 

```assembly
    .if \paranoid == 1
    testb	$3, CS-ORIG_RAX(%rsp)		/* If coming from userspace, switch stacks */
    jnz	.Lfrom_usermode_switch_stack_\@
    .endif
    ...
    idtentry_part \do_sym, \has_error_code, \read_cr2, \paranoid, \shift_ist, \ist_offset
	.if \paranoid == 1
	/*
	 * Entry from userspace.  Switch stacks and treat it
	 * as a normal entry.  This means that paranoid handlers
	 * run in real process context if user_mode(regs).
	 */
.Lfrom_usermode_switch_stack_\@:
	idtentry_part \do_sym, \has_error_code, \read_cr2, paranoid=0
	.endif
```

Let's look at the implementation of `idtentry_part` now.

idtentry_part
----------------------------------------------------------------------------------------
The first thing to do in `idtentry_part` is to save all registers in `pt_regs` and switch `gs` if needed. However, based on different ways used to determine whether an exception comes from userspace, two different functions are called.

```assembly
	.if \paranoid
	// come from kernel mode & paranoid==1
	call	paranoid_entry
	/* returned flag: ebx=0: need swapgs on exit, ebx=1: don't need it */
	.else
	call	error_entry
	.endif
```

Let's consider first case when we came from userspace or has `paranoid` equals to 1. As described above we would execute:

```assembly
call	error_entry
```

routine which saves and clears all general purpose registers on the stack:

```assembly
	PUSH_AND_CLEAR_REGS save_ret=1
```

`PUSH_AND_CLEAR_REGS` macro is defined in the  [arch/x86/entry/calling.h](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/entry/calling.h) header file and just move values of general purpose registers to a certain place at the stack, for example:

```assembly
.macro PUSH_AND_CLEAR_REGS rdx=%rdx rax=%rax save_ret=0
	/*
	 * Push registers and sanitize registers of values that a
	 * speculation attack might otherwise want to exploit. The
	 * lower registers are likely clobbered well before they
	 * could be put to use in a speculative execution gadget.
	 * Interleave XOR with PUSH for better uop scheduling:
	 */
	.if \save_ret
	pushq	%rsi		/* pt_regs->si */
	movq	8(%rsp), %rsi	/* temporarily store the return address in %rsi */
	movq	%rdi, 8(%rsp)	/* pt_regs->di (overwriting original return address) */
	.else
	pushq   %rdi		/* pt_regs->di */
	pushq   %rsi		/* pt_regs->si */
	.endif
	pushq	\rdx		/* pt_regs->dx */
	xorl	%edx, %edx	/* nospec   dx */
	pushq   %rcx		/* pt_regs->cx */
	xorl	%ecx, %ecx	/* nospec   cx */
	pushq   \rax		/* pt_regs->ax */
	pushq   %r8		/* pt_regs->r8 */
	xorl	%r8d, %r8d	/* nospec   r8 */
	pushq   %r9		/* pt_regs->r9 */
	xorl	%r9d, %r9d	/* nospec   r9 */
	pushq   %r10		/* pt_regs->r10 */
	xorl	%r10d, %r10d	/* nospec   r10 */
	pushq   %r11		/* pt_regs->r11 */
	xorl	%r11d, %r11d	/* nospec   r11*/
	pushq	%rbx		/* pt_regs->rbx */
	xorl    %ebx, %ebx	/* nospec   rbx*/
	pushq	%rbp		/* pt_regs->rbp */
	xorl    %ebp, %ebp	/* nospec   rbp*/
	pushq	%r12		/* pt_regs->r12 */
	xorl	%r12d, %r12d	/* nospec   r12*/
	pushq	%r13		/* pt_regs->r13 */
	xorl	%r13d, %r13d	/* nospec   r13*/
	pushq	%r14		/* pt_regs->r14 */
	xorl	%r14d, %r14d	/* nospec   r14*/
	pushq	%r15		/* pt_regs->r15 */
	xorl	%r15d, %r15d	/* nospec   r15*/
	UNWIND_HINT_REGS
	.if \save_ret
	pushq	%rsi		/* return address on top of stack */
	.endif
.endm
```

After execution of `PUSH_AND_CLEAR_REGS` the stack will look:

```
     +------------+
+160 | %SS        |
+152 | %RSP       |
+144 | %RFLAGS    |
+136 | %CS        |
+128 | %RIP       |
+120 | ERROR CODE |
     |------------|
+112 | %RDI       |
+104 | %RSI       |
 +96 | %RDX       |
 +88 | %RCX       |
 +80 | %RAX       |
 +72 | %R8        |
 +64 | %R9        |
 +56 | %R10       |
 +48 | %R11       |
 +40 | %RBX       |
 +32 | %RBP       |
 +24 | %R12       |
 +16 | %R13       |
  +8 | %R14       |
  +0 | %R15       | <- %RSP
     +------------+
```

After the kernel saved general purpose registers at the stack, we should check that we came from userspace space again with:

```assembly
testb	$3, CS+8(%rsp)
jz	.Lerror_kernelspace
```

If the exception comes from userspace, `swapgs` is invoked to user `kernel_gs_base`. Then we would switch stack to kernel thread stack and copy the saved `pt_regs` to the kernel thread stack. 

```assembly
movq	%rsp, %rdi
call	sync_regs
```

Here we put base address of stack pointer `%rdi` register which will be first argument (according to [x86_64 ABI](https://www.uclibc.org/docs/psABI-x86_64.pdf)) of the `sync_regs` function and call this function which is defined in the [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/traps.c) source code file:

```C
asmlinkage __visible notrace struct pt_regs *sync_regs(struct pt_regs *eregs)
{
	struct pt_regs *regs = (struct pt_regs *)this_cpu_read(cpu_current_top_of_stack) - 1;
	if (regs != eregs)
		*regs = *eregs;
	return regs;
}
```

As we came from userspace, this means that exception handler will run in real process context. After we got stack pointer from the `sync_regs` we switch stack:

```assembly
movq	%rax, %rsp
```

The last steps before an exception handler will call secondary handler are:

1. Passing pointer to `pt_regs` structure which contains preserved general purpose registers to the `%rdi` register:

```assembly
movq	%rsp, %rdi
```

as it will be passed as first parameter of secondary exception handler.

2. Pass error code to the `%rsi` register as it will be second argument of an exception handler and set it to `-1` on the stack for the same purpose as we did it before - to prevent restart of a system call:

```assembly
.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi
	movq	$-1, ORIG_RAX(%rsp)
.else
	xorl	%esi, %esi
.endif
```

Additionally you may see that we zeroed the `%esi` register above in a case if an exception does not provide error code. 

3. If `read_cr2` is specified as non-zero, the value in `CR2` register would be moved into `%rdx` register to serve as the 3rd argument. The `CR2` register contains the linear (virtual) address that triggered the page fault.

```assembly
.if \read_cr2
/*
 * Store CR2 early so subsequent faults cannot clobber it. Use R12 as
 * intermediate storage as RDX can be clobbered in enter_from_user_mode().
 * GET_CR2_INTO can clobber RAX.
 */
GET_CR2_INTO(%r12);
.endif
...
.if \read_cr2
movq	%r12, %rdx			/* Move CR2 into 3rd argument */
.endif
```



In the end we just call secondary exception handler:

```assembly
call	\do_sym
```

which:

```C
dotraplinkage void do_debug(struct pt_regs *regs, long error_code);
```

will be for `debug` exception and:

```C
dotraplinkage void notrace do_int3(struct pt_regs *regs, long error_code);
```

will be for `int 3` exception. In this part we will not see implementations of secondary handlers, because of they are very specific, but will see some of them in one of next parts.

Next, let us consider about the implementation of `paranoid_entry` function. In this case (i.e., when `paranoid_entry` is invoked inside `idtentry_part`) an exception was occurred in kernelspace and `idtentry` macro is defined with `paranoid=1` for this exception. This value of `paranoid` means that we should use *slower way* that we saw in the beginning of this part to check whether we really came from kernelspace or not. The `paranoid_entry` routing allows us to know this:

```assembly
SYM_CODE_START_LOCAL(paranoid_entry)
	UNWIND_HINT_FUNC
	cld
	PUSH_AND_CLEAR_REGS save_ret=1
	ENCODE_FRAME_POINTER 8
	movl	$1, %ebx
	movl	$MSR_GS_BASE, %ecx
	rdmsr
	testl	%edx, %edx
	js	1f				/* negative -> in kernel */
	SWAPGS
	xorl	%ebx, %ebx

1:
	/*
	 * Always stash CR3 in %r14.  This value will be restored,
	 * verbatim, at exit.  Needed if paranoid_entry interrupted
	 * another entry that already switched to the user CR3 value
	 * but has not yet returned to userspace.
	 *
	 * This is also why CS (stashed in the "iret frame" by the
	 * hardware at entry) can not be used: this may be a return
	 * to kernel code, but with a user CR3 value.
	 */
	SAVE_AND_SWITCH_TO_KERNEL_CR3 scratch_reg=%rax save_reg=%r14

	/*
	 * The above SAVE_AND_SWITCH_TO_KERNEL_CR3 macro doesn't do an
	 * unconditional CR3 write, even in the PTI case.  So do an lfence
	 * to prevent GS speculation, regardless of whether PTI is enabled.
	 */
	FENCE_SWAPGS_KERNEL_ENTRY

	ret
SYM_CODE_END(paranoid_entry)
```

As you may see, this function represents the same that we covered before. We use second (slow) method to get information about previous state of an interrupted task. We checked this and executed `SWAPGS` in a case if we came from userspace.

Exit from an exception handler
--------------------------------------------------------------------------------

After secondary handler will finish its works, we will return to the `idtentry_part` macro and the next step will be jump to the `error_exit` or `paranoid_exit` based on `paranoid` value:

```assembly
.if \paranoid
/* this procedure expect "no swapgs" flag in ebx */
jmp	paranoid_exit
.else
jmp	error_exit
.endif
```

**ICE: STOP HERE**

The `error_exit` function defined in the same [arch/x86/entry/entry_64.S](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/entry_64.S) assembly source code file and the main goal of this function is to know where we are from (from userspace or kernelspace) and execute `SWPAGS` depends on this. Restore registers to previous state and execute `iret` instruction to transfer control to an interrupted task.

That's all.

Conclusion
--------------------------------------------------------------------------------

It is the end of the third part about interrupts and interrupt handling in the Linux kernel. We saw the initialization of the [Interrupt descriptor table](https://en.wikipedia.org/wiki/Interrupt_descriptor_table) in the previous part with the `#DB` and `#BP` gates and started to dive into preparation before control will be transferred to an exception handler and implementation of some interrupt handlers in this part. In the next part we will continue to dive into this theme and will go next by the `setup_arch` function and will try to understand interrupts handling related stuff.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

Links
--------------------------------------------------------------------------------

* [Debug registers](http://en.wikipedia.org/wiki/X86_debug_register)
* [Intel 80385](http://en.wikipedia.org/wiki/Intel_80386)
* [INT 3](http://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT_3)
* [gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection)
* [TSS](http://en.wikipedia.org/wiki/Task_state_segment)
* [GNU assembly .error directive](https://sourceware.org/binutils/docs/as/Error.html#Error)
* [dwarf2](http://en.wikipedia.org/wiki/DWARF)
* [CFI directives](https://sourceware.org/binutils/docs/as/CFI-directives.html)
* [IRQ](http://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29)
* [system call](http://en.wikipedia.org/wiki/System_call)
* [swapgs](http://www.felixcloutier.com/x86/SWAPGS.html)
* [SIGTRAP](https://en.wikipedia.org/wiki/Unix_signal#SIGTRAP)
* [Per-CPU variables](https://0xax.gitbook.io/linux-insides/summary/concepts/linux-cpu-1)
* [kgdb](https://en.wikipedia.org/wiki/KGDB)
* [ACPI](https://en.wikipedia.org/wiki/Advanced_Configuration_and_Power_Interface)
* [Previous part](https://0xax.gitbook.io/linux-insides/summary/interrupts)
