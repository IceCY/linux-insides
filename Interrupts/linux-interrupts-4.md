Interrupts and Interrupt Handling. Part 4.
================================================================================

Initialization of non-early interrupt gates
--------------------------------------------------------------------------------

This is fourth part about an interrupts and exceptions handling in the Linux kernel and in the previous [part](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-3) we saw first early `#DB` and `#BP` exceptions handlers from the [arch/x86/kernel/traps.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/kernel/traps.c). We stopped on the right after the `idt_setup_early_traps` function that called in the `setup_arch` function which defined in the [arch/x86/kernel/setup.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/kernel/setup.c). In this part we will continue to dive into an interrupts and exceptions handling in the Linux kernel for `x86_64` and continue to do it from the place where we left off in the last part. First thing which is related to the interrupts and exceptions handling is the setup of the `#PF` or [page fault](https://en.wikipedia.org/wiki/Page_fault) handler with the `idt_setup_early_pf` function. Let's start from it.

Early page fault handler
--------------------------------------------------------------------------------

The `idt_setup_early_pf` function defined in the [arch/x86/kernel/traps.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/kernel/idt.c). It fills [Interrupt Descriptor Table](https://en.wikipedia.org/wiki/Interrupt_descriptor_table) with the given entry:

```C
void __init idt_setup_early_pf(void)
{
	idt_setup_from_table(idt_table, early_pf_idts,
			     ARRAY_SIZE(early_pf_idts), true);
}
```

The global variable `early_pf_idts` defines the exception number and the corresponding handler entry.

```c
static const __initconst struct idt_data early_pf_idts[] = {
	INTG(X86_TRAP_PF,		page_fault),
};
```

In our case they are:

* `X86_TRAP_PF` - `14`;
* `page_fault` - the interrupt handler entry point.

The `X86_TRAP_PF` is the element of enum which defined in the [arch/x86/include/asm/traps.h](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/include/asm/traps.h):

```C
enum {
	...
	...
	...
	...
	X86_TRAP_PF,            /* 14, Page Fault */
	...
	...
	...
}
```

When the `idt_setup_early_pf` will be called, the `idt_setup_from_table` will be called to  fill the `IDT` with the handler for the page fault. Now let's look on the implementation of the `page_fault` handler. The `page_fault` handler defined in the [arch/x86/entry/entry_64.S](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/entry) assembly source code file as all exceptions handlers. Let's look on it:

```assembly
idtentry page_fault		do_page_fault		has_error_code=1	read_cr2=1
```

We saw in the previous [part](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-3) how `#DB` and `#BP` handlers defined. They were defined with the `idtentry` macro. We already saw implementation of the `idtentry` macro in the previous [part](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-3), so let's start from the `page_fault` exception handler.

As we can see in the `idtentry` definition, the handler of the `page_fault` is `do_page_fault` function which defined in the [arch/x86/mm/fault.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/mm/fault.c) and it takes three arguments:

* `regs` - `pt_regs` structure that holds state of an interrupted process;
* `error_code` - error code of the page fault exception.
* `address` - the linear (virtual) address that caused the page fault. This is retrived from the [CR2](https://en.wikipedia.org/wiki/Control_register) control register before.

```C
dotraplinkage void
do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	enum ctx_state prev_state;

	prev_state = exception_enter();
	trace_page_fault_entries(regs, error_code, address);
	__do_page_fault(regs, error_code, address);
	exception_exit(prev_state);
}
```

Let's look inside this function. Firstly we make a call of the `exception_enter` function from the [include/linux/context_tracking.h](https://elixir.bootlin.com/linux/v5.5/source/include/linux/context_tracking.h). The `exception_enter` and `exception_exit` are functions from context tracking subsystem in the Linux kernel used by the [RCU](https://en.wikipedia.org/wiki/Read-copy-update) to remove its dependency on the timer tick while a processor runs in userspace. *Almost in the every exception handler* we will see similar code:

```C
enum ctx_state prev_state;
prev_state = exception_enter();
...
... // exception handler here
...
exception_exit(prev_state);
```

The `exception_enter` function checks that `context tracking` is enabled with the `context_tracking_is_enabled` and if it is in enabled state, we get previous context with the `this_cpu_read` (more about `this_cpu_*` operations you can read in the [Documentation](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/Documentation/this_cpu_ops.txt)). If previous context is not `CONTEXT_KERNEL`, it calls `context_tracking_user_exit` function which informs the context tracking that the processor is exiting userspace mode and entering the kernel:

```C
static inline enum ctx_state exception_enter(void)
{
	enum ctx_state prev_ctx;

	if (!context_tracking_enabled())
		return 0;

	prev_ctx = this_cpu_read(context_tracking.state);
	if (prev_ctx != CONTEXT_KERNEL)
		context_tracking_exit(prev_ctx);

	return prev_ctx;
}
```

The state can be one of the:

```C
enum ctx_state {
    IN_KERNEL = 0,
	IN_USER,
} state;
```

And in the end we return previous context. Between the `exception_enter` and `exception_exit` we call actual page fault handler:

```C
__do_page_fault(regs, error_code, address);
```

The `__do_page_fault` is defined in the same source code file as `do_page_fault` - [arch/x86/mm/fault.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/mm/fault.c). In the beginning of the `__do_page_fault` we can see the call of the `prefetchw` which executes instruction with the same [name](http://www.felixcloutier.com/x86/PREFETCHW.html) which fetches [X86_FEATURE_3DNOW](https://en.wikipedia.org/?title=3DNow!) to get exclusive [cache line](https://en.wikipedia.org/wiki/CPU_cache). The main purpose of prefetching is to hide the latency of a memory access.

```C
	prefetchw(&current->mm->mmap_sem);
```

In the next step we check that we got page fault not in the kernel space with the following condition:

```C
if (unlikely(fault_in_kernel_space(address))) {
...
...
...
}
```

where `fault_in_kernel_space` is:

```C
static int fault_in_kernel_space(unsigned long address)
{
	/*
	 * On 64-bit systems, the vsyscall page is at an address above
	 * TASK_SIZE_MAX, but is not considered part of the kernel
	 * address space.
	 */
	if (IS_ENABLED(CONFIG_X86_64) && is_vsyscall_vaddr(address))
		return false;

	return address >= TASK_SIZE_MAX;
}
```

The `TASK_SIZE_MAX` macro expands to the:

```C
#define TASK_SIZE_MAX	((1UL << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)

#ifdef CONFIG_X86_5LEVEL
#define __VIRTUAL_MASK_SHIFT	(pgtable_l5_enabled() ? 56 : 47)
#else
#define __VIRTUAL_MASK_SHIFT	47
#endif
```

Pay attention on `unlikely` macro. There are two macros in the Linux kernel:

```C
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
```

You can [often](http://lxr.free-electrons.com/ident?i=unlikely) find these macros in the code of the Linux kernel. Main purpose of these macros is optimization. Sometimes this situation is that we need to check the condition of the code and we know that it will rarely be `true` or `false`. With these macros we can tell to the compiler about this. For example 

```C
static int proc_root_readdir(struct file *file, struct dir_context *ctx)
{
        if (ctx->pos < FIRST_PROCESS_ENTRY) {
                int error = proc_readdir(file, ctx);
                if (unlikely(error <= 0))
                        return error;
...
...
...
}
```

Here we can see `proc_root_readdir` function which will be called when the Linux [VFS](https://en.wikipedia.org/wiki/Virtual_file_system) needs to read the `root` directory contents. If condition marked with `unlikely`, compiler can put `false` code right after branching. Now let's back to the our address check. Comparison between the given address and the `TASK_SIZE_MAX` will give us to know, was page fault in the kernel mode or user mode. After this check we know it. After this `__do_page_fault` routine will try to understand the problem that provoked page fault exception and then will pass address to the appropriate routine. It can be `kmemcheck` fault, spurious fault, [kprobes](https://www.kernel.org/doc/Documentation/kprobes.txt) fault and etc. Will not dive into implementation details of the page fault exception handler in this part, because we need to know many different concepts which are provided by the Linux kernel, but will see it in the chapter about the [memory management](https://0xax.gitbook.io/linux-insides/summary/mm) in the Linux kernel.

Back to start_kernel
--------------------------------------------------------------------------------

There are many different function calls after the `idt_setup_early_traps` in the `setup_arch` function from different kernel subsystems, but there are no one interrupts and exceptions handling related. So, we have to go back where we came from - `start_kernel` function from the [init/main.c](https://elixir.bootlin.com/linux/v5.5/source/init/main.c#L492). The first things after the `setup_arch` is the `trap_init` function from the [arch/x86/kernel/traps.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/kernel/traps.c). This function makes initialization of the remaining exceptions handlers (remember that we already setup 3 handlers for the `#DB` - debug exception, `#BP` - breakpoint exception and `#PF` - page fault exception). 

```c
void __init trap_init(void)
{
	/* Init cpu_entry_area before IST entries are set up */
	setup_cpu_entry_areas();

	idt_setup_traps();

	/*
	 * Set the IDT descriptor to a fixed read-only location, so that the
	 * "sidt" instruction will not leak the location of the kernel, and
	 * to defend the IDT against arbitrary memory write vulnerabilities.
	 * It will be reloaded in cpu_init() */
	cea_set_pte(CPU_ENTRY_AREA_RO_IDT_VADDR, __pa_symbol(idt_table),
		    PAGE_KERNEL_RO);
	idt_descr.address = CPU_ENTRY_AREA_RO_IDT;

	/*
	 * Should be a barrier for any external CPU state:
	 */
	cpu_init();

	idt_setup_ist_traps();

	x86_init.irqs.trap_init();

	idt_setup_debugidt_traps();
}
```

The first thing that `trap_init` does is invoking `setup_cpu_entry_areas` to setup per-cpu struct `cpu_entry_area` variable for each CPU so that the IST stacks is mapped. Every field in struct `cpu_entry_area` is a **virtual alias** of some other allocated backing store.

```c
struct cpu_entry_area {
	char gdt[PAGE_SIZE];
	...
	struct entry_stack_page entry_stack_page;  // trampoline stack
	...
	struct tss_struct tss;  // TSS

#ifdef CONFIG_X86_64
	/*
	 * Exception stacks used for IST entries with guard pages.
	 */
	struct cea_exception_stacks estacks;  // IST stack for #DF, #NMI, #DB{"","1","2"},#MCE 
#endif
	/*
	 * Per CPU debug store for Intel performance monitoring. Wastes a
	 * full page at the moment.
	 */
	struct debug_store cpu_debug_store;
	/*
	 * The actual PEBS/BTS buffers must be mapped to user space
	 * Reserve enough fixmap PTEs.
	 */
	struct debug_store_buffers cpu_debug_buffers;
};
```

After this we start to fill the `Interrupt Descriptor Table` with `def_idts` array, which is an instance of `struct idt_data` and contains the default IDT entries.

```C
/*
 * The default IDT entries which are set up in trap_init() before
 * cpu_init() is invoked. Interrupt stacks cannot be used at that point and
 * the traps which use them are reinitialized with IST after cpu_init() has
 * set up TSS.
 */
static const __initconst struct idt_data def_idts[] = {
	INTG(X86_TRAP_DE,		divide_error),
	INTG(X86_TRAP_NMI,		nmi),
	INTG(X86_TRAP_BR,		bounds),
	INTG(X86_TRAP_UD,		invalid_op),
	INTG(X86_TRAP_NM,		device_not_available),
	INTG(X86_TRAP_OLD_MF,		coprocessor_segment_overrun),
	INTG(X86_TRAP_TS,		invalid_TSS),
	INTG(X86_TRAP_NP,		segment_not_present),
	INTG(X86_TRAP_SS,		stack_segment),
	INTG(X86_TRAP_GP,		general_protection),
	INTG(X86_TRAP_SPURIOUS,		spurious_interrupt_bug),
	INTG(X86_TRAP_MF,		coprocessor_error),
	INTG(X86_TRAP_AC,		alignment_check),
	INTG(X86_TRAP_XF,		simd_coprocessor_error),

#ifdef CONFIG_X86_32
	TSKG(X86_TRAP_DF,		GDT_ENTRY_DOUBLEFAULT_TSS),
#else
	INTG(X86_TRAP_DF,		double_fault),
#endif
	INTG(X86_TRAP_DB,		debug),

#ifdef CONFIG_X86_MCE
	INTG(X86_TRAP_MC,		&machine_check),
#endif

	SYSG(X86_TRAP_OF,		overflow),
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32),
#endif
};
```

Here we can see:

* `#OF` or `Overflow` exception. This exception indicates that an overflow trap occurred when an special [INTO](http://x86.renejeschke.de/html/file_module_x86_id_142.html) instruction was executed;
* `#BR` or `BOUND Range exceeded` exception. This exception indicates that a `BOUND-range-exceed` fault occurred when a [BOUND](http://pdos.csail.mit.edu/6.828/2005/readings/i386/BOUND.htm) instruction was executed;
* `#UD` or `Invalid Opcode` exception. Occurs when a processor attempted to execute invalid or reserved [opcode](https://en.wikipedia.org/?title=Opcode), processor attempted to execute instruction with invalid operand(s) and etc;
* `#NM` or `Device Not Available` exception. Occurs when the processor tries to execute `x87 FPU` floating point instruction while `EM` flag in the [control register](https://en.wikipedia.org/wiki/Control_register#CR0) `cr0` was set.

* `#DF`exception. Occurs when processor detected a second exception while calling an exception handler for a prior exception. In usual way when the processor detects another exception while trying to call an exception handler, the two exceptions can be handled serially. If the processor cannot handle them serially, it signals the double-fault or `#DF` exception.

* `#CSO` or `Coprocessor Segment Overrun` - this exception indicates that math [coprocessor](https://en.wikipedia.org/wiki/Coprocessor) of an old processor detected a page or segment violation. Modern processors do not generate this exception
* `#TS` or `Invalid TSS` exception - indicates that there was an error related to the [Task State Segment](https://en.wikipedia.org/wiki/Task_state_segment).
* `#NP` or `Segment Not Present` exception indicates that the `present flag` of a segment or gate descriptor is clear during attempt to load one of `cs`, `ds`, `es`, `fs`, or `gs` register.
* `#SS` or `Stack Fault` exception indicates one of the stack related conditions was detected, for example a not-present stack segment is detected when attempting to load the `ss` register.
* `#GP` or `General Protection` exception indicates that the processor detected one of a class of protection violations called general-protection violations. There are many different conditions that can cause general-protection exception. For example loading the `ss`, `ds`, `es`, `fs`, or `gs` register with a segment selector for a system segment, writing to a code segment or a read-only data segment, referencing an entry in the `Interrupt Descriptor Table` (following an interrupt or exception) that is not an interrupt, trap, or task gate and many many more.
* `Spurious Interrupt` - a hardware interrupt that is unwanted.
* `#MF` or `x87 FPU Floating-Point Error` exception caused when the [x87 FPU](https://en.wikipedia.org/wiki/X86_instruction_listings#x87_floating-point_instructions) has detected a floating point error.
* `#AC` or `Alignment Check` exception Indicates that the processor detected an unaligned memory operand when alignment checking was enabled.

* `#MC` or `Machine-Check` exception. It depends on the `CONFIG_X86_MCE` kernel configuration option and indicates that the processor detected an internal [machine error](https://en.wikipedia.org/wiki/Machine-check_exception) or a bus error, or that an external agent detected a bus error.
* `SIMD Floating-Point` exception. It indicates the processor has detected a SIMD floating-point exception. There are six classes of numeric exception conditions that can occur while executing an SIMD floating-point instruction:
  * Invalid operation
  * Divide-by-zero
  * Denormal operand
  * Numeric overflow
  * Numeric underflow
  * Inexact result (Precision)
* `ia32_syscall`. There is `CONFIG_IA32_EMULATION` kernel configuration option on `x86_64` Linux kernels. This option provides ability to execute 32-bit processes in compatibility-mode. In the next parts we will see how it works, in the meantime we need only to know that there is yet another interrupt gate in the `IDT` with the vector number `0x80`. 

In the next step we maps `IDT` to the fixmap area:

```C
cea_set_pte(CPU_ENTRY_AREA_RO_IDT_VADDR, __pa_symbol(idt_table),
		    PAGE_KERNEL_RO);
idt_descr.address = CPU_ENTRY_AREA_RO_IDT;
```

and write its address to the `idt_descr.address` (more about fix-mapped addresses you can read in the second part of the [Linux kernel memory management](https://0xax.gitbook.io/linux-insides/summary/mm/linux-mm-2) chapter). After this we can see the call of the `cpu_init` function that defined in the [arch/x86/kernel/cpu/common.c](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/kernel/cpu/common.c). This function makes initialization of the all `per-cpu` state. In the beginning of the `cpu_init` we do the following things: First of all we wait while master cpu is initialized and then we call `ucode_cpu_init` to print early updated microcode information.

```C
wait_for_master_cpu(cpu);

ucode_cpu_init(cpu);
```

Then the `Global Descriptor Table` and `Interrupt Descriptor table` ( i.e., `idt_descr.address`) are reloaded with the:

```C
	switch_to_new_gdt(cpu);
	load_current_idt();
```

As we have filled `Task State Segments` with the `Interrupt Stack Tables` we can set `TSS` descriptor for the current processor and load it with the:

```C
set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss);
load_TR_desc();
```

where `set_tss_desc` macro from the [arch/x86/include/asm/desc.h](https://elixir.bootlin.com/linux/v5.5/source/arch/x86/include/asm/desc.h) writes given  descriptor to the `Global Descriptor Table` of the given processor:

```C
static inline void __set_tss_desc(unsigned cpu, unsigned int entry, struct x86_hw_tss *addr)
{
	struct desc_struct *d = get_cpu_gdt_rw(cpu);
	tss_desc tss;

	set_tssldt_descriptor(&tss, (unsigned long)addr, DESC_TSS,
			      __KERNEL_TSS_LIMIT);
	write_gdt_entry(d, entry, &tss, DESC_TSS);
}

#define set_tss_desc(cpu, addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)
```

and `load_TR_desc` macro expands to the `ltr` or `Load Task Register` instruction:

```C
#define load_TR_desc()                          native_load_tr_desc()
static inline void native_load_tr_desc(void)
{
	struct desc_ptr gdt;
	int cpu = raw_smp_processor_id();
	bool restore = 0;
	struct desc_struct *fixmap_gdt;

	native_store_gdt(&gdt);
	fixmap_gdt = get_cpu_gdt_ro(cpu);

	/*
	 * If the current GDT is the read-only fixmap, swap to the original
	 * writeable version. Swap back at the end.
	 */
	if (gdt.address == (unsigned long)fixmap_gdt) {
		load_direct_gdt(cpu);
		restore = 1;
	}
	asm volatile("ltr %w0"::"q" (GDT_ENTRY_TSS*8));
	if (restore)
		load_fixmap_gdt(cpu);
}
```

Now, Let's come back to `trap_init` function, the `idt_setup_ist_traps` is invoked to setup IST stacks for some exceptions with `ist_idts` array since TSS has been initialized in `cpu_init`.

```C
static const __initconst struct idt_data ist_idts[] = {
	ISTG(X86_TRAP_DB,	debug,		IST_INDEX_DB),
	ISTG(X86_TRAP_NMI,	nmi,		IST_INDEX_NMI),
	ISTG(X86_TRAP_DF,	double_fault,	IST_INDEX_DF),
#ifdef CONFIG_X86_MCE
	ISTG(X86_TRAP_MC,	&machine_check,	IST_INDEX_MCE),
#endif
};
```

Finally interrupt init code is called and initialize `debug_idt_table` with `idt_table` but set the entry for debug exception to the value of `dbg_idts`.

 **ICE: TODO**

```
x86_init.irqs.trap_init();
```

That's all. Soon we will consider all handlers of these interrupts/exceptions.

Conclusion
--------------------------------------------------------------------------------

It is the end of the fourth part about interrupts and interrupt handling in the Linux kernel. We saw the initialization of the [Task State Segment](https://en.wikipedia.org/wiki/Task_state_segment) in this part and initialization of the different interrupt handlers as `Divide Error`, `Page Fault` exception and etc. You can note that we saw just initialization stuff, and will dive into details about handlers for these exceptions. In the next part we will start to do it.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

Links
--------------------------------------------------------------------------------

* [page fault](https://en.wikipedia.org/wiki/Page_fault)
* [Interrupt Descriptor Table](https://en.wikipedia.org/wiki/Interrupt_descriptor_table)
* [Tracing](https://en.wikipedia.org/wiki/Tracing_%28software%29)
* [cr2](https://en.wikipedia.org/wiki/Control_register)
* [RCU](https://en.wikipedia.org/wiki/Read-copy-update)
* [this_cpu_* operations](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/Documentation/this_cpu_ops.txt)
* [kmemcheck](https://www.kernel.org/doc/Documentation/kmemcheck.txt)
* [prefetchw](http://www.felixcloutier.com/x86/PREFETCHW.html)
* [3DNow](https://en.wikipedia.org/?title=3DNow!)
* [CPU caches](https://en.wikipedia.org/wiki/CPU_cache)
* [VFS](https://en.wikipedia.org/wiki/Virtual_file_system) 
* [Linux kernel memory management](https://0xax.gitbook.io/linux-insides/summary/mm)
* [Fix-Mapped Addresses and ioremap](https://0xax.gitbook.io/linux-insides/summary/mm/linux-mm-2)
* [Extended Industry Standard Architecture](https://en.wikipedia.org/wiki/Extended_Industry_Standard_Architecture)
* [INT isntruction](https://en.wikipedia.org/wiki/INT_%28x86_instruction%29)
* [INTO](http://x86.renejeschke.de/html/file_module_x86_id_142.html)
* [BOUND](http://pdos.csail.mit.edu/6.828/2005/readings/i386/BOUND.htm)
* [opcode](https://en.wikipedia.org/?title=Opcode)
* [control register](https://en.wikipedia.org/wiki/Control_register#CR0)
* [x87 FPU](https://en.wikipedia.org/wiki/X86_instruction_listings#x87_floating-point_instructions)
* [MCE exception](https://en.wikipedia.org/wiki/Machine-check_exception)
* [SIMD](https://en.wikipedia.org/?title=SIMD)
* [cpumasks and bitmaps](https://0xax.gitbook.io/linux-insides/summary/concepts/linux-cpu-2)
* [NX](https://en.wikipedia.org/wiki/NX_bit)
* [Task State Segment](https://en.wikipedia.org/wiki/Task_state_segment)
* [Previous part](https://0xax.gitbook.io/linux-insides/summary/interrupts/linux-interrupts-3)
