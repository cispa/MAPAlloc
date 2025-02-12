#ifndef SET_KERNEL_ARGUMENTS_H
#define SET_KERNEL_ARGUMENTS_H
#include <asm/ptrace.h>

static inline void regs_set_kernel_argument(struct pt_regs *regs, __UINTPTR_TYPE__ n, __UINTPTR_TYPE__ v){
    static const unsigned int argument_offs[] = {
    #ifdef __i386__
		offsetof(struct pt_regs, ax),
		offsetof(struct pt_regs, dx),
		offsetof(struct pt_regs, cx),
    #elif defined(__x86_64__)
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, dx),
		offsetof(struct pt_regs, cx),
		offsetof(struct pt_regs, r8),
		offsetof(struct pt_regs, r9),
    #elif defined(__riscv)
        offsetof(struct pt_regs, a0),
		offsetof(struct pt_regs, a1),
		offsetof(struct pt_regs, a2),
		offsetof(struct pt_regs, a3),
		offsetof(struct pt_regs, a4),
		offsetof(struct pt_regs, a5),
		offsetof(struct pt_regs, a6),
		offsetof(struct pt_regs, a7),
    #elif defined(__aarch64__)
        offsetof(struct pt_regs, regs) + 0 * sizeof(*regs),
		offsetof(struct pt_regs, regs) + 1 * sizeof(*regs),
        offsetof(struct pt_regs, regs) + 2 * sizeof(*regs),
        offsetof(struct pt_regs, regs) + 3 * sizeof(*regs),
        offsetof(struct pt_regs, regs) + 4 * sizeof(*regs),
        offsetof(struct pt_regs, regs) + 5 * sizeof(*regs),
        offsetof(struct pt_regs, regs) + 6 * sizeof(*regs),
        offsetof(struct pt_regs, regs) + 7 * sizeof(*regs),
    #elif defined(__arm__)
        offsetof(struct pt_regs, uregs) + 0 * sizeof(*uregs),
		offsetof(struct pt_regs, uregs) + 1 * sizeof(*uregs),
        offsetof(struct pt_regs, uregs) + 2 * sizeof(*uregs),
        offsetof(struct pt_regs, uregs) + 3 * sizeof(*uregs),
    #else
    #error "Unsupported architecture"
    #endif
    };

    if (n >= (sizeof(argument_offs) / sizeof(*argument_offs)))
        return;
    
    *(__UINTPTR_TYPE__ *) ((unsigned char*)regs + argument_offs[n]) = v;
}



#endif

