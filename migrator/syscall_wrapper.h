#ifndef SYSCALL_WRAPPER_H
#define SYSCALL_WRAPPER_H

#include <sys/syscall.h>
#ifndef SYS_mmap
#define SYS_mmap SYS_mmap2
#endif

// System call wrapper function
static inline unsigned long __attribute__((always_inline)) syscall_wrapper6(unsigned long number, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6) {
    long result;

    #if defined(__x86_64__)
    // x86-64: System call using "syscall" instruction
    __asm__ (
        "mov %5, %%r10\n"
        "mov %6, %%r8\n"
        "mov %7, %%r9\n"
        "syscall\n"
        : "=a" (result)                     // Output: result in RAX
        : "a" (number),                     // Input: syscall number in RAX
          "D" (arg1),                       // arg1 in RDI
          "S" (arg2),                       // arg2 in RSI
          "d" (arg3),                       // arg3 in RDX
          "r" (arg4), "r" (arg5), "r" (arg6) // args in R10, R8, R9
        : "rcx", "r8", "r9", "r10", "r11", "memory"            // Clobbered registers
    );

    #elif defined(__aarch64__)
    // ARMv8 (AArch64): System call using "svc #0"
    register long x8 __asm__("x8") = number; // syscall number in x8
    register long x0 __asm__("x0") = arg1;  // arg1 in x0
    register long x1 __asm__("x1") = arg2;  // arg2 in x1
    register long x2 __asm__("x2") = arg3;  // arg3 in x2
    register long x3 __asm__("x3") = arg4;  // arg4 in x3
    register long x4 __asm__("x4") = arg5;  // arg5 in x4
    register long x5 __asm__("x5") = arg6;  // arg6 in x5

    __asm__ __volatile__(
        "svc #0"
        : "=r" (x0)                         // Output: result in x0
        : "r" (x8), "r" (x0), "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5) // Inputs
        : "memory"                          // Clobbered memory
    );
    result = x0;

    #elif defined(__arm__)
    // ARMv7: System call using "swi 0"
    register long r7 __asm__("r7") = number; // syscall number in r7
    register long r0 __asm__("r0") = arg1;  // arg1 in r0
    register long r1 __asm__("r1") = arg2;  // arg2 in r1
    register long r2 __asm__("r2") = arg3;  // arg3 in r2
    register long r3 __asm__("r3") = arg4;  // arg4 in r3
    register long r4 __asm__("r4") = arg5;  // arg5 in r4
    register long r5 __asm__("r5") = arg6;  // arg6 in r5

    __asm__ __volatile__(
        "swi #0"
        : "=r" (r0)                         // Output: result in r0
        : "r" (r7), "r" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r4), "r" (r5) // Inputs
        : "memory"                          // Clobbered memory
    );
    result = r0;

    #elif defined(__riscv)
    // RISC-V: System call using "ecall"
    register long a7 __asm__("a7") = number; // syscall number in a7
    register long a0 __asm__("a0") = arg1;  // arg1 in a0
    register long a1 __asm__("a1") = arg2;  // arg2 in a1
    register long a2 __asm__("a2") = arg3;  // arg3 in a2
    register long a3 __asm__("a3") = arg4;  // arg4 in a3
    register long a4 __asm__("a4") = arg5;  // arg5 in a4
    register long a5 __asm__("a5") = arg6;  // arg6 in a5

    __asm__ __volatile__(
        "ecall"
        : "=r" (a0)                         // Output: result in a0
        : "r" (a7), "r" (a0), "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5) // Inputs
        : "memory"                          // Clobbered memory
    );
    result = a0;

    #else
    #error "Unsupported architecture"
    #endif

    return result;
}
static inline unsigned long __attribute__((always_inline)) syscall_wrapper5(unsigned long number, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    return syscall_wrapper6(number, arg1, arg2, arg3, arg4, arg5, 0);
}
static inline unsigned long __attribute__((always_inline)) syscall_wrapper4(unsigned long number, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4) {
    return syscall_wrapper5(number, arg1, arg2, arg3, arg4, 0);
}
static inline unsigned long __attribute__((always_inline)) syscall_wrapper3(unsigned long number, unsigned long arg1, unsigned long arg2, unsigned long arg3) {
    return syscall_wrapper4(number, arg1, arg2, arg3, 0);
}
static inline unsigned long __attribute__((always_inline)) syscall_wrapper2(unsigned long number, unsigned long arg1, unsigned long arg2) {
    return syscall_wrapper3(number, arg1, arg2, 0);
}
static inline unsigned long __attribute__((always_inline)) syscall_wrapper1(unsigned long number, unsigned long arg1) {
    return syscall_wrapper2(number, arg1, 0);
}
static inline unsigned long __attribute__((always_inline)) syscall_wrapper0(unsigned long number) {
    return syscall_wrapper1(number, 0);
}

#endif //SYSCALL_WRAPPER_H
