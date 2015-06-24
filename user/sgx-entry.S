/**
 * Architecture dependent entry points. 
 *
 * Derived from entry.S in the Sandia Kitten microkernel 
 * (http://github.com/ktpedre/kitten) As such, it is available 
 * under Linus Torvald's Linux kernel license, a variant of the GNU 
 * GPL v2.
 *
 * Modifications for usage for enclave entry by: 
 *     2015, Patrick Bridges <patrickb314@gmail.com> for Two Sigma, Inc.
 */

#include <asm-linkage.h>

/* XXX - PGB
 * We need include files in OpenSGX to get the appropriate constants
 * from  -for now we just define them by hand.
 */ 
#define PAGE_SHIFT              12
#define PAGE_SIZE               (1 << PAGE_SHIFT)

#define SSA_FRAME_PAGES		1
#define SSA_FRAME_SHIFT		(PAGE_SHIFT + (SSA_FRAME_PAGES - 1))
#define SSA_FRAME_MASK		(~((1 << SSA_FRAME_SHIFT) - 1))
/**
 * Entry point for enclave calls.
 *
 * Upon entry we are still running with the user-level stack and the
 * x86_64 CPU control unit has stashed the user-level RIP in
 *
 * The first thing this function does is generate a partial stack frame
 * containing all caller-saved registers. The handler function
 * is responsible for saving all callee-saved registers. If it is a C
 * function, callee-saved registers are saved automatically by the compiler.
 *
 * Immediately before calling encalve main function, the enclave stack
 * looks like the following.  All fields represent the saved state of the
 * calling user-level task:
 *
 *            UNDEF      = Undefined, normally holds user-space SS
 *            UNDEF      = Undefined, normally holds user-space RSP
 *            UNDEF      = Undefined, normally holds user-space RFLAGS
 *            UNDEF      = Undefined, normally holds user-space CS
 *            RIP        = user-space RIP
 *            (junk)     = normally RAX, but RAX clobbered by EENTER
 *            RDI        = ARG0, passed from user-space
 *            RSI        = ARG1, passed from user-space
 *            RDX        = ARG2, passed from user-space
 *            (junk)     = normally RCX, but RCX is clobbered by EENTER
 *            RAX        = system call number, passed from user-space
 *            R8         = ARG4, passed from user-space
 *            R9         = ARG5, passed from user-space
 *            R10        = ARG3, passed from user-space
 *     RSP -> R11        = user-space RFLAGS
 *
 * And the registers are setup as follows:
 *
 *            RDI        = ARG0
 *            RSI        = ARG1
 *            RDX        = ARG2
 *            RCX        = ARG3 (was stored on R10 on entry)
 *            R8         = ARG4
 *            R9         = ARG5
 *
 * NOTE: RCX, RBX, and RAX are clobbered by system calls. This is due to 
 *       the ENCLS using EAX to store EENTER, RBX to store the TCS address,
 *       and RCX to store the AEP before transfering control to the kernel. 
 *       User-level will observe different values of RAX, RBX, and RCX after 
 *       EENTER than before.
 * 
 * C Prototype:
 *       int enclave_start(void);
 */
.section .enc_text
ENTRY(enclave_start)
	/*
	 * Enter from user-space - entry RSP/RBP are saved in the SSA by EENTER
	 * Just need to switch to a trusted stack, building up %rsp given the 
	 * info we have. The real trick is to locate the SAA for the TCS;
	 * right now we do that with extra information from the linker, 
	 * assuming that the SSA starts right after ENCD_END - that'll 
	 * only work if we have one TCS and will break once we can have multiple
	 * TCSes in an enclave. Ideally, we should move the SSA for each TCS 
	 * after that TCS, so we can find it using only the address for the 
	 * TCS and CSSA, which is stored in %RBX.
	 */
	lea ENCD_END(%rip), %rsp
	shlq $SSA_FRAME_SHIFT, %rax		/* Get to current SSA */
	addq %rax, %rsp	 
	addq $(PAGE_SIZE), %rsp			/* Stack at end of curr ssa */
						/* so %rsp point to next one */

	/*
	 * Save registers to trusted stack
	 */
	subq $15*8, %rsp		/* Make room on the stack            */
	movq %rcx, 10*8(%rsp)		/* Save user-space RIP               */
					/* RAX contains EENTER leaf 	     */
	movq %rdi,  8*8(%rsp)		/* Save user-space RDI (ARG0)        */
	movq %rsi,  7*8(%rsp)		/* Save user-space RSI (ARG1)        */
	movq %rdx,  6*8(%rsp)		/* Save user-space RDX (ARG2)        */
					/* RCX is clobbered		     */
					/* Save user-space RAX (syscall #)   */
	movq %r8,   3*8(%rsp)		/* Save user-space R8  (ARG4)        */
	movq %r9,   2*8(%rsp)		/* Save user-space R9  (ARG5)        */
	movq %r10,  1*8(%rsp)		/* Save user-space R10 (ARG3)        */
	movq %r11,     (%rsp)		/* Save user-space RFLAGS            */

	/*
	 * Call the enclave call handler
	 */
	movq %r10, %rcx			/* Per x86_64 C ABI, RCX holds ARG3  */
	call enclave_main		/* Call the main enclave entry point */

	/*
	 * Return to user-space
	 */
	movq     (%rsp), %r11		/* Restore RFLAGS for SYSRET         */
	movq  1*8(%rsp), %r10		/* Restore user-space R10 (ARG3)     */
	movq  2*8(%rsp), %r9		/* Restore user-space R9  (ARG5)     */
	movq  3*8(%rsp), %r8		/* Restore user-space R8  (ARG4)     */
					/* RAX will contain EEXIT on exit    */
					/* RCX will contain TCS.AEP on exit  */
	movq  6*8(%rsp), %rdx		/* Restore user-space RDX (ARG2)     */
	movq  7*8(%rsp), %rsi		/* Restore user-space RSI (ARG1)     */
	movq  8*8(%rsp), %rdi		/* Restore user-space RDI (ARG0)     */

	movl  $0x04, %eax		/* EEXIT 			     */
	movq  $0x0, %rbx		/* Should be 10*8(%rsp), but we're   */
				        /* using the OpenSGX eexit semantics */
  	.byte 0x0F			/* ENCLU			     */
        .byte 0x01
        .byte 0xd7
	retq
END(enclave_start)
