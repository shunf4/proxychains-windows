	.file	"remote_function.c"
	.text
	.data
	.align 8
newlib_vswprintf:
	.quad	vswprintf
	.align 8
newlib_swprintf:
	.quad	swprintf
	.section .rdata,"dr"
	.align 32
g_szChildDataSavingFileMappingPrefix:
	.ascii "L\0o\0c\0a\0l\0\\\0p\0r\0o\0x\0y\0c\0h\0a\0i\0n\0s\0_\0c\0h\0i\0l\0d\0_\0d\0a\0t\0a\0_\0\0\0"
	.align 32
g_szHookDllFileName:
	.ascii "c\0y\0g\0p\0r\0o\0x\0y\0c\0h\0a\0i\0n\0s\0_\0h\0o\0o\0k\0_\0x\0"
	.ascii "6\0"
	.ascii "4\0.\0d\0l\0l\0\0\0"
	.align 32
g_szHookDllFileNameX64:
	.ascii "c\0y\0g\0p\0r\0o\0x\0y\0c\0h\0a\0i\0n\0s\0_\0h\0o\0o\0k\0_\0x\0"
	.ascii "6\0"
	.ascii "4\0.\0d\0l\0l\0\0\0"
	.align 32
g_szHookDllFileNameX86:
	.ascii "c\0y\0g\0p\0r\0o\0x\0y\0c\0h\0a\0i\0n\0s\0_\0h\0o\0o\0k\0_\0x\0"
	.ascii "8\0"
	.ascii "6\0.\0d\0l\0l\0\0\0"
	.align 32
g_szMinHookDllFileNameX64:
	.ascii "M\0i\0n\0H\0o\0o\0k\0.\0x\0"
	.ascii "6\0"
	.ascii "4\0.\0d\0l\0l\0\0\0"
	.align 32
g_szMinHookDllFileNameX86:
	.ascii "M\0i\0n\0H\0o\0o\0k\0.\0x\0"
	.ascii "8\0"
	.ascii "6\0.\0d\0l\0l\0\0\0"
	.align 32
g_szMinHookDllFileName:
	.ascii "M\0i\0n\0H\0o\0o\0k\0.\0x\0"
	.ascii "6\0"
	.ascii "4\0.\0d\0l\0l\0\0\0"
	.text
	.globl	LoadHookDll
	.def	LoadHookDll;	.scl	2;	.type	32;	.endef
	.seh_proc	LoadHookDll
LoadHookDll:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	subq	$80, %rsp
	.seh_stackalloc	80
	.seh_endprologue
	movq	%rcx, 16(%rbp)
/APP
 # 29 "../src/remote_function.c" 1
	sub $0x8000, %rbp
	sub $0x8000, %rsp
	
 # 0 "" 2
/NO_APP
	movq	16(%rbp), %rax
	movq	%rax, -8(%rbp)
/APP
 # 43 "../src/remote_function.c" 1
	mov %rcx, %rax
 # 0 "" 2
/NO_APP
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	$1, 4(%rax)
	movq	-8(%rbp), %rax
	movl	$1114, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9208(%rax), %rax
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	addq	$288, %rax
	movq	%rax, %rcx
	call	*%rdx
	movq	%rax, -16(%rbp)
	cmpq	$0, -16(%rbp)
	jne	.L2
	movq	-8(%rbp), %rax
	movq	9232(%rax), %rax
	call	*%rax
	movl	%eax, %edx
	movq	-8(%rbp), %rax
	movl	%edx, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9272(%rax), %rax
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	movl	736(%rax), %eax
	movl	%eax, %ecx
	call	*%rdx
	movl	$-1, %eax
	jmp	.L3
.L2:
	movq	-8(%rbp), %rax
	movl	12(%rax), %eax
	cmpl	$1, %eax
	jbe	.L4
	movq	-8(%rbp), %rax
	movq	9272(%rax), %rax
	movl	$0, %ecx
	call	*%rax
	movl	$-2, %eax
	jmp	.L3
.L4:
	movq	-8(%rbp), %rax
	movl	$127, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9216(%rax), %rax
	movq	%rax, %r8
	movq	-8(%rbp), %rax
	leaq	544(%rax), %rdx
	movq	-16(%rbp), %rax
	movq	%rax, %rcx
	call	*%r8
	movq	%rax, -24(%rbp)
	movq	-8(%rbp), %rax
	movl	$1114, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9208(%rax), %rax
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	addq	$3056, %rax
	movq	%rax, %rcx
	call	*%rdx
	movq	%rax, -32(%rbp)
	cmpq	$0, -32(%rbp)
	jne	.L5
	movq	-8(%rbp), %rax
	movq	9232(%rax), %rax
	call	*%rax
	movl	%eax, %edx
	movq	-8(%rbp), %rax
	movl	%edx, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9272(%rax), %rax
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	movl	736(%rax), %eax
	movl	%eax, %ecx
	call	*%rdx
	movl	$-1, %eax
	jmp	.L3
.L5:
	movq	-8(%rbp), %rax
	movl	$127, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9216(%rax), %rax
	movq	%rax, %r8
	movq	-8(%rbp), %rax
	leaq	80(%rax), %rdx
	movq	-32(%rbp), %rax
	movq	%rax, %rcx
	call	*%r8
	movq	%rax, -40(%rbp)
	cmpq	$0, -40(%rbp)
	je	.L13
	movq	-40(%rbp), %rax
	movl	$1, (%rax)
	movq	-8(%rbp), %rax
	movl	$127, 736(%rax)
	movq	-8(%rbp), %rax
	movq	9216(%rax), %rax
	movq	%rax, %r8
	movq	-8(%rbp), %rax
	leaq	16(%rax), %rdx
	movq	-32(%rbp), %rax
	movq	%rax, %rcx
	call	*%r8
	movq	%rax, -48(%rbp)
	cmpq	$0, -48(%rbp)
	je	.L14
	movq	-8(%rbp), %rax
	movl	$1627, 736(%rax)
	movq	-8(%rbp), %rdx
	movq	-48(%rbp), %rax
	movq	%rdx, %rcx
	call	*%rax
	movl	%eax, %edx
	movq	-8(%rbp), %rax
	movl	%edx, 736(%rax)
	movq	-8(%rbp), %rax
	movl	736(%rax), %eax
	testl	%eax, %eax
	jne	.L15
	movq	-8(%rbp), %rax
	movl	$0, 736(%rax)
	movq	-40(%rbp), %rax
	movl	$0, (%rax)
	movq	-8(%rbp), %rax
	movq	9272(%rax), %rax
	movl	$0, %ecx
	call	*%rax
	movl	$-1, %eax
	jmp	.L3
.L15:
	nop
.L10:
	jmp	.L11
.L13:
	nop
	jmp	.L7
.L14:
	nop
.L7:
	movq	-8(%rbp), %rax
	movq	9232(%rax), %rax
	call	*%rax
	movl	%eax, %edx
	movq	-8(%rbp), %rax
	movl	%edx, 736(%rax)
	nop
.L11:
	movq	-8(%rbp), %rax
	movq	9224(%rax), %rax
	movq	%rax, %rdx
	movq	-32(%rbp), %rax
	movq	%rax, %rcx
	call	*%rdx
	movq	-8(%rbp), %rax
	movq	9272(%rax), %rax
	movq	%rax, %rdx
	movq	-8(%rbp), %rax
	movl	736(%rax), %eax
	movl	%eax, %ecx
	call	*%rdx
	movl	$-1, %eax
.L3:
	addq	$80, %rsp
	popq	%rbp
	ret
	.seh_endproc
	.globl	LoadHookDll_End
	.def	LoadHookDll_End;	.scl	2;	.type	32;	.endef
	.seh_proc	LoadHookDll_End
LoadHookDll_End:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	.seh_endprologue
	leaq	LoadHookDll(%rip), %rax
	popq	%rbp
	ret
	.seh_endproc
	.ident	"GCC: (GNU) 7.4.0"
	.def	vswprintf;	.scl	2;	.type	32;	.endef
	.def	swprintf;	.scl	2;	.type	32;	.endef
