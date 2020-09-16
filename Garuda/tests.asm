.code

__test_func_1 proc

	xor rax, rax
	mov rcx, 10

loop_:

	mov rdx, 1
	shl rdx, 2
	shr rdx, 1
	sub rcx, rdx
	test rcx, rax
	jne loop_

	mov rax, 1000h
	mov rcx, 2000h
	add rax, rcx
	sub rcx, -100h
	add rax, -100h
	xor rax, rcx

	cmp rax, rcx
	jge label_0

	rol rax, 7Fh

label_0:

	ror rax, -7Fh
	mov rcx, 1234h
	mov r8, -1h
	mul r8

	cmp rdx, rcx
	jle label_0

	xor rax, rax
	
label_1:

	mov rax, 123456789ABCFEFh

	xor rdi, rdi
	add rdi, 50h

	lea rax, [rax + rdi * 2 - 9999h]
	mov rax, [rax + rdx]

	ret

__test_func_1 endp

end