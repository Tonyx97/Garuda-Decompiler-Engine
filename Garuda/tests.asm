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

	ret

__test_func_1 endp

end