# Garuda Decompiler Engine
 
This is a simple tool to translate machine code into pseudo-code.

This is just a testing version, it certainly works for most common assembly code which contains basic operations such as *mov*, *lea*, arithmetic and logical operations etc. There are a lot of things to improve and implement. This project is designed to decompile parts of functions in memory where there is some encryption going on. For instance, it doesn't take into account operations where the destination is in the stack. There are a lot of instruction callbacks to implement but the ones currently implemented are the common ones to encrypt/decrypt basic data/memory at run-time.

This project uses [Capstone disassembly/disassembler framework](https://github.com/aquynh/capstone).

An example:

```asm
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
```

When this asm gets analyzed by Garuda it outputs the following:

```c++
#pragma once

#ifndef GARUDA_OUT_H
#define GARUDA_OUT_H

// File auto generated by GARUDA engine (developed by Tonyx97)

#include <intrin.h>

#define LOBYTE(x)       (*((BYTE*)&(x)))
#define LOWORD(x)       (*((WORD*)&(x)))
#define LODWORD(x)      (*((DWORD*)&(x)))
#define HIBYTE(x)       (*((BYTE*)&(x)+1))
#define HIWORD(x)       (*((WORD*)&(x)+1))
#define HIDWORD(x)      (*((DWORD*)&(x)+1))

template <typename T, typename B>
T rpm(const B& ptr)
{
        return *(T*)ptr;
}

// test 1
//
template <typename T>
unsigned __int64 __test_func_1(const T& data)
{
        unsigned __int64 v0, v1, v2, v3, v4;

        v0 = 0;                                           // xor        rax, rax
        v1 = 0xA;                                         // mov        rcx, 0xa

label_0:
        v2 = 0x1;                                         // mov        rdx, 1
        v2 <<= 0x2;                                       // shl        rdx, 2
        v2 >>= 0x1;                                       // shr        rdx, 1
        v1 -= v2;                                         // sub        rcx, rdx
        if (v0 != v1) goto label_0;
        v0 = 0x1000;                                      // mov        rax, 0x1000
        v1 = 0x2000;                                      // mov        rcx, 0x2000
        v0 += v1;                                         // add        rax, rcx
        v1 += 0x100;                                      // sub        rcx, -0x100
        v0 -= 0x100;                                      // add        rax, -0x100
        v0 ^= v1;                                         // xor        rax, rcx
        if (v0 >= v1) goto label_1;
        v0 = _rotl64(v0, 0x7F);                           // rol        rax, 0x7f

label_1:
        v0 = _rotr64(v0, 0x81);                           // ror        rax, 0x81
        v1 = 0x1234;                                      // mov        rcx, 0x1234
        v3 = -0x1;                                        // mov        r8, -1
        v0 = _umul128(v0, v3, &v2);                       // mul        r8
        if (v2 <= v1) goto label_1;
        v0 = 0;                                           // xor        rax, rax
        v0 = 0x123456789ABCFEF;                           // movabs     rax, 0x123456789abcfef
        v4 = 0;                                           // xor        rdi, rdi
        v4 += 0x50;                                       // add        rdi, 0x50
        v0 = v0 + v4 * 0x2 - 0x9999;                      // lea        rax, [rax + rdi*2 - 0x9999]
        v0 = rpm<unsigned __int64>(v0 + v2);              // mov        rax, qword ptr [rax + rdx]

        return v0;
}

#endif
```
