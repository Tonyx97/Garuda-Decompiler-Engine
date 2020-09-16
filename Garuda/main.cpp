#include "mem.h"
#include "garuda.h"

#include "tests.h"

extern "C" __declspec(dllexport) void __test_func_1();

int main()
{
#if TEST == 0
	garuda::global_info gi {};

	auto& parsing_info = gi.get_parse_info();

	gi.begin();

	gi.add_rpm_function("*(T*)ptr");

	gi.add_next_fn_comment("test 1");

	gi.parse_fn<uint64_t, X86_INS_INVALID, X86_INS_RET>("__test_func_1", 0, (uint64_t)__test_func_1, 0x100, garuda::FLAG_NONE, garuda::RETURN_ON_LAST_INSTRUCTION);

	gi.end();

	gi.print(true);
#else
	execute_tests();
#endif

	return std::cin.get();
}