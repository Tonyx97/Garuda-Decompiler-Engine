#pragma once

#ifndef ASSEMBLY_H
#define ASSEMBLY_H

namespace garuda
{
	enum eReturnFlag : uint32_t
	{
		RETURN_ON_REACH_SPECIFIED_END	= (1 << 0),
		RETURN_ON_SRC_TO_RSP			= (1 << 1),
		RETURN_ON_DST_REG_MATCH			= (1 << 2),
		RETURN_ON_LAST_INSTRUCTION		= (1 << 3),
	};

	enum eGenericFlag : uint32_t
	{
		FLAG_NONE						= (1 << 0),
		FLAG_IGNORE_LAST_INSTRUCTION	= (1 << 1),
		FLAG_IGNORE_REG_IN_DST			= (1 << 2),
		FLAG_IGNORE_REG_IN_SRC			= (1 << 3),
	};

	struct variable_info
	{
		std::string name,
					reg_name;

		x86_reg reg,
				reg_category;

		int index,
			dereferences;
	};

	struct map_to_set_variable_order
	{
		template <typename T>
		bool operator()(const T& l, const T& r) const { return l.second->index < r.second->index; }
	};

	struct operand_base_info
	{
		variable_info* variable;
		
		x86_op_type type;

		uint8_t size,
				access;
	};

	struct operand_reg : public operand_base_info
	{
		std::string reg_name;

		x86_reg reg,
				reg_category;
	};

	struct operand_imm : public operand_base_info
	{
		int64_t imm;
	};

	struct operand_mem : public operand_base_info
	{
		x86_reg base,
				index,
				segment;
		
		int64_t disp,
				scale,
				accessed_imm;
	};

	struct instruction_info
	{
		std::vector<operand_base_info*> operands;

		std::string mnemonic,
					op_str;

		uint64_t jmp,
				 offset;

		size_t size;

		uint32_t id;

		~instruction_info()
		{
			for (auto&& op : operands)
				delete op;
		}

		bool is_reg_in_any_operand(x86_reg reg)
		{
			for (auto&& op : operands)
				if (op->variable && op->variable->reg == reg)
					return true;
			return false;
		}
	};
	
	struct branch_info
	{
		std::string label_name;
		
		variable_info* v0 = nullptr,
					 * v1 = nullptr;

		instruction_info* cmp = nullptr,
						* jmp = nullptr,
						* target = nullptr;

		bool created = false;

		bool is_instruction_jmp(instruction_info* ins_info) const		{ return (ins_info == jmp); }
		bool is_instruction_target(instruction_info* ins_info) const	{ return (ins_info == target); }
	};

	struct parse_info
	{
		x86_reg dst_reg_return = X86_REG_INVALID,
				src_reg_return = X86_REG_INVALID,
				dst_ignore = X86_REG_INVALID,
				src_ignore = X86_REG_INVALID;

		x86_insn start_instruction = X86_INS_INVALID,
				 end_instruction = X86_INS_INVALID;

		uint32_t flags = FLAG_NONE,
				 return_flags = RETURN_ON_REACH_SPECIFIED_END;
	};
};

#endif