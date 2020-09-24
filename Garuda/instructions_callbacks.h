#pragma once

#include "garuda.h"
#include "utils.h"

namespace garuda
{
	/**
	* Information that is used by each callback to create the pseudo-code
	*/
	struct instruction_dispatch_data
	{
		global_info* gi;

		function_info* fi;

		instruction_info* ii;

		operand_base_info* op1,
						 * op2,
						 * op3;

		size_t op_count;

		uint64_t module_base,
				 ip;
	};

	static inline std::string _X86_INS_ADD(instruction_dispatch_data* idd)
	{
		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)		return idd->op1->variable->name + " += " + idd->op2->variable->name;
			else if (idd->op2->type == X86_OP_MEM)	return idd->op1->variable->name + " += data";
			else if (idd->op2->type == X86_OP_IMM)
			{
				auto imm = static_cast<operand_imm*>(idd->op2)->imm;

				std::string real_operation;

				if (imm < 0)
				{
					real_operation = " -";
					imm *= -1;
				}
				else if (imm > 0)
					real_operation = " +";

				return idd->op1->variable->name + real_operation + "= 0x" + utils::to_hex(imm);
			}
		}

		return "TODO";
	}

	static inline std::string _X86_INS_SUB(instruction_dispatch_data* idd)
	{
		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)		return idd->op1->variable->name + " -= " + idd->op2->variable->name;
			else if (idd->op2->type == X86_OP_MEM)	return idd->op1->variable->name + " -= data";
			else if (idd->op2->type == X86_OP_IMM)
			{
				auto imm = static_cast<operand_imm*>(idd->op2)->imm;

				std::string real_operation;

				if (imm < 0)
				{
					real_operation = " +";
					imm *= -1;
				}
				else if (imm > 0)
					real_operation = " -";

				return idd->op1->variable->name + real_operation + "= 0x" + utils::to_hex(imm);
			}
		}

		return "TODO";
	}

	static inline std::string _X86_INS_IMUL(instruction_dispatch_data* idd)
	{
		if (idd->op2)
		{
			if (idd->op2->type == X86_OP_REG)
			{
				if (idd->op3)
				{
					if (idd->op3->type == X86_OP_REG)		return idd->op1->variable->name + " = " + idd->op2->variable->name + " * " + idd->op3->variable->name;
					else if (idd->op3->type == X86_OP_IMM)	return idd->op1->variable->name + " = " + idd->op2->variable->name + " * 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op3)->imm);
				}
				else
				{
					if (idd->op3->type == X86_OP_REG)		return idd->op1->variable->name + " *= " + idd->op3->variable->name;
					else if (idd->op3->type == X86_OP_IMM)	return idd->op1->variable->name + " *= 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op3)->imm);
				}
			}
		}
		return "TODO";
	}

	static inline std::string _X86_INS_MUL(instruction_dispatch_data* idd)
	{
		if (idd->op1->type == X86_OP_REG)
		{
			auto rax_variable_name = idd->fi->get_variable_name_from_reg(X86_REG_RAX),
				 rdx_variable_name = idd->fi->get_variable_name_from_reg(X86_REG_RDX);

			return rax_variable_name.value() + " = _umul128(" + rax_variable_name.value() + ", " + idd->op1->variable->name + ", &" + rdx_variable_name.value() + ")";
		}
		return "TODO";
	}

	static inline std::string _X86_INS_AND(instruction_dispatch_data* idd)
	{
		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)		return idd->op1->variable->name + " &= " + idd->op2->variable->name;
			else if (idd->op2->type == X86_OP_IMM)	return idd->op1->variable->name + " &= 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op2)->imm);
		}
		return "TODO";
	}

	static inline std::string _X86_INS_XOR(instruction_dispatch_data* idd)
	{
		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)
			{
				if (idd->op1->variable->reg == idd->op2->variable->reg)
					return idd->op1->variable->name + " = 0";
				return idd->op1->variable->name + " ^= " + idd->op2->variable->name;
			}
			if (idd->op2->type == X86_OP_MEM) return idd->op1->variable->name + " ^= data";
			if (idd->op2->type == X86_OP_IMM) return idd->op1->variable->name + " ^= " + utils::to_hex(static_cast<operand_imm*>(idd->op2)->imm);
		}
		return "TODO";
	}

	static inline std::string _X86_INS_SHL(instruction_dispatch_data* idd)
	{
		if (idd->op2->type == X86_OP_IMM) return idd->op1->variable->name + " <<= 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op2)->imm);
		return "TODO";
	}

	static inline std::string _X86_INS_SHR(instruction_dispatch_data* idd)
	{
		if (idd->op2->type == X86_OP_IMM) return idd->op1->variable->name + " >>= 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op2)->imm);
		return "TODO";
	}

	static inline std::string _X86_INS_ROL(instruction_dispatch_data* idd)
	{
		const auto op1_var_name = idd->op1->variable->name,
			postfix = utils::get_type_postfix_from_size(idd->op1->size);

		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)		return op1_var_name + " = _rotl" + postfix + '(' + idd->op2->variable->name + ", " + idd->fi->get_variable_name_from_reg(static_cast<operand_reg*>(idd->op2)->reg).value() + ")";
			else if (idd->op2->type == X86_OP_IMM)	return op1_var_name + " = _rotl" + postfix + '(' + idd->op1->variable->name + ", 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op2)->imm) + ')';
		}
		return "TODO";
	}

	static inline std::string _X86_INS_ROR(instruction_dispatch_data* idd)
	{
		const auto op1_var_name = idd->op1->variable->name,
			postfix = utils::get_type_postfix_from_size(idd->op1->size);

		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)		return op1_var_name + " = _rotr" + postfix + '(' + idd->op2->variable->name + ", " + idd->fi->get_variable_name_from_reg(static_cast<operand_reg*>(idd->op2)->reg).value() + ")";
			else if (idd->op2->type == X86_OP_IMM)	return op1_var_name + " = _rotr" + postfix + '(' + idd->op1->variable->name + ", 0x" + utils::to_hex(static_cast<operand_imm*>(idd->op2)->imm) + ')';
		}
		return "TODO";
	}
	
	static inline std::string _X86_INS_LEA(instruction_dispatch_data* idd)
	{
		if (idd->op2 && idd->op2->type == X86_OP_MEM)
		{
			const auto op2_mem = static_cast<operand_mem*>(idd->op2);

			auto displacement = op2_mem->disp;

			if (idd->ip + displacement == idd->module_base)	return idd->op1->variable->name + " = " + idd->gi->get_base_address_name();
			else
			{
				std::string mem_str = idd->op1->variable->name + " = ";

				if (auto segment = op2_mem->segment; segment == X86_REG_INVALID)
				{
					if (auto base = op2_mem->base; base != X86_REG_INVALID)
						mem_str += idd->fi->get_variable_name_from_reg(base).value();

					if (auto index = op2_mem->index; index != X86_REG_INVALID)
					{
						mem_str += " + " + idd->fi->get_variable_name_from_reg(index).value();

						if (auto scale = op2_mem->scale; scale > 1)
							mem_str += " * 0x" + utils::to_hex(scale);
					}
				}
				else return "TODO";

				std::string displacement_op = " +";

				if (displacement < 0)
				{
					displacement_op = " -";
					displacement *= -1;
				}

				return (displacement != 0 ? mem_str + displacement_op + " 0x" + utils::to_hex(displacement) : mem_str);
			}
		}

		return "TODO";
	}

	static inline std::string _X86_INS_MOV(instruction_dispatch_data* idd)
	{
		if (idd->op1->type == X86_OP_REG)
		{
			if (idd->op2->type == X86_OP_REG)		return idd->op1->variable->name + " = " + idd->op2->variable->name;
			else if (idd->op2->type == X86_OP_IMM)
			{
				if (const auto imm = static_cast<operand_imm*>(idd->op2)->imm; imm < 0)
					return idd->op1->variable->name + " = -0x" + utils::to_hex(imm * -1);
				else return idd->op1->variable->name + " = 0x" + utils::to_hex(imm);
			}
			else if (idd->op2->type == X86_OP_MEM)
			{
				if (!idd->ii->assigned_param)
				{
					std::string mem_str = idd->op1->variable->name + " = rpm<" + utils::get_type_from_size(true, idd->op2->size) + ">(";

					const auto op2_mem = static_cast<operand_mem*>(idd->op2);

					if (auto base = op2_mem->base; base != X86_REG_INVALID)
					{
						if (auto base_variable_name = idd->fi->get_variable_name_from_reg(base); base_variable_name.has_value())
							mem_str += base_variable_name.value();
						else return idd->op1->variable->name + " = data";
					}

					if (auto index = op2_mem->index; index != X86_REG_INVALID)
					{
						auto index_name = idd->fi->get_variable_name_from_reg(index);

						if (!index_name.has_value())
							return idd->op1->variable->name + " = data";

						mem_str += " + " + index_name.value();

						if (auto scale = op2_mem->scale; scale > 1)
							mem_str += " * 0x" + utils::to_hex(scale);
					}

					const auto displacement = op2_mem->disp;

					return (displacement != 0 ? mem_str + " + 0x" + utils::to_hex(displacement) : mem_str) + ')';
				}
				else return idd->op1->variable->name + " = p" + std::to_string(*idd->ii->assigned_param);
			}
		}

		return "TODO";
	}

	static inline std::string _X86_INS_MOVABS(instruction_dispatch_data* idd)
	{
		return _X86_INS_MOV(idd);
	}

	static inline std::string _X86_INS_MOVSX(instruction_dispatch_data* idd)
	{
		return _X86_INS_MOV(idd);
	}

	static inline std::string _X86_INS_MOVZX(instruction_dispatch_data* idd)
	{
		return _X86_INS_MOV(idd);
	}

	static inline std::string _X86_INS_MOVDQU(instruction_dispatch_data* idd)
	{
		/*if (idd->op2 && idd->op2->type == X86_OP_REG) return " = " + idd->op1->variables[0]->name;
		return " = data";*/
		return "TODO";
	}

	static inline std::string _X86_INS_MOVDQA(instruction_dispatch_data* idd)
	{
		/*switch (idd->op1->type)
		{
		case X86_OP_MEM: return (idd->parsing ? "" : " = ") + idd->op1->variables[0]->name;
		}

		if (idd->op2)
			return " = " + idd->op1->variables[0]->name;
		return " data";*/
		return "TODO";
	}

	static inline std::string _X86_INS_PADDQ(instruction_dispatch_data* idd)
	{
		/*std::string op2_fixed;

		switch (idd->op2->type)
		{
		case X86_OP_REG: op2_fixed = idd->op2->var_name;										break;
		case X86_OP_IMM: op2_fixed = "0x" + idd->op2->imm;										break;
		case X86_OP_MEM: op2_fixed = "0x" + (idd->op2->imm.empty() ? idd->op2->mem.disp : idd->op2->imm);	break;
		}

		return " += " + op2_fixed;*/
		return "TODO";
	}

	static inline std::string _X86_INS_PSLLQ(instruction_dispatch_data* idd)
	{
		//if (idd->op2->type == X86_OP_IMM) return " = " + idd->variable_name + " << 0x" + idd->op2->imm;
		return "TODO";
	}

	static inline std::string _X86_INS_PSRLQ(instruction_dispatch_data* idd)
	{
		//if (idd->op2->type == X86_OP_IMM) return " = " + idd->variable_name + " >> 0x" + idd->op2->imm;
		return "TODO";
	}

	static inline std::string _X86_INS_POR(instruction_dispatch_data* idd)
	{
		//return " = " + idd->op1->var_name + " ^ " + idd->op2->var_name;
		return "TODO";
	}
};