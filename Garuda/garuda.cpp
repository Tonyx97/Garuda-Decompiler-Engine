#include "garuda.h"
#include "instructions_callbacks.h"
#include "post_proc_instructions_callbacks.h"

namespace garuda
{
	// main instructions
	std::unordered_map<uint32_t, std::function<std::string(instruction_dispatch_data*)>> ins_callbacks;

	// instructions used for post processing
	std::unordered_map<uint32_t, std::function<std::string(struct pp_instruction_dispatch_data*)>> ins_post_proc_callbacks;

	// instructions used for pre processing look-up
	std::unordered_set<x86_insn> ins_pre_proc;

	// instructions used for post processing look-up
	std::unordered_set<x86_insn> ins_post_proc;

	x86_reg helper::get_reg_category(x86_reg reg)
	{
		if (reg == X86_REG_INVALID)
			return reg;

		switch (reg)
		{
		case X86_REG_RAX:
		case X86_REG_EAX:
		case X86_REG_AX:
		case X86_REG_AH:	return X86_REG_RAX;
		case X86_REG_RBX:
		case X86_REG_EBX:
		case X86_REG_BX:
		case X86_REG_BH:	return X86_REG_RBX;
		case X86_REG_RCX:
		case X86_REG_ECX:
		case X86_REG_CX:
		case X86_REG_CH:	return X86_REG_RCX;
		case X86_REG_RDX:
		case X86_REG_EDX:
		case X86_REG_DX:
		case X86_REG_DH:	return X86_REG_RDX;
		case X86_REG_RSP:
		case X86_REG_ESP:
		case X86_REG_SP:
		case X86_REG_SPL:	return X86_REG_RSP;
		case X86_REG_RBP:
		case X86_REG_EBP:
		case X86_REG_BP:
		case X86_REG_BPL:	return X86_REG_RBP;
		case X86_REG_RSI:
		case X86_REG_ESI:
		case X86_REG_SI:
		case X86_REG_SIL:	return X86_REG_RSI;
		case X86_REG_RDI:
		case X86_REG_EDI:
		case X86_REG_DI:
		case X86_REG_DIL:	return X86_REG_RDI;
		case X86_REG_R8:
		case X86_REG_R8D:
		case X86_REG_R8W:
		case X86_REG_R8B:	return X86_REG_R8;
		case X86_REG_R9:
		case X86_REG_R9D:
		case X86_REG_R9W:
		case X86_REG_R9B:	return X86_REG_R9;
		case X86_REG_R10:
		case X86_REG_R10D:
		case X86_REG_R10W:
		case X86_REG_R10B:	return X86_REG_R10;
		case X86_REG_R11:
		case X86_REG_R11D:
		case X86_REG_R11W:
		case X86_REG_R11B:	return X86_REG_R11;
		case X86_REG_R12:
		case X86_REG_R12D:
		case X86_REG_R12W:
		case X86_REG_R12B:	return X86_REG_R12;
		case X86_REG_R13:
		case X86_REG_R13D:
		case X86_REG_R13W:
		case X86_REG_R13B:	return X86_REG_R13;
		case X86_REG_R14:
		case X86_REG_R14D:
		case X86_REG_R14W:
		case X86_REG_R14B:	return X86_REG_R14;
		case X86_REG_R15:
		case X86_REG_R15D:
		case X86_REG_R15W:
		case X86_REG_R15B:	return X86_REG_R15;
		}

		return reg;
	}

	bool helper_is_main_instruction(uint32_t ins)
	{
		return (ins_callbacks.find(x86_insn(ins)) != ins_callbacks.end());
	}
	
	bool helper_is_proc_look_up_instruction(uint32_t ins)
	{
		return (ins_pre_proc.find(x86_insn(ins)) != ins_pre_proc.end() ||
				ins_post_proc.find(x86_insn(ins)) != ins_post_proc.end());
	}
	
	bool helper_is_proc_instruction(uint32_t ins)
	{
		return (ins_post_proc_callbacks.find(x86_insn(ins)) != ins_post_proc_callbacks.end());
	}

	void global_info::destroy()
	{
		for (auto&& fn : functions)
			delete fn;
	}

	void function_info::destroy()
	{
		for (auto&& branch : branches)
			delete branch;

		for (auto&& ins : instructions)
			delete ins;

		for (auto&& [key, var] : variables)
			delete var;
	}

	bool function_info::create_snapshot(global_info* gi, uint64_t base_addr, uint64_t offset, size_t size)
	{
		this->gi = gi;
		this->base_address = base_addr;
		this->offset = offset;

		if (!snapshot.open())
			return false;

		return snapshot.disasm(base_addr + offset, size);
	}

	bool function_info::parse_instruction(parse_info& pi,
										  cs_insn* ins,
										  cs_x86* arch)
	{
		if (pi.start_instruction != X86_INS_INVALID && ins->id != pi.start_instruction)
			return false;
		else pi.start_instruction = X86_INS_INVALID;

#if PRINT_ALL_INSTRUCTIONS
		dbg::println(dbg::WHITE, "\n------------------------------");
		dbg::println(dbg::WHITE, "0x%llx (0x%x):\t%s\t%s", ins->address, ins->id, ins->mnemonic, ins->op_str);
#endif
		
		auto ins_info = new instruction_info();

		ins_info->id = ins->id;
		ins_info->mnemonic = ins->mnemonic;
		ins_info->op_str = ins->op_str;
		ins_info->jmp = base_address + offset + ins->address;
		ins_info->offset = ins->address;
		ins_info->size = ins->size;

		bool commit_instruction = true;

		for (auto j = 0; j < arch->op_count; ++j)
		{
			const auto op = &arch->operands[j];
			const auto op_reg = op->reg;
			const auto op_reg_category = helper::get_reg_category(op_reg);
			const bool read_access	= !!(op->access & CS_AC_READ),
					   write_access = !!(op->access & CS_AC_WRITE),
					   rw_access	= (read_access && write_access);

			operand_base_info* op_data_base = nullptr;

			switch (op->type)
			{
			case X86_OP_REG:
			{
#if PRINT_ALL_INSTRUCTIONS
				dbg::println(dbg::WHITE, "\t\t[%u] Type: REG = %s [R(%i) | W(%i) | size(%i)]", j, snapshot.get_reg_name(op_reg), read_access, write_access, op->size);
#endif

				if (((pi.flags & FLAG_IGNORE_REG_IN_DST) && op_reg_category == pi.dst_ignore && (read_access || write_access)) ||
					((pi.flags & FLAG_IGNORE_REG_IN_SRC) && op_reg_category == pi.src_ignore && read_access))
				{
					commit_instruction = false;
					break;
				}

				if ((pi.return_flags & RETURN_ON_DST_REG_MATCH) && op_reg_category == pi.dst_reg_return)
				{
					snapshot.stop_parsing();
					break;
				}
				
				auto op_data = new operand_reg();

				op_data->reg_name = snapshot.get_reg_name(op_reg);
				op_data->reg = op_reg;
				op_data->reg_category = op_reg_category;

				variable_info* var_info = nullptr;

				if (var_info = get_variable_from_reg(op_data->reg_category); !var_info)
				{
					var_info = new variable_info();

					var_info->name = VARIABLE_PREFIX() + std::to_string(var_info->index = variables.size());
					var_info->reg_name = op_data->reg_name;
					var_info->reg = op_data->reg;
					var_info->reg_category = op_data->reg_category;
					var_info->dereferences = 0;

					variables.insert({ op_data->reg_category, var_info });
				}
				else ++var_info->dereferences;

				if ((rw_access || write_access) && var_info->dereferences > 0)
					previous_written_variable = var_info;
				else
				{
					// special treats for instructions with implicit operations

					switch (ins->id)
					{
					case X86_INS_MUL:
					{
						if (auto rax_variable = get_variable_from_reg(X86_REG_RAX))
							previous_written_variable = rax_variable;
						break;
					}
					}
				}

				op_data->variable = var_info;

				op_data_base = op_data;

				break;
			}
			case X86_OP_IMM:
			{
#if PRINT_ALL_INSTRUCTIONS
				dbg::println(dbg::WHITE, "\t\t[%u] Type: IMM = 0x%llx [R(%i) | W(%i) | size(%i)]", j, op->imm, read_access, write_access, op->size);
#endif

				auto op_data = new operand_imm();

				op_data->imm = op->imm;

				op_data_base = op_data;

				break;
			}
			case X86_OP_MEM:
			{
#if PRINT_ALL_INSTRUCTIONS
				dbg::println(dbg::WHITE, "\t\t[%u] Type: MEM [R(%i) | W(%i) | size(%i)]", j, read_access, write_access, op->size);
#endif

				std::string base = (op->mem.base != X86_REG_INVALID ? snapshot.get_reg_name(op->mem.base) : ""),
							index = (op->mem.index != X86_REG_INVALID ? snapshot.get_reg_name(op->mem.index) : ""),
							disp = (op->mem.disp != 0 ? utils::to_hex(op->mem.disp) : ""),
							scale = (op->mem.scale != 0 ? utils::to_hex(op->mem.scale) : ""),
							segment = (op->mem.segment != 0 ? utils::to_hex(op->mem.segment) : "");

#if PRINT_ALL_INSTRUCTIONS
				if (!base.empty())		dbg::println(dbg::WHITE, "\t\t\tBase: %s", base.c_str());
				if (!index.empty())		dbg::println(dbg::WHITE, "\t\t\tIndex: %s", index.c_str());
				if (!disp.empty())		dbg::println(dbg::WHITE, "\t\t\tDisp: %s", disp.c_str());
				if (!scale.empty())		dbg::println(dbg::WHITE, "\t\t\tScale: %s", scale.c_str());	
				if (!segment.empty())	dbg::println(dbg::WHITE, "\t\t\tSegment: %s", segment.c_str());
#endif

				const auto base_reg_category = helper::get_reg_category(op->mem.base),
						   index_reg_category = helper::get_reg_category(op->mem.index);
				
				if (((pi.flags & FLAG_IGNORE_REG_IN_DST) && base_reg_category == pi.dst_ignore && (read_access || write_access)) ||
					((pi.flags & FLAG_IGNORE_REG_IN_SRC) && base_reg_category == pi.src_ignore && read_access))
				{
					commit_instruction = false;
					break;
				}
				
				auto op_data = new operand_mem();

				if (op->mem.base != X86_REG_INVALID)	op_data->base = op->mem.base;
				else									op_data->base = X86_REG_INVALID;

				if (op->mem.index != X86_REG_INVALID)	op_data->index = op->mem.index;
				else									op_data->index = X86_REG_INVALID;

				if (op->mem.segment != X86_REG_INVALID) op_data->segment = op->mem.segment;
				else									op_data->segment = X86_REG_INVALID;

				op_data->disp = op->mem.disp;
				op_data->scale = op->mem.scale;

				if (op->mem.base == x86_reg::X86_REG_RIP)
					op_data->accessed_imm = *(int64_t*)(ins_info->jmp + ins->size + op_data->disp);

				if (auto var = get_variable_from_reg(base_reg_category))	++var->dereferences;
				if (auto var = get_variable_from_reg(index_reg_category))	++var->dereferences;

				op_data_base = op_data;

				break;
			}
			}

			if (op_data_base)
			{
				op_data_base->type = op->type;
				op_data_base->size = op->size;
				op_data_base->access = op->access;

				ins_info->operands.push_back(op_data_base);
			}
		}

		if (!commit_instruction)
		{
			delete ins_info;
			return true;
		}

		const auto total_operands = ins_info->operands.size();

		auto op1 = total_operands > 0 ? ins_info->operands[0] : nullptr,
			 op2 = total_operands > 1 ? ins_info->operands[1] : nullptr,
			 op3 = total_operands > 2 ? ins_info->operands[2] : nullptr;

		const bool last_instruction = (pi.end_instruction != X86_INS_INVALID && ins->id == pi.end_instruction);

		if (last_instruction)
		{
			if (pi.flags & FLAG_IGNORE_LAST_INSTRUCTION)
			{
				if (previous_written_variable)
					++previous_written_variable->dereferences;

				snapshot.stop_parsing();
			}
			else if (pi.return_flags & RETURN_ON_LAST_INSTRUCTION)
				snapshot.stop_parsing();
		}
			
		if (helper_is_main_instruction(ins->id) || helper_is_proc_look_up_instruction(ins->id))
		{
			if (!snapshot.is_parsing())
				ins_info->id = X86_INS_RET;

			add_instruction(ins_info);
		}

		return true;
	}

	bool function_info::do_post_processing()
	{
		if (variables.empty())
			return false;

		// remove the corresponding redundant variables and instructions

		for (auto [it, var] = variables_tuple{ variables.begin(), variables.begin()->second }; it != variables.end(); var = it->second)
		{
			if (var->dereferences == 0)
			{
				auto ins_it = instructions.begin();
				while (ins_it != instructions.end())
				{
					auto instruction = *ins_it;

					if (instruction->is_reg_in_any_operand(var->reg_category))
					{
						delete instruction;
						ins_it = instructions.erase(ins_it);
					}
					else ++ins_it;
				}

				delete var;
				it = variables.erase(it);
			}
			else ++it;
		}

		// rename variables after cleaning up redundant variables and instructions

		int current_variable_index = 0;

		for (auto [reg, var] : variables)
			var->name = VARIABLE_PREFIX() + std::to_string(var->index = current_variable_index++);

		// create missing variables jmp instructions with implicit operations

		for (auto&& ins : instructions)
		{
			switch (ins->id)
			{
			case X86_INS_MUL:
			{
				if (!get_variable_name_from_reg(X86_REG_RAX).has_value()) create_variable(nullptr, X86_REG_RAX);
				if (!get_variable_name_from_reg(X86_REG_RDX).has_value()) create_variable(nullptr, X86_REG_RDX);

				break;
			}
			}
		}

		// process conditional jumps

		for (auto [it, ins] = instructions_tuple_ex { instructions.begin(), *instructions.begin() }; it != instructions.end(); ++it, ins = *it)
		{
			switch (ins->id)
			{
			case X86_INS_TEST:
			case X86_INS_CMP:	create_branch(ins); break;
			case X86_INS_JE:
			case X86_INS_JNE:
			case X86_INS_JG:
			case X86_INS_JL:
			case X86_INS_JGE:
			case X86_INS_JLE:
			{
				if (!current_branch_info->jmp || !current_branch_info->target)
				{
					if (auto target_instruction = find_instruction_by_address(static_cast<operand_imm*>(ins->operands[0])->imm))
					{
						for (auto&& branch : branches)
							if (branch->target == target_instruction)
							{
								current_branch_info->label_name = branch->label_name;
								break;
							}

						current_branch_info->jmp = ins;
						current_branch_info->target = target_instruction;
					}
				}

				break;
			}
			}
		}

		return true;
	}

	bool function_info::generate_code()
	{
		// do post processing

		if (!do_post_processing())
			return false;

		// define all the used variables

		define_variables();

		// dispatch and save all final instructions and branches

		std::unordered_set<instruction_info*> branch_targets_created;

		for (auto&& ins : instructions)
		{
			for (auto&& branch : branches)
			{
				const bool is_jmp = branch->is_instruction_jmp(ins),
						   is_target = branch->is_instruction_target(ins);
				
				if (is_jmp || is_target)
				{
					const auto jmp = branch->jmp,
							   target = branch->target;

					if (is_target)
					{
						if (auto it = branch_targets_created.find(target); it != branch_targets_created.end())
							continue;

						branch_targets_created.insert(target);
					}
					
					if (auto it = ins_post_proc_callbacks.find(x86_insn(jmp->id)); it != ins_post_proc_callbacks.end())
					{
						const auto& pp_callback = it->second;

						pp_instruction_dispatch_data pidd {};

						pidd.gi = gi;
						pidd.fi = this;
						pidd.bi = branch;
						pidd.create_condition = (is_jmp ? true : !is_target);

						if (!pidd.create_condition)
							add_instruction_line("");

						add_instruction_line(pp_callback(&pidd), pidd.create_condition ? -1 : 0);
					}
				}
			}

			if (auto it = ins_callbacks.find(ins->id); it != ins_callbacks.end() || ins->id == X86_INS_RET)
			{
				const auto total_operands = ins->operands.size();

				instruction_dispatch_data idd
				{
					gi,
					this,
					total_operands > 0 ? ins->operands[0] : nullptr,
					total_operands > 1 ? ins->operands[1] : nullptr,
					total_operands > 2 ? ins->operands[2] : nullptr,
					total_operands,
					base_address,
					ins->jmp + ins->size,
				};

				if (ins->id != X86_INS_RET)
					add_instruction_line(it->second(&idd) + ";", ins->mnemonic, ins->op_str);
				else if (return_size > 0)
					add_return_line(previous_written_variable->name);
			}
		}

		return true;
	}

	branch_info* function_info::create_branch(instruction_info* ins_info)
	{
		current_branch_info = new branch_info();

		current_branch_info->label_name = LABEL_PREFIX() + std::to_string(branches.size());
		current_branch_info->cmp = ins_info;
		current_branch_info->v0 = ins_info->operands[0]->variable;
		current_branch_info->v1 = ins_info->operands[1]->variable;

		branches.push_back(current_branch_info);

		return current_branch_info;
	}

	variable_info* function_info::create_variable(operand_reg* op, x86_reg reg)
	{
		variable_info* var_info = nullptr;

		if (var_info = get_variable_from_reg(reg); !var_info)
		{
			variable_info* var_info = new variable_info();

			var_info->name = VARIABLE_PREFIX() + std::to_string(var_info->index = variables.size());
			var_info->reg = reg;
			var_info->reg_name = snapshot.get_reg_name(reg);
			var_info->reg_category = helper::get_reg_category(reg);
			var_info->dereferences = true;

			variables.insert({ reg, var_info });
		}

		if (op)
			op->variable = var_info;

		return var_info;
	}

	variable_info* function_info::get_variable_from_reg(x86_reg reg)
	{
		auto it = variables.find(reg);
		return (it != variables.end() ? it->second : nullptr);
	}

	std::optional<std::string> function_info::get_variable_name_from_reg(x86_reg reg)
	{
		if (auto var = get_variable_from_reg(reg))
			return var->name;
		return {};
	}

	instruction_info* function_info::find_instruction_by_address(uint64_t offset)
	{
		auto it = std::find_if(instructions.begin(), instructions.end(), [offset](auto ins) { return (ins->offset == offset); });
		return (it != instructions.end() ? *it : nullptr);
	}

	void function_info::add_template_parameter(const std::string& name)
	{
		add_line(dbg::make_text(dbg::BLUE, "typename "));
		add_line(dbg::make_text(dbg::CYAN, name));
		template_names.insert(name);
	}

	void function_info::add_parameter(const std::string& name)
	{
		std::regex rule("(const)* ([a-zA-Z0-9]+)(\\s)*(\\&)*(\\s)*([a-zA-Z0-9]+)");
		std::smatch match;

		if (std::regex_match(name, match, rule))
		{
			if (match.size() > 1)
			{
				for (auto it = match.begin() + 1; it != match.end(); ++it)
				{
					const auto& str = it->str();

					if (!str.compare("const"))									add_line(dbg::make_text(dbg::BLUE, str + " "));
					else if (!str.compare("&"))									add_line(dbg::make_text(dbg::WHITE, str));
					else if (template_names.find(str) != template_names.end())	add_line(dbg::make_text(dbg::CYAN, str));
					else 														add_line(dbg::make_text(dbg::DARK_GREY, str));

				}
			}
			else add_line(dbg::make_text(dbg::WHITE, name));
		}
	}

	void function_info::add_comment(const std::string& val)
	{
		add_line(dbg::make_text_nl(dbg::DARK_GREEN, "// " + val));
		add_line(dbg::make_text_nl(dbg::DARK_GREEN, "// "));
	}

	void function_info::define_variables()
	{
		add_line(dbg::make_text(dbg::BLUE, "\tunsigned __int64 "));

		std::set<std::pair<x86_reg, variable_info*>, map_to_set_variable_order> variables_set { variables.begin(), variables.end() };

		for (auto it = variables_set.begin(); it != variables_set.end(); ++it)
		{
			if (it != variables_set.begin())
				add_line(dbg::make_text(dbg::WHITE, ", "));

			add_line(dbg::make_text(dbg::CYAN, it->second->name));
		}

		add_line(dbg::make_text_nl(dbg::WHITE, ";\n"));
	}

	void function_info::add_instruction_line(const std::string& val, const std::string& mnemonic, const std::string& op_str, int temp_indent_level)
	{
		auto current_indent_level = indent_level;

		if (temp_indent_level != -1)
			indent_level = temp_indent_level;

		for (auto i = 0; i < indent_level; ++i)
			add_line(dbg::make_text(dbg::WHITE, "\t"));

		add_line(dbg::make_text_align(dbg::WHITE, val, 50));
		add_line(dbg::make_text_align(dbg::DARK_GREEN, "// " + mnemonic + '\t' + op_str, 10));

		add_empty_line();

		indent_level = current_indent_level;
	}

	void function_info::add_instruction_line(const std::string& val, int temp_indent_level)
	{
		auto current_indent_level = indent_level;

		if (temp_indent_level != -1)
			indent_level = temp_indent_level;

		for (auto i = 0; i < indent_level; ++i)
			add_line(dbg::make_text(dbg::WHITE, "\t"));

		add_line(dbg::make_text_nl(dbg::WHITE, val));

		indent_level = current_indent_level;
	}

	void function_info::add_return_line(const std::string& variable)
	{
		add_line(dbg::make_text_nl(dbg::WHITE, ""));

		for (auto i = 0; i < indent_level; ++i)
			add_line(dbg::make_text(dbg::WHITE, "\t"));

		add_line(dbg::make_text(dbg::BLUE, "return"));
		add_line(dbg::make_text_nl(dbg::WHITE, (!variable.empty() ? " " + variable : "") + ';'));
	}
	
	void function_info::print()
	{
		for (auto& line : content)
			line.print();
	}

	global_info::global_info()
	{
		// basic instructions
		ins_callbacks.insert({ X86_INS_ADD,		_X86_INS_ADD });
		ins_callbacks.insert({ X86_INS_SUB,		_X86_INS_SUB });
		ins_callbacks.insert({ X86_INS_IMUL,	_X86_INS_IMUL });
		ins_callbacks.insert({ X86_INS_MUL,		_X86_INS_MUL });
		ins_callbacks.insert({ X86_INS_AND,		_X86_INS_AND });
		ins_callbacks.insert({ X86_INS_XOR,		_X86_INS_XOR });
		ins_callbacks.insert({ X86_INS_SHL,		_X86_INS_SHL });
		ins_callbacks.insert({ X86_INS_SHR,		_X86_INS_SHR });
		ins_callbacks.insert({ X86_INS_ROL,		_X86_INS_ROL });
		ins_callbacks.insert({ X86_INS_ROR,		_X86_INS_ROR });

		// memory instructions
		ins_callbacks.insert({ X86_INS_LEA,		_X86_INS_LEA });
		ins_callbacks.insert({ X86_INS_MOV,		_X86_INS_MOV });
		ins_callbacks.insert({ X86_INS_MOVABS,	_X86_INS_MOVABS });
		ins_callbacks.insert({ X86_INS_MOVSX,	_X86_INS_MOVSX });
		ins_callbacks.insert({ X86_INS_MOVZX,	_X86_INS_MOVZX });

		// SSE instructions
		ins_callbacks.insert({ X86_INS_MOVDQU,	_X86_INS_MOVDQU });
		ins_callbacks.insert({ X86_INS_MOVDQA,	_X86_INS_MOVDQA });
		ins_callbacks.insert({ X86_INS_PADDQ,	_X86_INS_PADDQ });
		ins_callbacks.insert({ X86_INS_PSLLQ,	_X86_INS_PSLLQ });
		ins_callbacks.insert({ X86_INS_PSRLQ,	_X86_INS_PSRLQ });
		ins_callbacks.insert({ X86_INS_POR,		_X86_INS_POR });

		ins_pre_proc.insert(X86_INS_RET);
		ins_pre_proc.insert(X86_INS_CALL);
		ins_pre_proc.insert(X86_INS_TEST);
		ins_pre_proc.insert(X86_INS_NOP);

		ins_post_proc.insert(X86_INS_TEST);
		ins_post_proc.insert(X86_INS_CMP);
		ins_post_proc.insert(X86_INS_JE);
		ins_post_proc.insert(X86_INS_JNE);
		ins_post_proc.insert(X86_INS_JG);
		ins_post_proc.insert(X86_INS_JGE);
		ins_post_proc.insert(X86_INS_JL);
		ins_post_proc.insert(X86_INS_JLE);

		ins_post_proc_callbacks.insert({ X86_INS_JE,	_X86_INS_JE });
		ins_post_proc_callbacks.insert({ X86_INS_JNE,	_X86_INS_JNE });
		ins_post_proc_callbacks.insert({ X86_INS_JG,	_X86_INS_JG });
		ins_post_proc_callbacks.insert({ X86_INS_JGE,	_X86_INS_JGE });
		ins_post_proc_callbacks.insert({ X86_INS_JL,	_X86_INS_JL });
		ins_post_proc_callbacks.insert({ X86_INS_JLE,	_X86_INS_JLE });
	}

	bool global_info::parse_fn(const std::string& return_type,
							   size_t return_size,
							   const std::string& name,
							   uint64_t base_addr,
							   uint64_t offset,
							   size_t size)
	{
		auto fi = new function_info(return_size);

		if (!fi->create_snapshot(this, base_addr, offset, size))
			return false;

		fi->add_comment(next_fn_comment);
		fi->add_template("T");
		fi->add_definition(return_type, name, "const T& data");
		fi->begin();

		const auto snapshot = fi->get_snapshot();

		snapshot->for_each_instruction([&](cs_insn* ins)
		{
			fi->parse_instruction(parsing_info, ins, &ins->detail->x86);
		}, [&]() { return !snapshot->is_parsing(); });

		if (!fi->generate_code())
			return false;

		fi->end();
		
		add_function(fi);
	
		return true;
	}

	uint64_t global_info::find_instruction(uint64_t base_addr, x86_insn instruction, size_t max_size)
	{
		helper::snapshot temp {};

		if (!temp.open())
			return 0;

		uint64_t found_at = 0;

		if (temp.disasm(base_addr, max_size))
			temp.for_each_instruction([&](cs_insn* ins)
			{
				if (ins->id == instruction)
					found_at = ins->address;
			}, [&]() { return !!found_at; });

		return found_at;
	}

	void global_info::add_rpm_function(const std::string& str)
	{
		add_lines<dbg::HEADER>(dbg::BLUE, "template ",
							   dbg::WHITE, "<",
							   dbg::BLUE, "typename ",
							   dbg::CYAN, "T",
							   dbg::WHITE, ", ",
							   dbg::BLUE, "typename ",
							   dbg::CYAN, "B",
							   dbg::WHITE, ">\n",
							   dbg::CYAN, "T ",
							   dbg::WHITE, "rpm(",
							   dbg::BLUE, "const ",
							   dbg::CYAN, "B",
							   dbg::WHITE, "& ",
							   dbg::DARK_GREY, "ptr",
							   dbg::WHITE, ")\n",
							   dbg::WHITE, "{\n",
							   dbg::BLUE, "\treturn ",
							   dbg::WHITE, str + ";\n",
							   dbg::WHITE, "}\n\n");
	}

	void global_info::begin()
	{
		add_lines<dbg::HEADER>(dbg::DARK_GREY, "#pragma once\n",
							   EMPTY_NEW_LINE,
							   dbg::DARK_GREY, "#ifndef GARUDA_OUT_H\n",
							   dbg::DARK_GREY, "#define GARUDA_OUT_H\n",
							   EMPTY_NEW_LINE,
							   dbg::DARK_GREEN, "// File auto generated by GARUDA engine (developed by Tonyx97)\n",
							   EMPTY_NEW_LINE);

		add_include("intrin.h");

		add_define("LOBYTE",	"x", "*((unsigned __int8*)&x)");
		add_define("LOWORD",	"x", "*((unsigned __int16*)&x)");
		add_define("LODWORD",	"x", "*((unsigned __int32*)&x)");
		add_define("HIBYTE",	"x", "*((unsigned __int8*)&x + 1)");
		add_define("HIWORD",	"x", "*((unsigned __int16*)&x + 1)");
		add_define("HIDWORD",	"x", "*((unsigned __int32*)&x + 1)");

		add_lines<dbg::HEADER>(EMPTY_NEW_LINE);
	}

	void global_info::end()
	{
		add_lines<dbg::FOOTER>(dbg::DARK_GREY, "#endif");
	}

	void global_info::print(bool copy_to_clipboard)
	{
		dbg::begin_clipboard();

		for (auto&& line : header)	line.print();
		for (auto&& fn : functions) fn->print();
		for (auto&& line : footer)	line.print();

		dbg::end_clipboard();
	}

	void global_info::add_include(const std::string& val)
	{
		add_lines<dbg::HEADER>(dbg::DARK_GREY, "#include ", dbg::DARK_YELLOW, "<" + val + ">\n", EMPTY_NEW_LINE);
	}

	void global_info::add_define(const std::string& name, const std::string& params, const std::string& def)
	{
		add_lines<dbg::HEADER>(dbg::DARK_GREY, "#define ", dbg::DARK_PURPLE, name);

		if (!params.empty())
			add_lines<dbg::HEADER>(dbg::WHITE, "(" + params + ")");

		add_lines<dbg::HEADER>(dbg::WHITE, '\t' + def, EMPTY_NEW_LINE);
	}
};