#pragma once

#include "garuda.h"
#include "utils.h"

namespace garuda
{
	/**
	* Information that is used by each callback to create the pseudo-code
	*/
	struct pp_instruction_dispatch_data
	{
		global_info* gi;

		function_info* fi;

		branch_info* bi;

		bool create_condition;
	};

	static inline std::string _X86_INS_JE(pp_instruction_dispatch_data* pidd)
	{
		if (pidd->create_condition) return "if (" + pidd->bi->v0->name + " == " + pidd->bi->v1->name + ") goto " + pidd->bi->label_name + ';';
		else						return pidd->bi->label_name + ":";
		return "TODO";
	}

	static inline std::string _X86_INS_JNE(pp_instruction_dispatch_data* pidd)
	{
		if (pidd->create_condition) return "if (" + pidd->bi->v0->name + " != " + pidd->bi->v1->name + ") goto " + pidd->bi->label_name + ';';
		else						return pidd->bi->label_name + ":";
		return "TODO";
	}

	static inline std::string _X86_INS_JG(pp_instruction_dispatch_data* pidd)
	{
		if (pidd->create_condition) return "if (" + pidd->bi->v0->name + " > " + pidd->bi->v1->name + ") goto " + pidd->bi->label_name + ';';
		else						return pidd->bi->label_name + ":";
		return "TODO";
	}

	static inline std::string _X86_INS_JGE(pp_instruction_dispatch_data* pidd)
	{
		if (pidd->create_condition) return "if (" + pidd->bi->v0->name + " >= " + pidd->bi->v1->name + ") goto " + pidd->bi->label_name + ';';
		else						return pidd->bi->label_name + ":";
		return "TODO";
	}

	static inline std::string _X86_INS_JL(pp_instruction_dispatch_data* pidd)
	{
		if (pidd->create_condition) return "if (" + pidd->bi->v0->name + " < " + pidd->bi->v1->name + ") goto " + pidd->bi->label_name + ';';
		else						return pidd->bi->label_name + ":";
		return "TODO";
	}

	static inline std::string _X86_INS_JLE(pp_instruction_dispatch_data* pidd)
	{
		if (pidd->create_condition) return "if (" + pidd->bi->v0->name + " <= " + pidd->bi->v1->name + ") goto " + pidd->bi->label_name + ';';
		else						return pidd->bi->label_name + ":";
		return "TODO";
	}
};