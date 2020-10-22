#pragma once

#pragma comment(lib, "capstone.lib")

#include <capstone/platform.h>
#include <capstone/capstone.h>

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <sstream>
#include <string>
#include <iomanip>
#include <intrin.h>
#include <regex>
#include <optional>

#include "debug.h"
#include "assembly.h"

#define PRINT_ALL_INSTRUCTIONS 0

#define LOBYTE(x)		(*((unsigned __int8*)&(x)))
#define LOWORD(x)		(*((unsigned __int16*)&(x)))
#define LODWORD(x)		(*((unsigned __int32*)&(x))) 
#define HIBYTE(x)		(*((unsigned __int8*)&(x)+1))
#define HIWORD(x)		(*((unsigned __int16*)&(x)+1))
#define HIDWORD(x)		(*((unsigned __int32*)&(x)+1))

#define SLOBYTE(x)		(*((__int8*)&(x)))
#define SLOWORD(x)		(*((__int16*)&(x)))
#define SLODWORD(x)		(*((__int32*)&(x)))
#define SHIBYTE(x)		(*((__int8*)&(x)+1))
#define SHIWORD(x)		(*((__int16*)&(x)+1))
#define SHIDWORD(x)		(*((__int32*)&(x)+1))

namespace garuda
{
	namespace helper
	{
		/**
		* Class that encapsulates Capstone important variables such as the handle and the instructions parsed
		*/
		class snapshot
		{
		private:

			csh handle = 0;
			cs_insn* instructions = nullptr;
			size_t instructions_count = 0;
			bool parsing = false;

		public:

			~snapshot()
			{
				if (instructions && instructions_count > 0)
					cs_free(instructions, instructions_count);
				cs_close(&handle);
			}

			/**
			* Calls cs_open to init Capstone
			* @return True if it was initialized successfully, false otherwise
			*/
			bool open()								{ return (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == cs_err::CS_ERR_OK && cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == cs_err::CS_ERR_OK); }

			/**
			* Calls cs_disasm to dissect a piece of machine code
			* @param address The start of the code that is going to be analyzed
			* @param size The size of the code region specified
			* @return True if it was dissected successfully, false otherwise
			*/
			bool disasm(uint64_t address, size_t size)
													{ return ((instructions_count = cs_disasm(handle, (uint8_t*)address, size, 0, 0, &instructions)) > 0); }

			void stop_parsing()						{ parsing = false; }
			bool is_parsing() const					{ return parsing; }

			template <typename F, typename C>
			void for_each_instruction(const F& fn, const C& stop_condition)
			{
				parsing = true;

				for (auto i = 0; i < instructions_count && !stop_condition(); ++i)
					fn(&instructions[i]);

				parsing = false;
			}

			const char* get_reg_name(x86_reg reg)	{ return cs_reg_name(handle, reg); }
			
			size_t get_instructions_count()			{ return instructions_count; }
		};

		/**
		* Gets the 64-bit register from a lower sized register of the same type
		* @param address The lower register
		* @return The 64-bit register of the same type
		*/
		x86_reg get_reg_category(x86_reg reg);
	}

	struct global_info;

	/**
	* Class encapsulating all the information required to parse a function
	*/
	struct function_info
	{
	private:

		std::unordered_map<x86_reg, variable_info*> variables;
		
		std::vector<instruction_info*> instructions;

		helper::snapshot snapshot {};

		global_info* gi = nullptr;

		variable_info* previous_written_variable = nullptr;

		branch_info* current_branch_info = nullptr;

		uint64_t base_address = 0,
				 offset = 0;

		size_t return_size = 0;

		int32_t indent_level = 0;
		
		std::vector<dbg::text> content;
		std::vector<branch_info*> branches;
		std::unordered_set<std::string> template_names;

		/**
		* Adds a template parameter
		* @param name The name of the parameter
		*/
		void add_template_parameter(const std::string& name);

		/**
		* Adds a parameter to the function output
		* @param name The name of the parameter
		*/
		void add_parameter(const std::string& name);

		static constexpr auto VARIABLE_PREFIX()							{ return "v"; }
		static constexpr auto LABEL_PREFIX()							{ return "label_"; }

		using variables_iterator = decltype(variables)::iterator;
		using variables_mapped_type = decltype(variables)::mapped_type;
		using variables_tuple = std::tuple<variables_iterator, variables_mapped_type>;

		using instructions_iterator = decltype(instructions)::iterator;
		using instructions_value_type = decltype(instructions)::value_type;
		using instructions_tuple = std::tuple<instructions_iterator, instructions_value_type>;
		using instructions_tuple_ex = std::tuple<instructions_iterator, instructions_value_type>;

		/**
		* Cleans all resources used by this instance
		*/
		void destroy();

	public:

		function_info(size_t return_size) : return_size(return_size)	{}
		~function_info()												{ destroy(); }

		// parsing functions

		/**
		* Creates the capstone snapshot to parse the function (code)
		* @param gi A global_info instance
		* @param base_addr The base address of the code
		* @param offset The offset starting from the base_addr
		* @param The size of the code
		* @return True if the snapshot was created, false otherwise
		*/
		bool create_snapshot(global_info* gi, uint64_t base_addr, uint64_t offset, size_t size);

		/**
		* Parses an specific instruction of the code
		* @param pi A parse_info instance
		* @param ins The instruction to parse
		* @param arch The arquitecture info of the instruction
		* @return True if the instruction was parsed successfully, false otherwise
		*/
		bool parse_instruction(parse_info& pi,
							   cs_insn* ins,
							   cs_x86* arch);

		/**
		* Do the post processing (remove unused variables, optimize code, etc)
		* @return True if the post processing was successful, false otherwise
		*/
		bool do_post_processing();

		/**
		* Generates the pseudo-code after the parsing
		* @param pi A parsing info reference ptr
		* @return True if the code was generated successfully, false otherwise
		*/
		bool generate_code(parse_info& pi);

		/**
		* Saves a instruction into the array for generation purposes
		*/
		void add_instruction(instruction_info* ins_info)				{ instructions.push_back(ins_info); }

		/**
		* Creates an instance of "branch_info"
		* @param ins_info The instruction that modifies RFLAGS (the comparison instruction: test, comp, etc)
		* @return A branch_info instance containing information about a branch, nullptr otherwise
		*/
		branch_info* create_branch(instruction_info* ins_info);

		/**
		* Creates an instance of "variable_info"
		* @param op The operand that will contain the variable info
		* @param reg The register corresponding to the variable
		* @return A variable_info instance containing info about a variable, nullptr otherwise
		*/
		variable_info* create_variable(operand_reg* op, x86_reg reg);

		/**
		* Gets the variable_info instance corresponding to the specified register
		* @param reg The register corresponding to the variable
		* @return A variable_info instance containing info about the variable, nullptr otherwise
		*/
		variable_info* get_variable_from_reg(x86_reg reg);

		/**
		* Gets the variable name from specified register
		* @param reg The register corresponding to the variable
		* @return An std::optional which contains the name if the variable was found
		*/
		std::optional<std::string> get_variable_name_from_reg(x86_reg reg);

		/**
		* Finds the instruction from the specified address
		* @param offset The offset starting from the base address of the code
		* @return A instruction_info* instance corresponding to the found instruction
		*/
		instruction_info* find_instruction_by_address(uint64_t offset);

		helper::snapshot* get_snapshot()								{ return &snapshot; }

		std::vector<instruction_info*>& get_instructions()				{ return instructions; }

		// output functions

		/**
		* Adds a new line to the output
		* @param val The new line
		*/
		void add_line(const dbg::text& val)								{ content.push_back(val); }

		/**
		* Adds an empty line to the output
		* @param val The new line
		*/
		void add_empty_line()											{ content.push_back(dbg::make_text(dbg::WHITE, "\n")); }

		int set_indent_level(int level)									{ return indent_level++; }

		/**
		* Adds a template to the output
		* @param names The variadic arguments of the template
		*/
		template <typename... A>
		void add_template(A&&... names)
		{
			add_line(dbg::make_text(dbg::BLUE, "template "));
			add_line(dbg::make_text(dbg::WHITE, "<"));

			const auto names_list = { names... };

			for (auto it = names_list.begin(); it != names_list.end(); ++it)
			{
				if (it != names_list.begin())
					add_line(dbg::make_text(dbg::WHITE, ", "));

				add_template_parameter(*it);
			}

			add_line(dbg::make_text_nl(dbg::WHITE, ">"));
		}

		/**
		* Adds the definition of the function to the output
		* @param ret_type The return type
		* @param name The name of the function
		* @param params The parameters of the function
		*/
		template <typename... A>
		void add_definition(const std::string& ret_type, const std::string& name, A&&... params)
		{
			add_line(dbg::make_text(dbg::BLUE, ret_type + " "));
			add_line(dbg::make_text(dbg::YELLOW, name));
			add_line(dbg::make_text(dbg::WHITE, "("));

			const auto params_list = { params... };

			for (auto it = params_list.begin(); it != params_list.end(); ++it)
			{
				if (it != params_list.begin())
					add_line(dbg::make_text(dbg::WHITE, ", "));

				add_parameter(*it);
			}

			add_line(dbg::make_text_nl(dbg::WHITE, ")"));
		}

		/**
		* Adds a comment to the function output
		* @param val The comment
		*/
		void add_comment(const std::string& val);

		/**
		* Adds all used variables definitions at the beginning of the function
		*/
		void define_variables();

		/**
		* Adds a line containing the final pseudo-code of an instruction and the original assembly code
		* @param val The pseudo-code
		* @param mnemonic The mnemonic of the instruction
		* @param op_str The operation string of the instruction
		* @param temp_indent_level The new indent level that will be used to print this line
		*/
		void add_instruction_line(const std::string& val, const std::string& mnemonic, const std::string& op_str, int temp_indent_level = -1);
		
		/**
		* Adds a line containing the final pseudo-code of an instruction and the original assembly code
		* @param val The pseudo-code
		* @param temp_indent_level The new indent level that will be used to print this line
		*/
		void add_instruction_line(const std::string& val, int temp_indent_level = -1);

		/**
		* Adds the line that contains the return instruction to end the function
		* @param variable The variable name that will be returned
		*/
		void add_return_line(const std::string& variable);

		/**
		* Begins the pre-processing of the function
		*/
		void begin()													{ add_line(dbg::make_text_nl(dbg::WHITE, "{"));   indent_level = 1; }

		/**
		* Ends the post-processing of the function
		*/
		void end()														{ add_line(dbg::make_text_nl(dbg::WHITE, "}\n")); indent_level = 0; }

		/**
		* Prints the complete generated pseudo-code
		*/
		void print();
	};

	struct global_info
	{
	private:

		parse_info parsing_info {};

		std::vector<function_info*> functions;

		std::vector<dbg::text> header,
							   footer;

		std::string next_fn_comment,
					base_address_name;

		/**
		* Parses a function. The parsing is unsafe against invalid memory region, must add explicit checks before calling this function
		* @param return_type The return type name of the function
		* @param return_size The return size of the function
		* @param name The name of the function
		* @param base_addr The base address of the code
		* @param offset The offset based on the base_addr
		* @param size The size of the code
		* @return True if function was parsed successfully, false otherwise
		*/
		bool parse_fn(const std::string& return_type,
					  size_t return_size,
					  const std::string& name,
					  uint64_t base_addr,
					  uint64_t offset,
					  size_t size);

		/**
		* Adds the last unpack of the main 'add_lines<dbg::HEADER>' method to the global output
		* @tparam T The type of the line
		* @param color The color of the current text
		* @param text The current text
		*/
		template <unsigned int T, std::enable_if_t<T == dbg::HEADER>* = nullptr>
		void add_lines(uint16_t color, const std::string& text) { header.push_back(dbg::make_text(color, text)); }

		/**
		* Adds the last unpack of the main 'add_lines<dbg::FOOTER>' method to the global output
		* @tparam T The type of the line
		* @param color The color of the current text
		* @param text The current text
		*/
		template <unsigned int T, std::enable_if_t<T == dbg::FOOTER>* = nullptr>
		void add_lines(uint16_t color, const std::string& text) { footer.push_back(dbg::make_text(color, text)); }

		/**
		* Cleans all resources used by this instance
		*/
		void destroy();

	public:

		global_info();
		~global_info()											{ destroy(); }

		// parsing functions

		/**
		* Parses a function with detailed arguments. The parsing is unsafe against invalid memory region, must add explicit checks before calling this function
		* @tparam R The return type
		* @tparam start_ins The instruction where the parsing will start at. Ignored if X86_INS_INVALID is given
		* @tparam end_ins The instruction where the parsing will stop at. Ignored if X86_INS_INVALID is given
		* @param name The name of the function
		* @param base_addr The base address of the code
		* @param offset The offset based on the base_addr
		* @param size The size of the code
		* @param flags The generic flags to parse
		* @param return_flags The return flags to parse
		* @return True if function was parsed successfully, false otherwise
		*/
		template <typename R, x86_insn start_ins = X86_INS_INVALID, x86_insn end_ins = X86_INS_INVALID>
		bool parse_fn(const std::string& name,
					  uint64_t base_addr,
					  uint64_t offset,
				 	  size_t size,
			 		  uint32_t flags = FLAG_NONE,
					  uint32_t return_flags = RETURN_ON_REACH_SPECIFIED_END)
		{
			parsing_info.start_instruction = start_ins;
			parsing_info.end_instruction = end_ins;
			parsing_info.flags = flags;
			parsing_info.return_flags = return_flags;

			size_t return_size = 0;

			if constexpr (!std::is_void_v<R>)
				return_size = sizeof(R);

			const bool ok = parse_fn(typeid(R).name(), return_size, name, base_addr, offset, size);

			memset(&parsing_info, 0, sizeof(parsing_info));

			return ok;
		}

		/**
		* Adds a function to the functions container for post-processing
		* @param val The function
		*/
		void add_function(function_info* val)					{ functions.push_back(val); }

		/**
		* Finds an instruction in memory
		* @param base_addr The base address of the code
		* @param instruction The instruction to be found
		* @param max_size The maximum size that it will be parsing to
		* @return The offset of the found instruction, 0 otherwise
		*/
		uint64_t find_instruction(uint64_t base_addr, x86_insn instruction, size_t max_size = 0x100);

		/**
		* Finds an piece of mem in memory by its bytes
		* @param base_addr The base address of the code
		* @param instruction The instruction to be found
		* @param max_size The maximum size that it will be parsing to
		* @return The offset of the found memory, 0 otherwise
		*/
		uint64_t find_mem(uint64_t base_addr, uint8_t* mem, size_t len, size_t max_size = 0x100);

		/**
		* Prints all instructions in the specified range
		* @param base_addr The base address of the code
		* @param max_size The maximum size that it will be parsing to
		*/
		void print_instructions_in_range(uint64_t base_addr, size_t max_size = 0x100);

		parse_info& get_parse_info()							{ return parsing_info; }

		// output functions

		/**
		* Adds a new lines to the global output using variadic parameters unpacking
		* @tparam T The type of the line (T == HEADER)
		* @param color The color of the current text
		* @param text The current text
		*/
		template <unsigned int T, typename... A, std::enable_if_t<T == dbg::HEADER>* = nullptr>
		void add_lines(uint16_t color, const std::string& text, A&&... args)
		{
			header.push_back(dbg::make_text(color, text));
			add_lines<T>(args...);
		}

		/**
		* Adds a new lines to the global output using variadic parameters unpacking
		* @tparam T The type of the line (T == FOOTER)
		* @param color The color of the current text
		* @param text The current text
		*/
		template <unsigned int T, typename... A, std::enable_if_t<T == dbg::FOOTER>* = nullptr>
		void add_lines(uint16_t color, const std::string& text, A&&... args)
		{
			footer.push_back(dbg::make_text(color, text));
			add_lines<T>(args...);
		}

		/**
		* Adds an include to the global output
		* @param val The include
		*/
		void add_include(const std::string& val);

		/**
		* Adds a define to the global output
		* @param name The define name
		* @param params The define parameters
		* @param def The definition itself
		*/
		void add_define(const std::string& name, const std::string& params, const std::string& def);

		/**
		* Adds a base address to the global output
		* @param val The base address name
		*/
		void add_base_address(const std::string& val)			{ base_address_name = val; }

		/**
		* Adds a comment to the next function
		* @param val The comment of the function
		*/
		void add_next_fn_comment(const std::string& val)		{ next_fn_comment = val; }

		const std::string& get_base_address_name()				{ return base_address_name; }

		/**
		* Adds a function to read a process memory
		* @param str The read operation
		*/
		void add_rpm_function(const std::string& str);

		/**
		* Begins the global pre-processing
		*/
		void begin();

		/**
		* Ends the global pre-processing
		*/
		void end();

		/**
		* Prints global content and all pseudo-code functions
		* @param copy_to_clipboard Specify whether to copy the output to the clipboard
		*/
		void print(bool copy_to_clipboard = false);
	};
};