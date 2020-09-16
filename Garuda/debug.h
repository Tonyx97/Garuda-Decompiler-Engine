#pragma once

#ifndef DEBUG_H
#define DEBUG_H

#include "utils.h"

namespace dbg
{
	static constexpr auto SINGLE_TEXT_MAX_LENGTH = 0x100;

	enum eColor : unsigned short
	{
		BLACK = 0x0,
		DARK_BLUE = 0x1,
		DARK_GREEN = 0x2,
		DARK_CYAN = 0x3,
		DARK_RED = 0x4,
		DARK_PURPLE = 0x5,
		DARK_YELLOW = 0x6,
		GREY = 0x7,
		DARK_GREY = 0x8,
		BLUE = 0x9,
		GREEN = 0xA,
		CYAN = 0xB,
		RED = 0xC,
		PURPLE = 0xD,
		YELLOW = 0xE,
		WHITE = 0xF,
	};

	enum eTextSection
	{
		HEADER,
		FOOTER,
	};

	class basic_buffer
	{
	private:

		char* data = nullptr;

	public:

		basic_buffer(size_t max_len)	{ data = new char[max_len](); }
		~basic_buffer()					{ delete[] data; }
		
		char* get()						{ return data; }

		friend std::ostream& operator << (std::ostream& os, const basic_buffer& buffer)
		{
			std::cout << buffer.data;
			return os;
		}
	};

	template <typename... A>
	std::string format(const std::string& txt, A... args)
	{
		basic_buffer buffer(SINGLE_TEXT_MAX_LENGTH);
		sprintf_s(buffer.get(), SINGLE_TEXT_MAX_LENGTH, txt.c_str(), std::forward<A>(args)...);
		return std::string(buffer.get());
	}

	struct color
	{
		color(uint16_t value)	{ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), value); }
		~color()				{ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xF); }
	};

	class text
	{
	private:

		std::string data;

		uint16_t color_id;

		int alignment = 0;

		bool nl;

	public:

		text(uint16_t color_id, const std::string& data, bool nl, int alignment = 0) : data(data), color_id(color_id), nl(nl), alignment(alignment) {}

		void print() { std::cout << *this; }

		friend std::ostream& operator << (std::ostream& os, const text& t)
		{
			auto align = [&](int width)
			{
				std::cout.setf(std::ios_base::left, std::ios_base::adjustfield);
				std::cout.fill(' ');
				std::cout.width(width);
			};

			if (t.alignment > 0)
				align(t.alignment);

			color c(t.color_id);
			std::cout << t.data << (t.nl ? "\n" : "");
			return os;
		}
	};

	template <typename... A>
	static inline text make_text(uint16_t color, const std::string& txt, A&&... args)
	{
		return dbg::text(color, dbg::format(txt, args...), false);
	}

	template <typename... A>
	static inline text make_text_nl(uint16_t color, const std::string& txt, A&&... args)
	{
		return dbg::text(color, dbg::format(txt, args...), true);
	}

	template <typename... A>
	static inline text make_text_align(uint16_t color, const std::string& txt, int alignment, A&&... args)
	{
		return dbg::text(color, dbg::format(txt, args...), false, alignment);
	}

	template <typename... A>
	static inline void print(uint16_t color_id, const std::string& txt, A&&... args)
	{
		color c(color_id);
		std::cout << format(txt, args...);
	}

	template <typename... A>
	static inline void println(uint16_t color_id, const std::string& txt, A&&... args)
	{
		color c(color_id);
		std::cout << format(txt, args...) << std::endl;
	}
};

#endif