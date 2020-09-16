#pragma once

#ifndef UTILS_H
#define UTILS_H

#include <Windows.h>

#include <sstream>
#include <string>
#include <iostream>

namespace utils
{
	/**
	* Copies a given string to the clipboard
	* @param val The string to copy to the clipboard
	*/
	static inline void to_clipboard(const std::string& val)
	{
		OpenClipboard(0);
		EmptyClipboard();

		if (HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, val.size() + 1); hg)
		{
			memcpy(GlobalLock(hg), val.c_str(), val.size() + 1);
			GlobalUnlock(hg);
			SetClipboardData(CF_TEXT, hg);
			CloseClipboard();
			GlobalFree(hg);
		}
		else CloseClipboard();
	}

	/**
	* Converts the __int64 to hex formatted string
	* @param val The __int64 integer value
	* @return the String that contains the value in hex format
	*/
	static inline std::string to_hex(int64_t val)
	{
		std::stringstream stream; stream << std::hex << std::uppercase << val;
		return stream.str();
	}

	/**
	* Gets the string containing the variable type from the size and unsigned type
	* @param unsigned_ Specify whether the type is unsigned
	* @return The string that contains the type of the variable
	*/
	static inline std::string get_type_from_size(bool unsigned_, size_t size)
	{
		std::string unsigned_str = unsigned_ ? "unsigned " : "",
					type_str;

		switch (size)
		{
		case 1: type_str = "__int8";  break;
		case 2: type_str = "__int16"; break;
		case 4: type_str = "__int32"; break;
		case 8: type_str = "__int64"; break;
		}

		return unsigned_str + type_str;
	}
	
	/**
	* Gets the string cointaining the type postfix from the size, 
	* usually for instructions like _umulX or _rotlX/_rotrX
	* @param unsigned_ Specify whether the type is unsigned
	* @return The string that contains the corresponding postfix
	*/
	static inline std::string get_type_postfix_from_size(size_t size)
	{
		switch (size)
		{
		case 1: return "8";
		case 2: return "16";
		case 4: return "32";
		case 8: return "64";
		}

		return "UNKNOWN";
	}
};

#endif