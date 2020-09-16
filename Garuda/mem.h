#pragma once

#ifndef MEM_H
#define MEM_H

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include "debug.h"

#define IN_RANGE(x,a,b) (x >= a && x <= b) 
#define GET_BITS(x)		(IN_RANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (IN_RANGE(x,'0','9') ? x - '0' : 0))
#define GET_BYTE(x)		(GET_BITS(x[0]) << 4 | GET_BITS(x[1]))

namespace mem
{
	inline HANDLE process_handle = nullptr;
	inline uint32_t pid = 0;

	inline MODULEINFO process_info {};
	inline uint8_t* process_memory = nullptr;
	inline uint32_t process_size = 0;

	void destroy()
	{
		delete[] process_memory;

		CloseHandle(process_handle);
	}

	uint32_t get_process_id(const wchar_t* name)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		uint32_t lpid = 0;

		if (Process32First(snapshot, &entry))
		{
			do
			{
				if (!wcscmp(entry.szExeFile, name))
				{
					lpid = entry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);

		return (pid = lpid);
	}

	MODULEINFO get_module(const wchar_t* name)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

		MODULEENTRY32 entry;
		entry.dwSize = sizeof(MODULEENTRY32);

		MODULEINFO mod_info;

		do
		{
			if (!wcscmp(entry.szModule, name))
			{
				mod_info = { entry.modBaseAddr, entry.modBaseSize, nullptr };
				break;
			}
		} while (Module32Next(snapshot, &entry));

		CloseHandle(snapshot);

		return mod_info;
	}

	void rpm_by_pages(uintptr_t base, void* basic_buffer, size_t size)
	{
		for (size_t page_offset = 0; page_offset < size; page_offset += 0x1000)
			ReadProcessMemory(process_handle, (uint8_t*)base + page_offset, (uint8_t*)basic_buffer + page_offset, 0x1000, nullptr);
	}

	template <typename T>
	T rpm(uintptr_t base)
	{
		T basic_buffer;
		if (ReadProcessMemory(process_handle, (void*)base, &basic_buffer, sizeof(T), nullptr))
			return basic_buffer;
		return {};
	}

	bool cmp_byte_array(uintptr_t base_addr, uint8_t* sig, uint8_t* mask)
	{
		for (; *mask; ++mask, ++sig, ++base_addr)
		{
			if (*mask == '\?')
				continue;

			if (*(uint8_t*)base_addr != *sig)
				return false;
		}

		return true;
	}

	uintptr_t find_sig(uintptr_t base_addr, uintptr_t img_size, uint8_t* sig, uint8_t* mask)
	{
		uintptr_t process_end = base_addr + (img_size - strlen(reinterpret_cast<const char*>(sig))),
			first_byte = sig[0];

		auto original_base = base_addr;

		for (; base_addr < process_end; ++base_addr)
		{
			if (*(uint8_t*)base_addr != first_byte)
				continue;

			if (cmp_byte_array(base_addr, sig, mask))
				return base_addr;
		}

		return 0;
	}

	uintptr_t scan_sig(uintptr_t base, uint32_t size, const char* ida_sig)
	{
		int ida_sig_len = strlen(ida_sig);
		if (ida_sig_len <= 1)
			return 0;

		uint8_t sig[1024]{ 0 },
			mask[1024]{ 0 };

		int it = 0;

		while (*ida_sig != '\0')
		{
			if (*ida_sig == '?')
			{
				sig[it] = (uint8_t)'\x00';
				mask[it] = (uint8_t)'\?';
			}
			else
			{
				sig[it] = (uint8_t)GET_BYTE(ida_sig);
				mask[it] = (uint8_t)'x';
			}

			if (*(unsigned short*)ida_sig == '\?\?' || *ida_sig != '?')
			{
				if ((*(ida_sig + 1) == '\0') || (*(ida_sig + 2) == '\0'))
					break;
				ida_sig += 3;
			}
			else
			{
				if ((*(ida_sig + 1) == '\0'))
					break;
				ida_sig += 2;
			}

			++it;
		}

		return find_sig((uintptr_t)process_memory, size, sig, mask);
	}

	bool read_process(const wchar_t* mod_name)
	{
		dbg::println(dbg::WHITE, "-------------------------------");

		process_info = get_module(mod_name);

		if (!process_info.lpBaseOfDll || !process_info.SizeOfImage)
			return false;

		if (!process_memory || !process_size)
		{
			process_memory = new uint8_t[process_size = process_info.SizeOfImage];

			dbg::println(dbg::WHITE, "Reading process...");

			rpm_by_pages((uintptr_t)process_info.lpBaseOfDll, process_memory, process_size);

			dbg::println(dbg::WHITE, "Base: 0x%llx", process_info.lpBaseOfDll);
			dbg::println(dbg::WHITE, "Size: 0x%x", process_info.SizeOfImage);

			return true;
		}

		return false;
	}

	template <typename F>
	uintptr_t scan_internal(const wchar_t* mod_name, const char* sig, const F& fn, bool subtract_local_base = true)
	{
		return fn(scan_sig((uintptr_t)process_info.lpBaseOfDll, process_info.SizeOfImage, sig)) - (subtract_local_base ? (uint64_t)process_memory : 0);
	}
};

#endif