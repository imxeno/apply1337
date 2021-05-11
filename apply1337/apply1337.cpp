#include <algorithm>
#include <iostream>
#include <vector>

#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#include "1337.h"
#include "utils.h"

#pragma comment(lib, "Shlwapi.lib")

std::vector<HMODULE> enum_process_modules(HANDLE process)
{
	DWORD byte_length;
	if (!EnumProcessModules(process, nullptr, 0, &byte_length))
		throw winapi_exception("EnumProcessModules", GetLastError());
	std::vector<HMODULE> handles(byte_length / sizeof(HMODULE));
	if (!EnumProcessModules(process, &handles[0], byte_length, &byte_length))
		throw winapi_exception("EnumProcessModules", GetLastError());
	return handles;
}

std::string get_module_name(HANDLE process_handle, HMODULE module_handle)
{
	std::vector<char> module_name(MAX_PATH);
	GetModuleFileNameExA(process_handle, module_handle, &module_name[0], module_name.size());
	if (GetLastError())
		throw winapi_exception("GetModuleFileNameEx", GetLastError());
	PathStripPathA(&module_name[0]);
	std::string handle_name(&module_name[0]);
	return handle_name;
}

bool module_name_equals(HANDLE process_handle, HMODULE module_handle, std::string target_name)
{
	std::string handle_name;
	try {
		handle_name = get_module_name(process_handle, module_handle);
	}
	catch (winapi_exception) { return false; }
	string_to_lower(handle_name);
	string_to_lower(target_name);
	return handle_name == target_name;
}

void patch_module(HANDLE process_handle, HMODULE module_handle, const std::vector<patch_info>& patches)
{
	for(auto patch : patches)
	{
		DWORD old_protection;
		const auto destination_byte_address = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(module_handle) + patch.rva);
		if(!VirtualProtectEx(process_handle, destination_byte_address, 1, PAGE_EXECUTE_READWRITE, &old_protection))
			throw winapi_exception("VirtualProtectEx", GetLastError());
		if(!WriteProcessMemory(process_handle, destination_byte_address, &patch.patched_byte, 1, nullptr))
			throw winapi_exception("WriteProcessMemory", GetLastError());
		if (!VirtualProtectEx(process_handle, destination_byte_address, 1, old_protection, &old_protection))
			throw winapi_exception("VirtualProtectEx", GetLastError());
	}
}

void usage()
{
	std::cout << "usage: apply1337.exe <pid> <patch_file>" << std::endl;
}

int main(int argc, char** argv)
{
	if(argc != 3)
	{
		usage();
		return 1;
	}

	try {
		const auto pid = strtol(argv[1], nullptr, 0);
		const std::string patch_file_name(argv[2]);

		const auto process = winapi_handle(OpenProcess(PROCESS_ALL_ACCESS, false, pid));

		if (!static_cast<HANDLE>(process))
		{
			throw winapi_exception("OpenProcess", GetLastError());
		}

		const auto patches = read_1337_file(patch_file_name);

		auto modules = enum_process_modules(process);
		for (auto* module_handle : modules)
		{
			for (const auto& patch : patches)
			{
				if (module_name_equals(process, module_handle, patch.name))
				{
					patch_module(process, module_handle, patch.patches);
				}
			}
		}
		
		std::cout << "Successfully applied " << patch_file_name << " to process " << pid << "!" << std::endl;
		
	} catch (const std::exception &exception)
	{
		std::cerr << exception.what() << std::endl;
		return 1;
	}

	return 0;
}
