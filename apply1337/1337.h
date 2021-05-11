#pragma once

#include <fstream>
#include <string>
#include <stdexcept>
#include <vector>

struct patch_info
{
    uint64_t rva;
    unsigned char original_byte;
    unsigned char patched_byte;
};

struct patched_module_info
{
    std::string name;
    std::vector<patch_info> patches;
};

inline uint64_t parse_hex(const std::string& str)
{
    char* end;
    const auto result = std::strtoull(str.c_str(), &end, 16);

    if (*end != '\0')
        throw std::runtime_error(("Not a hex number: \"" + str + "\"").c_str());
	
    return result;
}

inline std::vector<patched_module_info> read_1337_file(const std::string& filename)
{
    std::ifstream stream(filename);

    if (stream.bad())
        throw std::runtime_error(("Error opening file \"" + filename + "\".").c_str());

    std::vector<patched_module_info> patch_infos;

    patched_module_info patched_module;

    while (!stream.eof())
    {
        std::string line;

        std::getline(stream, line);

        if (line.find('>', 0) == 0)
        {
        	if(!patched_module.name.empty())
        	{
                patch_infos.emplace_back(patched_module);
        	}
            patched_module = patched_module_info({ line.substr(1) });
        }
        else
        {
            if (patched_module.name.empty())
                throw std::runtime_error("Invalid 1337 file - expected module name.");

            const auto colon_pos = line.find(':', 0);
            const auto arrow_pos = line.find("->", 0);

            if (colon_pos == -1 || arrow_pos == -1 || arrow_pos <= colon_pos)
                throw std::runtime_error("Invalid 1337 file.");

            const auto rva = parse_hex(line.substr(0, colon_pos));
            const auto original_byte = parse_hex(line.substr(colon_pos + 1, arrow_pos - colon_pos - 1));
            const auto patched_byte = parse_hex(line.substr(arrow_pos + 2));

            if (original_byte > 255 || patched_byte > 255)
                throw std::runtime_error("Invalid 1337 file.");

            patched_module.patches.push_back({
                rva,
                static_cast<unsigned char>(original_byte),
                static_cast<unsigned char>(patched_byte) });
        }
    }

    if (!patched_module.name.empty())
    {
        patch_infos.emplace_back(patched_module);
    }

    return patch_infos;
}