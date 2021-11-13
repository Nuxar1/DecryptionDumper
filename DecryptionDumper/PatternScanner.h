#pragma once
#include <Windows.h>
#include <string>
#include <vector>
class Debugger;

class PatternScanner
{
private:
	Debugger* debugger;
private:
	PIMAGE_SECTION_HEADER getCodeSection(LPVOID lpHeader);
	size_t replace_all(std::string& str, const std::string& from, const std::string& to);
	std::vector<int> pattern(std::string patternstring);
	std::vector<uintptr_t> find_pattern(const uint8_t* data, std::size_t data_size, const std::vector<int>& pattern, bool bSingle = false);
	std::vector<uintptr_t> AOBScan(std::string str_pattern, bool bSingle = false);
public:
	PatternScanner(Debugger* dbg);
	uintptr_t Find_Pattern(std::string pattern, bool last = false, uint32_t rIndex = 0, uintptr_t offset = 0, uintptr_t base_offset = 0, uintptr_t pre_base_offset = 0);
};

