#pragma once
#include <Windows.h>
#include <string>
#include <vector>
class Debugger;

class PatternScanner
{
private:
	Debugger* debugger;
	PVOID lpCodeSection;
	DWORD nSize;
private:
	PIMAGE_SECTION_HEADER getCodeSection(LPVOID lpHeader);
	void Init();
public:
	PatternScanner(Debugger* dbg);
	uintptr_t Find_Pattern(const char* pattern, bool last = false, uint32_t rIndex = 0, uintptr_t offset = 0, uintptr_t base_offset = 0, uintptr_t pre_base_offset = 0);
};

