#pragma once
#include <Windows.h>
#include <memory>
#include <string>
#include <sstream>
#include <Zydis/Zydis.h>
class Debugger;

class Disassembler
{
private:
	ZydisDecoder decoder;
	ZydisFormatter formatter;

	uintptr_t current_rip;
	Debugger* debugger;

	std::unique_ptr<ZydisDecodedInstruction[]> stack_trace;
private:
	ZydisDecodedInstruction Decode(uintptr_t rip);
	void SkipOverUntilInstruction(ZydisMnemonic instruction);
	std::string AsmToCPP(ZydisDecodedInstruction instruction);
public:
	Disassembler(Debugger* dbg);

	void Print_PEB();
	void Dump_ClientInfo();
	bool Init(uintptr_t address);
};

