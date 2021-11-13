#pragma once
#include <Windows.h>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <Zydis/Zydis.h>

class Debugger;

struct InstructionTrace {
	ZydisDecodedInstruction instruction;
	std::map<ZydisRegister, uint32_t> last_modified; //uint32_t is the index in the instructin_trace list.
	std::map<int, uint32_t> rsp_stack_map; //uint32_t is the index in the instructin_trace list.
	std::map<int, uint32_t> rbp_stack_map; //uint32_t is the index in the instructin_trace list.
	uintptr_t rip;
};

class Disassembler
{
private:
	ZydisDecoder decoder;
	ZydisFormatter formatter;

	uintptr_t current_rip;
	Debugger* debugger;
private:
	ZydisRegister To64BitRegister(ZydisRegister reg) const;
	std::string Get64BitRegisterString(ZydisRegister reg) const;
	void GetModifiedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[4]) const;
	void GetAccessedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[4]) const;
	void AddRequiredInstruction(std::vector<InstructionTrace>& instruction_trace, std::vector<InstructionTrace>::iterator trace, std::vector<bool>& used_instructions) const;
	ZydisDecodedInstruction Decode(uintptr_t rip);
	void SkipOverUntilInstruction(ZydisMnemonic instruction);
	void SkipUntilInstruction(ZydisMnemonic mnemonic);
	std::string AsmToCPP(ZydisDecodedInstruction instruction, uintptr_t rip) const;
	void Print_PEB();
	void Dump_Decryption(ZydisMnemonic end_mnemonic, ZydisRegister enc_reg, const char* print_indexing);
public:
	Disassembler(Debugger* dbg);

	void Dump_ClientInfo(uintptr_t address);
	void Dump_ClientBase(uintptr_t address);
	void Dump_BoneIndex(uintptr_t address);
	void Dump_BoneBase(uintptr_t address);
};

