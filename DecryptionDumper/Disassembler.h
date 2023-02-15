#pragma once
#include <Windows.h>
#include <string>
#include <sstream>
#include <map>
#include <regex>
#include <vector>
#include <Zydis/Zydis.h>

class Debugger;

struct InstructionTrace {
	ZydisDecodedInstruction instruction;
	std::map<ZydisRegister, uint32_t> last_modified; //uint32_t is the index in the instructin_trace list.
	std::map<int, uint32_t> rsp_stack_map; //uint32_t is the index in the instructin_trace list.
	std::map<int, uint32_t> rbp_stack_map; //uint32_t is the index in the instructin_trace list.
	uintptr_t rip;
	CONTEXT context;
	bool used;
};

class Disassembler
{
private:
	std::vector<ZydisRegister> ignore_trace; //this is for e.g the peb register. It will not warn if this register is not tracable

	ZydisDecoder decoder;
	ZydisFormatter formatter;

	uintptr_t current_rip;
	Debugger* debugger;

	uintptr_t client_base_end;
	uintptr_t bone_base_end;
private:
	ZydisRegister To64BitRegister(ZydisRegister reg) const;
	std::string Get64BitRegisterString(ZydisRegister reg) const;
	void GetModifiedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[8]) const;
	void GetAccessedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[8]) const;
	void AddRequiredInstruction(std::vector<InstructionTrace>& instruction_trace, std::vector<InstructionTrace>::iterator trace) const;
	ZydisDecodedInstruction Decode(uintptr_t rip) const;
	void SkipOverUntilInstruction(ZydisMnemonic instruction);
	void SkipUntilInstruction(ZydisMnemonic mnemonic);
	void RunUntilInstruction(ZydisMnemonic mnemonic);
	void GoToAddress(uintptr_t address);
	std::string AsmToCPP(ZydisDecodedInstruction instruction, uintptr_t rip, const char* stack_trace_name = 0) const;
	std::string GetInstructionText(ZydisDecodedInstruction& instruction) const;
	bool Print_PEB();
	void Print_Decryption(std::vector<InstructionTrace>& instruction_trace, ZydisRegister enc_reg, const char* print_indexing);
	void Trace_Decryption(std::vector<InstructionTrace>& instruction_trace, ZydisRegister enc_reg);
	void Load_DecryptionTrace(std::vector<InstructionTrace>& instruction_trace, uintptr_t decryption_end, ZydisMnemonic end_mnemonic);
	void Dump_Decryption(uintptr_t decryption_end, ZydisRegister enc_reg, const char* print_indexing, ZydisMnemonic end_mnemonic = ZydisMnemonic::ZYDIS_MNEMONIC_INVALID);

	uintptr_t Dump_Switch();
	void PrintRegisters();
public:
	Disassembler(Debugger* dbg);

	void Dump_ClientInfo_MW(uintptr_t address);
	void Dump_ClientInfo_Vanguard(uintptr_t address);
	void Dump_ClientBase(uintptr_t address);
	void Dump_BoneBase(uintptr_t address);
	void Dump_BoneIndex(uintptr_t address);

	void Dump_Offsets_MW();
};

