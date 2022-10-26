#include "Disassembler.h"
#include "Debugger.h"
#include "PatternScanner.h"
#include <regex>
#include "ContextRestorer.h"

Disassembler::Disassembler(Debugger* dbg) : debugger(dbg)
{
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

ZydisDecodedInstruction Disassembler::Decode(uintptr_t rip) const
{
	ZydisDecodedInstruction instruction;
	BYTE bRead[20];
	debugger->read_array(rip, bRead, 20);

	if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, bRead, 20,
		&instruction))) {
	}
	return instruction;
}

void Disassembler::SkipOverUntilInstruction(ZydisMnemonic mnemonic)
{
	ZydisDecodedInstruction instruction = Decode(current_rip);
	while (instruction.mnemonic != mnemonic)
	{
		current_rip += instruction.length;
		instruction = Decode(current_rip);
	}
	current_rip += instruction.length;
	debugger->SetRIP(current_rip);
}

void Disassembler::SkipUntilInstruction(ZydisMnemonic mnemonic)
{
	ZydisDecodedInstruction instruction = Decode(current_rip);
	while (instruction.mnemonic != mnemonic)
	{
		current_rip += instruction.length;
		instruction = Decode(current_rip);
	}
	debugger->SetRIP(current_rip);
}

void Disassembler::RunUntilInstruction(ZydisMnemonic mnemonic)
{
	ZydisDecodedInstruction instruction = Decode(current_rip);
	while (instruction.mnemonic != mnemonic)
	{

		uintptr_t rip = debugger->SingleStep();
		if (debugger->exception_hit) {
			current_rip += instruction.length; //if exception is caused the ptr is not advanced.
			debugger->SetRIP(current_rip);
			debugger->exception_hit = false;
		}
		current_rip = rip;
		instruction = Decode(current_rip);
	}
}

void Disassembler::GoToAddress(uintptr_t address)
{
	current_rip = address;
	debugger->SetRIP(current_rip);
}

ZydisRegister Disassembler::To64BitRegister(ZydisRegister reg) const
{
	if (ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) == 32)
	{
		ZyanI16 regID = ZydisRegisterGetId(reg);
		reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regID);
	}
	return reg;
}

std::string Disassembler::Get64BitRegisterString(ZydisRegister reg) const
{
	return ZydisRegisterGetString(To64BitRegister(reg));
}

void Disassembler::GetModifiedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[8]) const
{
	for (uint32_t i = 0; i < instruction.operand_count; i++)
	{
		if (instruction.operands[i].visibility == ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_EXPLICIT
			|| To64BitRegister(instruction.operands[i].reg.value) == ZydisRegister::ZYDIS_REGISTER_RAX //RAX is implicit? idk lol
			|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_AND
			|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MUL) { //ZydisMnemonic::ZYDIS_MNEMONIC_AND or ZYDIS_MNEMONIC_MUL-> operand 0 is implicit ... for whatever reason..
			if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER) {
				if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_WRITE)
					reg[i] = To64BitRegister(instruction.operands[i].reg.value);
			}
			else if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY) {
				if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_WRITE)
					reg[i] = To64BitRegister(instruction.operands[i].mem.base);
			}
		}
	}
}

void Disassembler::GetAccessedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[8]) const
{
	for (uint32_t i = 0; i < instruction.operand_count; i++)
	{
		if (instruction.operands[i].visibility == ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_EXPLICIT
			|| To64BitRegister(instruction.operands[i].reg.value) == ZydisRegister::ZYDIS_REGISTER_RAX //RAX is implicit? idk lol
			|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_AND
			|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MUL) { //ZydisMnemonic::ZYDIS_MNEMONIC_AND or ZYDIS_MNEMONIC_MUL-> operand 0 is implicit ... for whatever reason..
			if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER) {
				if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_READ)
					reg[i] = To64BitRegister(instruction.operands[i].reg.value);
			}
			else if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY) {
				if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_READ || (instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_LEA && i > 0)) {
					if (instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RIP && instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RBP && instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RSP)
						reg[i] = To64BitRegister(instruction.operands[i].mem.base);
					if (instruction.operands[i].mem.index)
						reg[i + 4] = To64BitRegister(instruction.operands[i].mem.index);
				}
			}
		}
	}
}

std::string Disassembler::AsmToCPP(ZydisDecodedInstruction instruction, uintptr_t rip, const char* stack_trace_name) const
{
	std::stringstream ss;
	ZydisRegister r1 = instruction.operands[0].reg.value;
	ZydisRegister r2 = instruction.operands[1].reg.value;
	ZydisRegister r3 = instruction.operands[2].reg.value;
	ZydisRegister r4 = instruction.operands[3].reg.value;
	switch (instruction.mnemonic)
	{
	case ZYDIS_MNEMONIC_LEA:
		//LEA	r16/32,	m
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP) {
			ss << Get64BitRegisterString(r1) << " = " << "baseModuleAddr";
			if ((rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address != 0)
				ss << " + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address;
		}
		// LEA   RAX,[RAX + RCX * 0x2]
		else if (instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.scale != 0)
		{
			if (instruction.operands[1].mem.base != ZydisRegister::ZYDIS_REGISTER_NONE)
				ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(instruction.operands[1].mem.base) << " + " << Get64BitRegisterString(instruction.operands[1].mem.index) << " * " << (int)instruction.operands[1].mem.scale;
			else
				ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(instruction.operands[1].mem.index) << " * " << (int)instruction.operands[1].mem.scale << " + 0x" << instruction.operands[1].mem.disp.value;
		}
		else
		{
			ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value;
		}
		break;
	case ZYDIS_MNEMONIC_MOV:
		if (instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
		{
			switch (instruction.operands[1].type)
			{
			case ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER:
				ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(r2);
				break;
			case ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY:
				if (instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
				{
					ss << Get64BitRegisterString(r1) << " = " << "peb";
				}
				else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
				{
					ss << Get64BitRegisterString(r1) << " = " << "read<uintptr_t>(baseModuleAddr + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address << ")";
				}
				else if (stack_trace_name) {
					ss << Get64BitRegisterString(r1) << " = " << stack_trace_name;
				}
				else if (instruction.operands[1].mem.disp.has_displacement)
				{
					ss << Get64BitRegisterString(r1) << " = read<uintptr_t>(" << Get64BitRegisterString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
				}
				else
				{
					ss << Get64BitRegisterString(r1) << " = read<uintptr_t>(" << Get64BitRegisterString(instruction.operands[1].mem.base) << ")";
				}
				break;
			case ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE:
				if (instruction.operands[1].imm.is_signed)
					ss << Get64BitRegisterString(r1) << " = " << "0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
				else
					ss << Get64BitRegisterString(r1) << " = " << "0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
				break;
			default:
				break;
			}
		}
		//Register to Register

		break;

	case ZYDIS_MNEMONIC_MOVZX:
	case ZYDIS_MNEMONIC_MOVSX:
		// MOVSX    R15D,word ptr [RCX + R11*0x1 + 0x4dfb360]
		if (instruction.operand_count == 2 && instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.disp.value != 0)
		{
			ss << Get64BitRegisterString(r1) << " = read<uint16_t>(" << std::uppercase << Get64BitRegisterString(instruction.operands[1].mem.base) << " + " << Get64BitRegisterString(instruction.operands[1].mem.index) << " * "
				<< (int)instruction.operands[1].mem.scale << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
		}
		else if (stack_trace_name) {
			ss << Get64BitRegisterString(r1) << " = " << stack_trace_name;
		}
		else
			ss << GetInstructionText(instruction);

		break;
	case ZYDIS_MNEMONIC_ROR:
		ss << Get64BitRegisterString(r1) << " = _rotr64(" << Get64BitRegisterString(r1) << ", 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u << ")";
		break;
	case ZYDIS_MNEMONIC_ROL:
		ss << Get64BitRegisterString(r1) << " = _rotl64(" << Get64BitRegisterString(r1) << ", 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u << ")";
		break;
	case ZYDIS_MNEMONIC_SHR:
		ss << Get64BitRegisterString(r1) << " >>= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
		break;
	case ZYDIS_MNEMONIC_SHL:
		ss << Get64BitRegisterString(r1) << " <<= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
		break;
	case ZYDIS_MNEMONIC_SUB:
		//Reg to Reg
		if (instruction.operand_count == 3 && r2 != 0)
		{
			ss << Get64BitRegisterString(r1) << " -= " << Get64BitRegisterString(r2);
		}
		else if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << Get64BitRegisterString(r1) << " -= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << Get64BitRegisterString(r1) << " -= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		else if (stack_trace_name) {
			ss << Get64BitRegisterString(r1) << " -= " << stack_trace_name;
		}
		else
			ss << GetInstructionText(instruction);
		break;
	case ZYDIS_MNEMONIC_ADD:
		//Reg to Reg
		if (instruction.operand_count == 3 && r2 != 0)
		{
			ss << Get64BitRegisterString(r1) << " += " << std::uppercase << Get64BitRegisterString(r2);
		}
		//ADD   RCX, 0x236d1de3
		else if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << Get64BitRegisterString(r1) << " += 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << Get64BitRegisterString(r1) << " += 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		else if (stack_trace_name) {
			ss << Get64BitRegisterString(r1) << " += " << stack_trace_name;
		}
		else
			ss << GetInstructionText(instruction);
		break;
	case ZYDIS_MNEMONIC_AND:
		//Reg to Value
		if (instruction.operands[1].imm.value.s != 0 && instruction.operands[0].reg.value != 0)
		{
			if (instruction.operands[1].imm.value.s != 0xffffffffc0000000) {
				if (instruction.operands[1].imm.is_signed) {
					ss << Get64BitRegisterString(r1) << " " << " &= 0x" << std::hex << instruction.operands[1].imm.value.s;
				}
				else {
					ss << Get64BitRegisterString(r1) << " " << " &= 0x" << std::hex << instruction.operands[1].imm.value.u;
				}
			}
			else
				ss << Get64BitRegisterString(r1) << " = 0";
		}
		//Reg to Reg
		else if (instruction.operands[0].reg.value != 0 && r2 != 0)
		{
			ss << Get64BitRegisterString(r1) << " &= " << Get64BitRegisterString(r2);
		}
		else
		{
			ss << GetInstructionText(instruction);
		}

		break;
	case ZYDIS_MNEMONIC_XOR:
		if (stack_trace_name) {
			ss << Get64BitRegisterString(r1) << " ^= " << stack_trace_name;
		}
		else if (instruction.operands[1].mem.disp.value != 0)
		{
			ss << Get64BitRegisterString(r1) << " ^= " << "read<uintptr_t>(baseModuleAddr + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address << ")";
		}
		else
		{
			ss << Get64BitRegisterString(r1) << " ^= " << Get64BitRegisterString(r2);
		}

		break;
	case ZYDIS_MNEMONIC_BSWAP:
		ss << Get64BitRegisterString(r1) << " = _byteswap_uint64(" << Get64BitRegisterString(r1) << ")";
		break;
	case ZYDIS_MNEMONIC_NOT:
		ss << Get64BitRegisterString(r1) << " = ~" << Get64BitRegisterString(r1);
		break;
	case ZYDIS_MNEMONIC_MUL:
		if (instruction.operand_count == 4)
		{
			ss << Get64BitRegisterString(r2) << std::uppercase << " = _umul128(" << Get64BitRegisterString(r2) << ", " << Get64BitRegisterString(r1) << ", (uintptr_t*)&" << Get64BitRegisterString(r3) << ")";
		}
		else
			ss << GetInstructionText(instruction);
		break;
	case ZYDIS_MNEMONIC_IMUL:
		//Reg to Reg
		if ((instruction.operand_count == 2 || instruction.operand_count == 3) && r2 != 0)
		{
			ss << Get64BitRegisterString(r1) << " *= " << Get64BitRegisterString(r2);
		}
		//Value
		else if (instruction.operand_count == 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << Get64BitRegisterString(r1) << " *= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << Get64BitRegisterString(r1) << " *= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		//IMUL  RAX,qword ptr [RCX + 0xb]
		else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.disp.has_displacement)
		{
			if (instruction.operands[1].mem.base != ZYDIS_REGISTER_RSP && instruction.operands[1].mem.base != ZYDIS_REGISTER_RBP)
				ss << Get64BitRegisterString(r1) << " *= " << "read<uintptr_t>(" << Get64BitRegisterString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
		}
		//IMUL  RAX,RAX,0x25a3
		else if (instruction.operand_count == 4 && instruction.operands[0].reg.value != 0 && r2 != 0 && instruction.operands[2].imm.value.s != 0)
		{
			ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(r2) << " * 0x" << std::hex << std::uppercase << instruction.operands[2].imm.value.s;
		}
		else if (stack_trace_name) {
			ss << Get64BitRegisterString(r1) << " *= " << stack_trace_name;
		}
		else
		{
			ss << GetInstructionText(instruction);
		}
		break;
	case ZYDIS_MNEMONIC_CALL:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_NOP:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_CMP:
	case ZYDIS_MNEMONIC_TEST:
	case ZYDIS_MNEMONIC_JZ:
		break;
	default:
		//ss << "//?? " << std::hex << rip - debugger->base_address;
		break;
	}
	return ss.str();
}

std::string Disassembler::GetInstructionText(ZydisDecodedInstruction& instruction) const {
	char DisassembledString[256];
	ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);
	return std::string(DisassembledString);
}

bool Disassembler::Print_PEB()
{
	ZydisDecodedInstruction instruction;
	bool checkNotPeb = false;

	int i = 0;


	while (i < 15)
	{
		instruction = Decode(current_rip);
		current_rip += instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
		{
			char DisassembledString[256];
			ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);

			ZydisDecodedInstruction next_instruction = Decode(current_rip);
			if (next_instruction.mnemonic == ZYDIS_MNEMONIC_NOT)
				printf("\t%s; \t\t//%s\n", ((std::string)ZydisRegisterGetString(instruction.operands[0].reg.value) + "= ~Peb").c_str(), DisassembledString);
			else
				printf("\t%s; \t\t//%s\n", ((std::string)ZydisRegisterGetString(instruction.operands[0].reg.value) + " = Peb").c_str(), DisassembledString);
			ignore_trace.push_back(instruction.operands[0].reg.value);
			return true;;
		}
		i++;
	}
	return false;
}

void Disassembler::AddRequiredInstruction(std::vector<InstructionTrace>& instruction_trace, std::vector<InstructionTrace>::iterator trace) const
{
#ifdef DEBUG
	char DisassembledString[256];
	ZydisFormatterFormatInstruction(&formatter, &(trace->instruction), DisassembledString, sizeof(DisassembledString), 0);
	printf("needed line %d: %s\n", trace - instruction_trace.begin(), DisassembledString);
#endif
	ZydisRegister accessed[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
	GetAccessedRegisters(trace->instruction, accessed);
	for (size_t j = 0; j < 8; j++)
	{
		if (accessed[j] != ZydisRegister::ZYDIS_REGISTER_NONE && trace->instruction.operands[1].imm.value.s != 0xffffffffc0000000) {
			try
			{
				uint32_t trace_index = trace->last_modified.at(accessed[j]);
				if (!instruction_trace[trace_index].used) {
					instruction_trace[trace_index].used = true;
					AddRequiredInstruction(instruction_trace, (instruction_trace.begin() + trace_index));
				}
			}
			catch (const std::exception&)
			{
				if (std::find(ignore_trace.begin(), ignore_trace.end(), accessed[j]) == ignore_trace.end()) {
					uintptr_t offset = (To64BitRegister(accessed[j]) - ZydisRegister::ZYDIS_REGISTER_RAX);
					if (*(&trace->context.Rax + offset) == debugger->base_address)
						printf("\t%s = moduleBaseAddr;", Get64BitRegisterString(accessed[j]).c_str());
					else
						printf("\033[1;31m//failed to trace. Register value: %s = %p. base: %p It's possibly wrong\033[0m\n", Get64BitRegisterString(accessed[j]).c_str(), *(&trace->context.Rax + offset), debugger->base_address);
				}
			}
		}
	}
}

void Disassembler::Print_Decryption(std::vector<InstructionTrace>& instruction_trace, ZydisRegister enc_reg, const char* print_indexing)
{
	for (size_t j = 0; j < instruction_trace.size(); j++)
	{
		if (enc_reg == ZydisRegister::ZYDIS_REGISTER_MAX_VALUE || instruction_trace[j].used) {
			std::string DisassembledString = GetInstructionText(instruction_trace[j].instruction);

			if (instruction_trace[j].instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP && instruction_trace[j].instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_PUSHFQ) {
				try {
					auto stack_trace = instruction_trace[instruction_trace[j].rsp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)];
					auto stack_instruction = stack_trace.instruction;

					char tmp_var[100];
					sprintf_s(tmp_var, 100, "RSP_0x%llX", instruction_trace[j].instruction.operands[1].mem.disp.value);
					printf("%suintptr_t %s;\n", print_indexing, tmp_var);

					std::string trace_code = AsmToCPP(stack_instruction, stack_trace.rip);
					std::string TraceDisassembledString = GetInstructionText(stack_instruction);
					trace_code = std::regex_replace(trace_code, std::regex(Get64BitRegisterString(stack_instruction.operands[0].reg.value)), tmp_var);
					if (trace_code.size() > 1)
						printf("\033[1;34m\t\t%s; \t\t//%s : %RSP+0x%llX\n\033[0m", trace_code.c_str(), TraceDisassembledString.c_str(), instruction_trace[j].instruction.operands[1].mem.disp.value);
					instruction_trace[j].instruction.operands[1] = stack_instruction.operands[0];

					std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();
					cpp_code = cpp_code.replace(cpp_code.find("=") + 2, cpp_code.size(), tmp_var);
					if (cpp_code.size() > 1)
						printf("%s%s; \t\t//%s\n", print_indexing, cpp_code.c_str(), DisassembledString.c_str());
				}
				catch (const std::exception&) { // didn't find stack trace. use base;
					printf("\033[1;31m%s%s; \t\t//%s -- didn't find trace -> use base\033[0m\n", print_indexing, AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip, "baseModuleAddr").c_str(), DisassembledString.c_str());
					continue;
				}
			}
			else if (instruction_trace[j].instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP && instruction_trace[j].instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_PUSHFQ) {
				try {
					auto stack_trace = instruction_trace[instruction_trace[j].rbp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)];
					auto stack_instruction = stack_trace.instruction;

					char tmp_var[100];
					sprintf_s(tmp_var, 100, "RSP_0x%llX", instruction_trace[j].instruction.operands[1].mem.disp.value);
					printf("%suintptr_t %s;\n", print_indexing, tmp_var);

					std::string trace_code = AsmToCPP(stack_instruction, stack_trace.rip);
					std::string TraceDisassembledString = GetInstructionText(stack_instruction);
					trace_code = std::regex_replace(trace_code, std::regex(Get64BitRegisterString(stack_instruction.operands[0].reg.value)), tmp_var);
					if (trace_code.size() > 1)
						printf("\033[1;34m\t\t%s; \t\t//%s : %RBP+0x%llX\n\033[0m", trace_code.c_str(), TraceDisassembledString.c_str(), instruction_trace[j].instruction.operands[1].mem.disp.value);
					instruction_trace[j].instruction.operands[1] = stack_instruction.operands[0];

					std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();
					cpp_code = cpp_code.replace(cpp_code.find("=") + 2, cpp_code.size(), tmp_var);
					if (cpp_code.size() > 1)
						printf("%s%s; \t\t//%s\n", print_indexing, cpp_code.c_str(), DisassembledString.c_str());
				}
				catch (const std::exception&) { // didn't find stack trace. use base;
					printf("\033[1;31m%s%s; \t\t//%s -- didn't find trace -> use base\033[0m\n", print_indexing, AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip, "baseModuleAddr").c_str(), DisassembledString.c_str());
					continue;
				}
			}
			else {
				std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();

				if (cpp_code.size() > 1)
					printf("%s%s; \t\t//%s\n", print_indexing, cpp_code.c_str(), DisassembledString.c_str());
				else
					printf("%s\033[1;31m//failed to translate: %s\033[0m\n", print_indexing, DisassembledString.c_str());
			}
		}
	}
}

void Disassembler::Trace_Decryption(std::vector<InstructionTrace>& instruction_trace, ZydisRegister enc_reg)
{
	for (int32_t j = instruction_trace.size() - 1; j >= 0; j--)
	{
		if (instruction_trace[j].instruction.operands[0].reg.value == enc_reg)
		{
			instruction_trace[j].used = true;
			AddRequiredInstruction(instruction_trace, (instruction_trace.begin() + j));
			break;
		}
	}
}

void Disassembler::Load_DecryptionTrace(std::vector<InstructionTrace>& instruction_trace, uintptr_t decryption_end, ZydisMnemonic end_mnemonic)
{
	std::map<ZydisRegister, uint32_t> last_modified;
	std::map<int, uint32_t> rsp_stack_map;
	std::map<int, uint32_t> rbp_stack_map;
	instruction_trace.reserve(200);

	ZydisDecodedInstruction instruction = Decode(current_rip);
	while (current_rip != decryption_end && (end_mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_INVALID || instruction.mnemonic != end_mnemonic))
	{
		uintptr_t rip = debugger->SingleStep();

		instruction_trace.push_back({ instruction, last_modified, rsp_stack_map, rbp_stack_map, current_rip, debugger->GetContext(), false });

#ifdef DEBUG
		char DisassembledString[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);
		printf("read line %d: %s\n", instruction_trace.size() - 1, DisassembledString);
#endif
		ZydisRegister modified[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
		ZydisRegister accessed[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
		GetModifiedRegisters(instruction, modified);
		GetAccessedRegisters(instruction, accessed);
		for (size_t j = 0; j < 8; j++)
		{
			if (modified[j] != ZydisRegister::ZYDIS_REGISTER_NONE)
				last_modified[modified[j]] = instruction_trace.size() - 1;
		}
		if (instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP) {
			for (size_t j = 0; j < 8; j++)
			{
				if (accessed[j] != ZydisRegister::ZYDIS_REGISTER_NONE) {
					try
					{
						rsp_stack_map[instruction.operands[0].mem.disp.value] = last_modified.at(accessed[j]);
					}
					catch (const std::exception&)
					{

					}
				}
			}
		}
		if (instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP) {
			for (size_t j = 0; j < 8; j++)
			{
				if (accessed[j] != ZydisRegister::ZYDIS_REGISTER_NONE) {
					try
					{
						rbp_stack_map[instruction.operands[0].mem.disp.value] = last_modified.at(accessed[j]);
					}
					catch (const std::exception&)
					{

					}
				}
			}
		}

		current_rip = rip;
		if (debugger->exception_hit) {
			current_rip += instruction.length; //if exception is caused the ptr is not advanced.
			debugger->SetRIP(current_rip);
			debugger->exception_hit = false;
		}

		instruction = Decode(current_rip);
	}
}

void Disassembler::Dump_Decryption(uintptr_t decryption_end, ZydisRegister enc_reg, const char* print_indexing, ZydisMnemonic end_mnemonic)
{
	std::vector<InstructionTrace> instruction_trace;

	Load_DecryptionTrace(instruction_trace, decryption_end, end_mnemonic);

	Trace_Decryption(instruction_trace, enc_reg);

	Print_Decryption(instruction_trace, enc_reg, print_indexing);
}

void Disassembler::Dump_Switch()
{
	printf("\tuint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;\n");

	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
	std::string enc_client_info = AsmToCPP(encrypted_read_instruction, current_rip);
	printf("\t%s;\n", std::regex_replace(enc_client_info, std::regex(Get64BitRegisterString(encrypted_read_instruction.operands[1].mem.base)), "client_info").c_str());
	printf("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

	Print_PEB();

	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	ZydisDecodedInstruction jmp_to_end = Decode(current_rip);
	uintptr_t decryption_end = jmp_to_end.operands[0].imm.value.u + current_rip + jmp_to_end.length;
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	Dump_Decryption(0, ZydisRegister::ZYDIS_REGISTER_MAX_VALUE, "\t", ZydisMnemonic::ZYDIS_MNEMONIC_AND);

	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_CMP);
	ZydisRegister switch_register = To64BitRegister(Decode(current_rip).operands[0].reg.value);
	uintptr_t switch_address = current_rip;
	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_ADD);
	ZydisRegister base_register = To64BitRegister(Decode(current_rip).operands[1].reg.value);

	printf("\t%s &= 0xF;\n\tGlobals::clientSwitch = %s;\n\tswitch(%s) {\n", Get64BitRegisterString(switch_register).c_str(), Get64BitRegisterString(switch_register).c_str(), Get64BitRegisterString(switch_register).c_str());
	for (uint32_t i = 0; i < 16; i++)
	{
		printf("\tcase %d:\n\t{\n", i);

		current_rip = switch_address;
		debugger->SetRIP(current_rip);
		debugger->SetRegisterValue(switch_register, i);
		debugger->SetRegisterValue(base_register, debugger->base_address);

		Dump_Decryption(decryption_end, encrypted_read_instruction.operands[0].reg.value, "\t\t");

		printf("\t\treturn %s;\n\t}\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
	}
	printf("\t}\n}\n");
}

void Disassembler::Dump_ClientInfo_MW(uintptr_t address)
{
	ContextRestorer restorer(debugger);
	if (!address) {
		printf("//ClientInfo pattern scan failed.\n");
		return;
	}

	current_rip = address;
	printf("uintptr_t decrypt_client_info()\n{\n");
	printf("\tuint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;\n");

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
	printf("\t%s;\n", AsmToCPP(encrypted_read_instruction, current_rip).c_str());
	printf("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

	if (!Print_PEB()) {
		printf("\t//Failed to find peb. exiting\n}\n");
		return;
	}
	RunUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	ZydisDecodedInstruction jmp_to_end = Decode(current_rip);
	uintptr_t decryption_end = jmp_to_end.operands[0].imm.value.u + current_rip + jmp_to_end.length;
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	Dump_Decryption(decryption_end, encrypted_read_instruction.operands[0].reg.value, "\t");
	printf("\treturn %s;\n}\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
	ignore_trace.clear();
}

void Disassembler::Dump_ClientInfo_Vanguard(uintptr_t address)
{
	ContextRestorer restorer(debugger);
	if (!address) {
		printf("//ClientInfo pattern scan failed.\n");
		return;
	}

	current_rip = address;
	printf("uintptr_t decrypt_client_info()\n{\n");
	printf("\tuint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;\n");

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
	printf("\t%s;\n", AsmToCPP(encrypted_read_instruction, current_rip).c_str());
	printf("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

	RunUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	ZydisDecodedInstruction jmp_to_end = Decode(current_rip);
	uintptr_t decryption_end = jmp_to_end.operands[0].imm.value.u + current_rip + jmp_to_end.length;
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	Dump_Decryption(decryption_end, encrypted_read_instruction.operands[0].reg.value, "\t");
	printf("\treturn %s;\n}\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
	ignore_trace.clear();
}

void Disassembler::Dump_ClientBase(uintptr_t address)
{
	ContextRestorer restorer(debugger);
	if (!address) {
		printf("//ClientBase pattern scan failed.\n");
		return;
	}

	current_rip = address;

	printf("uintptr_t decrypt_client_base(uintptr_t client_info)\n{\n");
	printf("\tuint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;\n");

	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
	std::string enc_client_info = AsmToCPP(encrypted_read_instruction, current_rip);
	printf("\t%s;\n", std::regex_replace(enc_client_info, std::regex(Get64BitRegisterString(encrypted_read_instruction.operands[1].mem.base)), "client_info").c_str());
	printf("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

	Dump_Switch();
	ignore_trace.clear();
}

void Disassembler::Dump_BoneBase(uintptr_t address)
{
	ContextRestorer restorer(debugger);
	if (!address) {
		printf("//BoneBase pattern scan failed.\n");
		return;
	}

	current_rip = address;
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	printf("uintptr_t decrypt_bone_base(uintptr_t client_info)\n{\n");
	printf("\tuint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;\n");

	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
	printf("\t%s;\n", AsmToCPP(encrypted_read_instruction, current_rip).c_str());
	printf("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

	Dump_Switch();
	ignore_trace.clear();
}

void Disassembler::Dump_BoneIndex(uintptr_t address)
{
	ContextRestorer restorer(debugger);
	if (!address) {
		printf("//BoneIndex pattern scan failed.\n");
		return;
	}

	current_rip = address;
	printf("uintptr_t get_bone_index(uint32_t bone_index)\n{\n");
	printf("\tuint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;\n");

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_TEST);
	ZydisRegister return_register = Decode(current_rip).operands[0].reg.value;
	current_rip = address;

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

	ZydisDecodedInstruction instruction = Decode(current_rip);
	printf("\t%s = bone_index;\n", Get64BitRegisterString(instruction.operands[1].reg.value).c_str());
	printf("\t%s;\n", AsmToCPP(instruction, current_rip).c_str());
	ignore_trace.push_back(instruction.operands[0].reg.value);

	current_rip = debugger->SingleStep();
	if (debugger->exception_hit) {
		current_rip += instruction.length; //if exception is caused the ptr is not advanced.
		debugger->SetRIP(current_rip);
		debugger->exception_hit = false;
	}
	Dump_Decryption(0, return_register, "\t", ZydisMnemonic::ZYDIS_MNEMONIC_TEST);
	printf("\treturn %s;\n}", Get64BitRegisterString(return_register).c_str());
	ignore_trace.clear();
}
void Disassembler::Dump_Offsets_MW()
{
	printf("namespace offsets {\n");
	{
		uintptr_t addr = debugger->scanner->Find_Pattern("33 05 ? ? ? ? 89 44 24 34 48 8B 44 24 ? F2 0F 10 50");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto ref_def_ptr = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address - 0x4);
		else
			printf("\t\033[1;31mconstexpr auto refdef = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 8D 0D ? ? ? ? 48 8B 0C C1 48 8B 01 FF 90 ? ? ? ? 8B 40 78 83 E0 07 48 83 C4 28 C3");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto name_array = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address);
		else
			printf("\t\033[1;31mconstexpr auto name_array = 0x0;\033[0m\n");
		printf("\tconstexpr auto name_array_pos = 0x4C70;\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 8D 05 ? ? ? ? 48 03 F8 80 BF ? ? ? ? ? 75 18 48 8B 07");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto loot_ptr = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address - 0x4);
		else
			printf("\t\033[1;31mconstexpr auto loot = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 8B 05 ? ? ? ? 48 8B 7C 24 ? 48 05 ? ? ? ? 48 69 CA ? ? ? ? 48 03 C1 C3");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto camera_base = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address);
		else
			printf("\t\033[1;31mconstexpr auto camera_base = 0x0;\033[0m\n");
		printf("\tconstexpr auto camera_pos = 0x1D8;\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 83 BB ? ? ? ? ? 0F 84 ? ? ? ? 83 BB ? ? ? ? ? 0F 84 ? ? ? ? 8B 8B ? ? ? ? 8B C1 D1 E8 A8 01 0F 85 ? ? ? ? 8B 83 ? ? ? ? C1 E8 02 A8 01 0F 85");
		auto instruction = Decode(addr);
		if (instruction.operands[0].mem.disp.has_displacement)
			printf("\tconstexpr auto local_index = 0x%llX;\n", instruction.operands[0].mem.disp.value);
		else
			printf("\t\033[1;31mconstexpr auto local_index = 0x0;\033[0m\n");
		printf("\tconstexpr auto local_index_pos = 0x1FC;\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("41 8B 52 0C 4D 8D 4A 04 4D 8D 42 08 4C 89 95 ? ? ? ? 8B C2 4C 89 8D") - 0x9;//DEAD
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RSI && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto recoil = 0x%llX;\n", instruction.operands[1].mem.disp.value);
		else
			printf("\t\033[1;31mconstexpr auto recoil = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("8B 15 ?? ?? ?? ?? 41 B9 08 00 00 00 8B 0D"); //3B 1D ? ? ? ? 8B E8 74 17 41 B8 ? ? ? ?
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto game_mode = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address);
		else
			printf("\t\033[1;31mconstexpr auto game_mode = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 8D 15 ?? ?? ?? ?? 8B D8 44 8B D7");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto weapon_definitions = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address);
		else
			printf("\t\033[1;31mconstexpr auto weapon_definitions = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 8B 1D ?? ?? ?? ?? BA FF FF FF FF 48 8B CF E8 ?? ?? ?? ?? 48 8B D0 48 85 C0 74 28");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto distribute = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address);
		else
			printf("\t\033[1;31mconstexpr auto distribute = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("80 BF ? ? ? ? ? 74 20 80 BF ? ? ? ? ? 74 17 3B 87");
		auto instruction = Decode(addr);
		if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RDI && instruction.operands[0].mem.disp.has_displacement)
			printf("\tconstexpr auto visible_offset = 0x%llX;\n", instruction.operands[0].mem.disp.value);
		else
			printf("\t\033[1;31mconstexpr auto visible_offset = 0x0;\033[0m\n");
	}

	{
		uintptr_t addr = debugger->scanner->Find_Pattern("48 8D 05 ?? ?? ?? ?? 48 89 87 90 00 00 00 F3 0F 11 87 1C 01 00 00");
		auto instruction = Decode(addr);
		if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
			printf("\tconstexpr auto visible = 0x%llX;\n", (addr + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address);
		else
			printf("\t\033[1;31mconstexpr auto visible = 0x0;\033[0m\n");
	}

	printf("\tnamespace player {\n");
	{
		{
			uintptr_t addr = debugger->scanner->Find_Pattern("48 69 D3 ? ? ? ? 48 03 96 ? ? ? ? 83 BA ? ? ? ? ? 75 68 83 BA ? ? ? ? ? 75 5F 48 81 C2 ? ? ? ? 4C 8D 44 24");
			auto instruction = Decode(addr);
			if (instruction.operands[2].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE)
				printf("\t\tconstexpr auto size = 0x%llX;\n", instruction.operands[2].imm.value);
			else
				printf("\t\t\033[1;31mconstexpr auto index_struct_size = 0x0;\033[0m\n");
		}

		{
			uintptr_t addr = debugger->scanner->Find_Pattern("C7 87 ? ? ? ? ? ? ? ? C7 87 ? ? ? ? ? ? ? ? 41 89 9E ? ? ? ? 41 89 9E ? ? ? ? 41 C7 86 ? ? ? ? ? ? ? ? 41 89 B6 ? ? ? ? 41 C7 86 ? ? ? ? ? ? ? ? 41 C7 86 ? ? ? ? ? ? ? ? 41 C7 86");
			auto instruction = Decode(addr);
			if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RDI && instruction.operands[0].mem.disp.has_displacement)
				printf("\t\tconstexpr auto valid = 0x%llX;\n", instruction.operands[0].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto valid = 0x0;\033[0m\n");
		}

		{
			uintptr_t addr = debugger->scanner->Find_Pattern("4C 89 BB ? ? ? ? C7 83 ? ? ? ? ? ? ? ? C7 83 ? ? ? ? ? ? ? ? 48 8B 05");
			auto instruction = Decode(addr);
			if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RBX && instruction.operands[0].mem.disp.has_displacement)
				printf("\t\tconstexpr auto pos = 0x%llX;\n", instruction.operands[0].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto pos = 0x0;\033[0m\n");
		}

		{
			uintptr_t addr = debugger->scanner->Find_Pattern("3B 81 ? ? ? ? 75 0E B0 01 48 81 C4 ? ? ? ? 5F 5E 5B 5D C3");
			auto instruction = Decode(addr);
			if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RCX && instruction.operands[1].mem.disp.has_displacement)
				printf("\t\tconstexpr auto team = 0x%llX;\n", instruction.operands[1].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto team = 0x0;\033[0m\n");
		}

		{
			uintptr_t addr = debugger->scanner->Find_Pattern("0F 48 F0 83 BF ? ? ? ? ? 75 0A F3 0F 10 35 ? ? ? ? EB 08");
			auto instruction = Decode(addr);
			instruction = Decode(addr + instruction.length);
			if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RDI && instruction.operands[0].mem.disp.has_displacement)
				printf("\t\tconstexpr auto stance = 0x%llX;\n", instruction.operands[0].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto stance = 0x0;\033[0m\n");
		}

		{
			uintptr_t addr = debugger->scanner->Find_Pattern("49 8D A8 ? ? ? ? 44 0F B7 F2 48 8B D9 33 D2 48 8B CD 49 8B F9 4D 8B F8 E8");//DEAD
			auto instruction = Decode(addr);
			if (instruction.operands[1].mem.base == ZYDIS_REGISTER_R8 && instruction.operands[1].mem.disp.has_displacement)
				printf("\t\tconstexpr auto weapon_index = 0x%llX;\n", instruction.operands[1].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto weapon_index = 0x0;\033[0m\n");
		}

		{
			uintptr_t addr = debugger->scanner->Find_Pattern("C7 83 ? ? ? ? ? ? ? ? C7 83 ? ? ? ? ? ? ? ? E8 ? ? ? ? 44 0F B6 C6 48 8B D5 48 8B CF E8 ? ? ? ? 48 89 83");
			auto instruction = Decode(addr);
			if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RBX && instruction.operands[0].mem.disp.has_displacement)
				printf("\t\tconstexpr auto dead_1 = 0x%llX;\n", instruction.operands[0].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto dead_1 = 0x0;\033[0m\n");
			instruction = Decode(addr + instruction.length);
			if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RBX && instruction.operands[0].mem.disp.has_displacement)
				printf("\t\tconstexpr auto dead_2 = 0x%llX;\n", instruction.operands[0].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto dead_2 = 0x0;\033[0m\n");
		}
	}
	printf("\t}\n");

	printf("\tnamespace bone {\n");
	{
		{
			uintptr_t addr = debugger->scanner->Find_Pattern("F2 0F 10 86 ? ? ? ? F2 0F 11 85 ? ? ? ? 8B 86 ? ? ? ? 89 85 ? ? ? ? 80 BE ? ? ? ? ? 0F 84");
			auto instruction = Decode(addr);
			if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RSI && instruction.operands[1].mem.disp.has_displacement)
				printf("\t\tconstexpr auto bone_base = 0x%llX;\n", instruction.operands[1].mem.disp.value);
			else
				printf("\t\t\033[1;31mconstexpr auto bone_base = 0x0;\033[0m\n");
			printf("\t\tconstexpr auto size = 0x150;\n");
		}
	}
	printf("\t}\n");

	printf("}\n");
}