#include "Disassembler.h"
#include "Debugger.h"
#include <regex>
#include "ContextRestorer.h"

Disassembler::Disassembler(Debugger* dbg) : debugger(dbg)
{
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

ZydisDecodedInstruction Disassembler::Decode(uintptr_t rip)
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
			|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_AND
			|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MUL) { //ZydisMnemonic::ZYDIS_MNEMONIC_AND or ZYDIS_MNEMONIC_MUL-> operand 0 is implicit ... for whatever reason..
			if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER) {
				if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_READ)
					reg[i] = To64BitRegister(instruction.operands[i].reg.value);
			}
			else if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY) {
				if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_READ || (instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_LEA && i > 0)) {
					if (instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RIP)
						reg[i] = To64BitRegister(instruction.operands[i].mem.base);
					if (instruction.operands[i].mem.index)
						reg[i + 4] = To64BitRegister(instruction.operands[i].mem.index);
				}
			}
		}
	}
}

std::string Disassembler::AsmToCPP(ZydisDecodedInstruction instruction, uintptr_t rip) const
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
				// MOV  RAX,qword ptr [DAT_04f67224]
				else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
				{
					ss << Get64BitRegisterString(r1) << " = " << "read<uintptr_t>(baseModuleAddr + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address << ")";
				}
				// MOV  RAX, 
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
		else
			ss << "???MOZZD";

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
		else
			ss << "-????";
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
		else
			ss << "+???";
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
			ss << "?? &";
		}

		break;
	case ZYDIS_MNEMONIC_XOR:
		if (instruction.operands[1].mem.disp.value != 0)
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
			ss << "MUL??";
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
		else
		{
			ss << Get64BitRegisterString(r1) << " " << "?????";
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

void Disassembler::Print_PEB()
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
			break;
		}
		i++;
	}
}

void Disassembler::AddRequiredInstruction(std::vector<InstructionTrace>& instruction_trace, std::vector<InstructionTrace>::iterator trace, std::vector<bool>& used_instructions) const
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
				if (!used_instructions[trace_index]) {
					used_instructions[trace_index] = true;
					AddRequiredInstruction(instruction_trace, (instruction_trace.begin() + trace_index), used_instructions);
				}
			}
			catch (const std::exception&)
			{

			}
		}
	}
}

void Disassembler::Dump_Decryption(ZydisMnemonic end_mnemonic, ZydisRegister enc_reg, const char* print_indexing)
{
	std::vector<InstructionTrace> instruction_trace(0x200);

	std::map<ZydisRegister, uint32_t> last_modified;
	std::map<int, uint32_t> rsp_stack_map;
	std::map<int, uint32_t> rbp_stack_map;
	uint32_t i = 0;

	{
		ZydisDecodedInstruction instruction = Decode(current_rip);
		while (instruction.mnemonic != end_mnemonic)
		{
			if (i >= 0x200)break;

			uintptr_t rip = debugger->SingleStep();

			instruction_trace[i] = { instruction, last_modified, rsp_stack_map, rbp_stack_map, current_rip };

#ifdef DEBUG
			char DisassembledString[256];
			ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);
			printf("read line %d: %s\n", i, DisassembledString);
#endif
			ZydisRegister modified[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
			ZydisRegister accessed[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
			GetModifiedRegisters(instruction, modified);
			GetAccessedRegisters(instruction, accessed);
			for (size_t j = 0; j < 8; j++)
			{
				if (modified[j] != ZydisRegister::ZYDIS_REGISTER_NONE)
					last_modified[modified[j]] = i;
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
			i++;
		}
	}

	std::vector<bool> is_instruction_used(0x200, enc_reg == ZydisRegister::ZYDIS_REGISTER_MAX_VALUE); //ZydisRegister::ZYDIS_REGISTER_MAX_VALUE means don't filter. used for dumping switch.
	for (int32_t j = i - 1; j >= 0; j--)
	{
		if (instruction_trace[j].instruction.operands[0].reg.value == enc_reg)
		{
			is_instruction_used[j] = true;
			AddRequiredInstruction(instruction_trace, (instruction_trace.begin() + j), is_instruction_used);
			break;
		}
	}
	for (size_t j = 0; j < i; j++)
	{
		if (is_instruction_used[j]) {
			char DisassembledString[256];
			ZydisFormatterFormatInstruction(&formatter, &(instruction_trace[j].instruction), DisassembledString, sizeof(DisassembledString), 0);

			std::string cpp_code;
			if (instruction_trace[j].instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP && instruction_trace[j].instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_PUSHFQ) {
				try
				{
					cpp_code = AsmToCPP(instruction_trace[instruction_trace[j].rsp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)].instruction, instruction_trace[j].rip);
					char TraceDisassembledString[256];
					ZydisFormatterFormatInstruction(&formatter, &(instruction_trace[instruction_trace[j].rsp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)].instruction), TraceDisassembledString, sizeof(TraceDisassembledString), 0);
					if (cpp_code.size() > 1)
						printf("\t\t%s; \t\t//%s : %RSP_%X\n", cpp_code.c_str(), TraceDisassembledString, instruction_trace[j].instruction.operands[1].mem.disp.value);
					instruction_trace[j].instruction.operands[1] = instruction_trace[instruction_trace[j].rsp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)].instruction.operands[0];
				}
				catch (const std::exception&) {}
			}
			else if (instruction_trace[j].instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP && instruction_trace[j].instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_PUSHFQ) {
				try {
					cpp_code = AsmToCPP(instruction_trace[instruction_trace[j].rbp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)].instruction, instruction_trace[j].rip);
					char TraceDisassembledString[256];
					ZydisFormatterFormatInstruction(&formatter, &(instruction_trace[instruction_trace[j].rbp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)].instruction), TraceDisassembledString, sizeof(TraceDisassembledString), 0);
					if (cpp_code.size() > 1)
						printf("\t\t%s; \t\t//%s : %RSP_%X\n", cpp_code.c_str(), TraceDisassembledString, instruction_trace[j].instruction.operands[1].mem.disp.value);
					instruction_trace[j].instruction.operands[1] = instruction_trace[instruction_trace[j].rbp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)].instruction.operands[0];
				}
				catch (const std::exception&) {}
			}
			cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();

			if (cpp_code.size() > 1)
				printf("%s%s; \t\t//%s\n", print_indexing, cpp_code.c_str(), DisassembledString);
		}
	}
}

void Disassembler::Dump_ClientInfo(uintptr_t address)
{
	ContextRestorer restorer(debugger); //restores the context when function is done.

	current_rip = address;
	printf("uintptr_t decrypt_client_info()\n{\n");
	printf("\tuint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rdi = 0, rsi = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;\n");

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	printf("\t%s;\n", AsmToCPP(encrypted_read_instruction, current_rip).c_str());

	Print_PEB();
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	Dump_Decryption(ZydisMnemonic::ZYDIS_MNEMONIC_CALL, encrypted_read_instruction.operands[0].reg.value, "\t");
	printf("\treturn %s;\n}\n\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
}

void Disassembler::Dump_ClientBase(uintptr_t address)
{
	ContextRestorer restorer(debugger);

	current_rip = address;
	printf("uintptr_t decrypt_client_base(uintptr_t client_info)\n{\n");
	printf("\tuint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rdi = 0, rsi = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;\n");

	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	std::string enc_client_info = AsmToCPP(encrypted_read_instruction, current_rip);
	printf("\t%s;\n", std::regex_replace(enc_client_info, std::regex("rbx"), "client_info").c_str());

	Print_PEB();
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	Dump_Decryption(ZydisMnemonic::ZYDIS_MNEMONIC_AND, ZydisRegister::ZYDIS_REGISTER_MAX_VALUE, "\t");

	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_CMP);
	ZydisRegister switch_register = To64BitRegister(Decode(current_rip).operands[0].reg.value);
	uintptr_t switch_address = current_rip; //important that this is exactly here!
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

		Dump_Decryption(ZydisMnemonic::ZYDIS_MNEMONIC_MOVSXD, encrypted_read_instruction.operands[0].reg.value, "\t\t");

		printf("\t\treturn %s;\n\t}\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
	}
	printf("\t}\n}\n");
}

void Disassembler::Dump_BoneIndex(uintptr_t address)
{
	ContextRestorer restorer(debugger);

	current_rip = address;
	printf("uintptr_t get_bone_index(uint32_t bone_index)\n{\n");
	printf("\tuint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rdi = 0, rsi = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;\n");

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_TEST);
	ZydisRegister return_register = Decode(current_rip).operands[0].reg.value;
	current_rip = address;

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	ZydisDecodedInstruction instruction = Decode(current_rip);
	std::string enc_client_info = AsmToCPP(instruction, current_rip);
	printf("\t%s;\n", std::regex_replace(enc_client_info, std::regex("rdi"), "bone_index").c_str());

	current_rip = debugger->SingleStep();
	if (debugger->exception_hit) {
		current_rip += instruction.length; //if exception is caused the ptr is not advanced.
		debugger->SetRIP(current_rip);
		debugger->exception_hit = false;
	}
	Dump_Decryption(ZydisMnemonic::ZYDIS_MNEMONIC_TEST, return_register, "\t");
	printf("\treturn %s;\n}", Get64BitRegisterString(return_register).c_str());
}

void Disassembler::Dump_BoneBase(uintptr_t address)
{
	ContextRestorer restorer(debugger);

	current_rip = address;
	printf("uintptr_t decrypt_bone_base()\n{\n");
	printf("\tuint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rdi = 0, rsi = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;\n");

	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	ZydisDecodedInstruction encrypted_read_instruction = Decode(current_rip);
	printf("\t%s;\n", AsmToCPP(encrypted_read_instruction, current_rip).c_str());

	Print_PEB();
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	Dump_Decryption(ZydisMnemonic::ZYDIS_MNEMONIC_AND, ZydisRegister::ZYDIS_REGISTER_MAX_VALUE, "\t");

	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_CMP);
	ZydisRegister switch_register = To64BitRegister(Decode(current_rip).operands[0].reg.value);
	uintptr_t switch_address = current_rip; //important that this is exactly here!
	SkipUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_ADD);
	ZydisRegister base_register = To64BitRegister(Decode(current_rip).operands[1].reg.value);

	printf("\t%s &= 0xF;\n\tGlobals::boneSwitch = %s;\n\tswitch(%s) {\n", Get64BitRegisterString(switch_register).c_str(), Get64BitRegisterString(switch_register).c_str(), Get64BitRegisterString(switch_register).c_str());
	for (uint32_t i = 0; i < 16; i++)
	{
		printf("\tcase %d:\n\t{\n", i);

		current_rip = switch_address;
		debugger->SetRIP(current_rip);
		debugger->SetRegisterValue(switch_register, i);
		debugger->SetRegisterValue(base_register, debugger->base_address);

		Dump_Decryption(ZydisMnemonic::ZYDIS_MNEMONIC_TEST, encrypted_read_instruction.operands[0].reg.value, "\t\t");

		printf("\t\treturn %s;\n\t}\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
	}
	printf("\t}\n}\n");
}