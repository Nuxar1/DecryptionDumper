#include "Disassembler.h"
#include "Debugger.h"
#include <map>

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

std::string Disassembler::AsmToCPP(ZydisDecodedInstruction instruction)
{
	std::stringstream ss;
	ZydisRegister r1 = instruction.operands[0].reg.value;
	ZydisRegister r2 = instruction.operands[1].reg.value;
	ZydisRegister r3 = instruction.operands[2].reg.value;
	ZydisRegister r4 = instruction.operands[3].reg.value;
	switch (instruction.mnemonic)
	{
	case ZYDIS_MNEMONIC_LEA:
	case ZYDIS_MNEMONIC_MOV:

		//RAX,0x4b2bd3eca30d631
		if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << ZydisRegisterGetString(r1) << " = " << "0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << ZydisRegisterGetString(r1) << " = " << "0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		//Peb
		else if (instruction.operand_count >= 2 && instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
		{
			ss << ZydisRegisterGetString(r1) << " = " << "peb";
		}
		// LEA   RAX,[RAX + RCX*0x2]
		else if (instruction.operand_count >= 2 && instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.scale != 0)
		{
			ss << ZydisRegisterGetString(r1) << " = " << ZydisRegisterGetString(r2) << " + " << ZydisRegisterGetString(instruction.operands[1].mem.index) << " * " << (int)instruction.operands[1].mem.scale;
		}
		//R9,qword ptr [DAT_04f67224]
		else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
		{
			if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
				ss << ZydisRegisterGetString(r1) << " = " << "debugger->read<uintptr_t>(baseModuleAddr + 0x" << std::hex << std::uppercase << (current_rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address << ")";
			else
			{
				if ((current_rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address != 0)
					ss << ZydisRegisterGetString(r1) << " = " << "(baseModuleAddr + 0x" << std::hex << std::uppercase << (current_rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address << ")";
				else
					ss << ZydisRegisterGetString(r1) << " = " << "baseModuleAddr";
			}
		}

		else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.base != ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
		{
			if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
				ss << ZydisRegisterGetString(r1) << " = debugger->read<uintptr_t>(" << ZydisRegisterGetString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
			else
				ss << ZydisRegisterGetString(r1) << " = " << ZydisRegisterGetString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value;
		}
		else if (instruction.operand_count == 2 && r2 != 0 && instruction.operands[0].reg.value != 0 && instruction.operands[1].mem.disp.value == 0 && instruction.operands[1].imm.value.s == 0 && instruction.operands[0].imm.value.s == 0)
		{
			ss << ZydisRegisterGetString(r1) << " = " << ZydisRegisterGetString(r2);//<< CurrentIndex;
		}
		//Register to Register
		else
			ss << "?? MOV";

		break;

	case ZYDIS_MNEMONIC_SHR:

		ss << ZydisRegisterGetString(r1) << " >>= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
		break;
	case ZYDIS_MNEMONIC_MOVZX:
	case ZYDIS_MNEMONIC_MOVSX:
		// MOVSX    R15D,word ptr [RCX + R11*0x1 + 0x4dfb360]
		if (instruction.operand_count == 2 && instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.disp.value != 0)
		{
			ss << ZydisRegisterGetString(r1) << " = debugger->read<uint16_t>(" << std::uppercase << ZydisRegisterGetString(r2) << " + " << ZydisRegisterGetString(instruction.operands[1].mem.index) << " * "
				<< (int)instruction.operands[1].mem.scale << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
		}
		else
			ss << "???MOZZD";

		break;
	case ZYDIS_MNEMONIC_ROL:
		ss << ZydisRegisterGetString(r1) << " = _rotl64(" << ZydisRegisterGetString(r1) << ", 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u << ")";
		break;
	case ZYDIS_MNEMONIC_SHL:
		ss << ZydisRegisterGetString(r1) << " <<= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;

		break;
	case ZYDIS_MNEMONIC_SUB:
		//Reg to Reg
		if (instruction.operand_count == 3 && r2 != 0)
		{
			ss << ZydisRegisterGetString(r1) << " -= " << ZydisRegisterGetString(r2);
		}
		else if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << ZydisRegisterGetString(r1) << " -= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << ZydisRegisterGetString(r1) << " -= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		else
			ss << "-????";

		break;
	case ZYDIS_MNEMONIC_ADD:
		//Reg to Reg
		if (instruction.operand_count == 3 && r2 != 0)
		{
			ss << ZydisRegisterGetString(r1) << " += " << std::uppercase << ZydisRegisterGetString(r2);
		}
		//ADD   RCX, 0x236d1de3
		else if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << ZydisRegisterGetString(r1) << " += 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << ZydisRegisterGetString(r1) << " += 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		else
			ss << "+???";

		break;
	case ZYDIS_MNEMONIC_AND:

		//Reg to Value
		if (instruction.operands[1].imm.value.s != 0 && instruction.operands[0].reg.value != 0)
		{
			if (instruction.operands[1].imm.is_signed) {
				if (instruction.operands[1].imm.value.s != 0xffffffffc0000000)
					ss << ZydisRegisterGetString(r1) << " " << " &= 0x" << std::hex << instruction.operands[1].imm.value.s;
				else
					ss << ZydisRegisterGetString(r1) << " " << " = 0";
			}
			else {
				if (instruction.operands[1].imm.value.s != 0xffffffffc0000000)
					ss << ZydisRegisterGetString(r1) << " " << " &= 0x" << std::hex << instruction.operands[1].imm.value.u;
				else
					ss << ZydisRegisterGetString(r1) << " " << " = 0";
			}
		}
		//Reg to Reg
		else if (instruction.operands[0].reg.value != 0 && r2 != 0)
		{
			ss << ZydisRegisterGetString(r1) << " &= " << ZydisRegisterGetString(r2);
		}
		else
		{
			ss << "?? &";
		}

		break;

	case ZYDIS_MNEMONIC_XOR:
		if (instruction.operands[1].mem.disp.value != 0)
		{
			ss << ZydisRegisterGetString(r1) << " ^= " << "debugger->read<uintptr_t>(baseModuleAddr + 0x" << std::hex << std::uppercase << (current_rip + instruction.operands[1].mem.disp.value + instruction.length) - debugger->base_address << ")/*maybe wrong*/";
		}
		else
		{
			ss << ZydisRegisterGetString(r1) << " ^= " << ZydisRegisterGetString(r2);
		}

		break;																																								  //		  this is new
	case ZYDIS_MNEMONIC_BSWAP:																																				  //				| 
		ss << ZydisRegisterGetString(r1) << "= _byteswap_uint64(" << ZydisRegisterGetString(r1) << ")"; // for example rax = _byteswap_uint64(rax)
		break;
	case ZYDIS_MNEMONIC_NOT:
		ss << ZydisRegisterGetString(r1) << " = (~" << ZydisRegisterGetString(r1) << ")";
		break;
	case ZYDIS_MNEMONIC_MUL:
		if (instruction.operand_count == 4)
		{
			ss << ZydisRegisterGetString(r2) << std::uppercase << " = _umul128(" << ZydisRegisterGetString(r2) << ", " << ZydisRegisterGetString(r1) << ", (uintptr_t*)&" << ZydisRegisterGetString(r3) << ")";
		}
		else
			ss << "MUL??";
		break;
	case ZYDIS_MNEMONIC_IMUL:
		//Reg to Reg
		if ((instruction.operand_count == 2 || instruction.operand_count == 3) && r2 != 0)
		{
			ss << ZydisRegisterGetString(r1) << " *= " << ZydisRegisterGetString(r2);
		}
		//Value
		else if (instruction.operand_count == 2 && instruction.operands[1].imm.value.s != 0)
		{
			if (instruction.operands[1].imm.is_signed)
				ss << ZydisRegisterGetString(r1) << " *= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
			else
				ss << ZydisRegisterGetString(r1) << " *= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
		}
		//IMUL  RAX,qword ptr [RCX + 0xb]
		else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.disp.has_displacement)
		{
			if (instruction.operands[1].mem.base != ZYDIS_REGISTER_RSP && instruction.operands[1].mem.base != ZYDIS_REGISTER_RBP)
				ss << ZydisRegisterGetString(r1) << " *= " << "debugger->read<uintptr_t>(" << ZydisRegisterGetString(r2) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
			else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RSP)
				ss << "error: 3  (stack)";//ss << ZydisRegisterGetString(r1) << " *= 0x" << std::hex << std::uppercase << debugger->read<uintptr_t>(c.Rsp + instruction.operands[1].mem.disp.value);
			else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RBP)
				ss << "error: 4";//ss << ZydisRegisterGetString(r1) << " *= 0x" << std::hex << std::uppercase << debugger->read<uintptr_t>(c.Rbp + instruction.operands[1].mem.disp.value);
			else
				ss << "error: 5";//ss << ZydisRegisterGetString(r1) << " *= 0x" << std::hex << std::uppercase << debugger->read<uintptr_t>(c.Rip + instruction.operands[1].mem.disp.value);
		}
		//IMUL  RAX,RAX,0x25a3
		else if (instruction.operand_count == 4 && instruction.operands[0].reg.value != 0 && r2 != 0 && instruction.operands[2].imm.value.s != 0)
		{
			ss << ZydisRegisterGetString(r1) << " = " << ZydisRegisterGetString(r2) << " * 0x" << std::hex << std::uppercase << instruction.operands[2].imm.value.s;
		}
		else
		{
			ss << ZydisRegisterGetString(r1) << " " << "?????";
		}
		break;
	case ZYDIS_MNEMONIC_ROR:
		ss << "_rotr64(" << ZydisRegisterGetString(r1) << ", 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u << ")";
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
		ss << "?? " << current_rip - debugger->base_address;
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
			instruction = Decode(current_rip);
			if (instruction.mnemonic == ZYDIS_MNEMONIC_NOT)
				printf("%s%s%s%s", ZydisRegisterGetString(instruction.operands[0].reg.value), "= ~", ZydisRegisterGetString(instruction.operands[0].reg.value), ";");
			else
				printf("%s%s", ZydisRegisterGetString(instruction.operands[0].reg.value), " = Peb;\n");
			break;
		}
		i++;
	}
}

void Disassembler::Dump_ClientInfo()
{
	Print_PEB();
	SkipOverUntilInstruction(ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
	std::map<int, ZydisDecodedInstruction> rsp_stack_map;
	std::map<int, ZydisDecodedInstruction> rbp_stack_map;
	stack_trace = std::make_unique<ZydisDecodedInstruction[]>(0x1000);
	uint32_t i = 0;

	ZydisDecodedInstruction instruction = Decode(current_rip);
	while (instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_CALL)
	{
		stack_trace[i] = instruction;

		current_rip = debugger->SingleStep();
		if (debugger->exception_hit) {
			current_rip += instruction.length; //if exception is caused the ptr is not advanced.
			debugger->SetRIP(current_rip);
			debugger->exception_hit = false;
		}
		

		char DisassembledString[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);

		printf("%30s  :   %50s", DisassembledString, AsmToCPP(instruction).c_str());
		if (instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP)
			rsp_stack_map[instruction.operands[0].mem.disp.value] = instruction;
		else if(instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP)
			rbp_stack_map[instruction.operands[0].mem.disp.value] = instruction;
		else if (instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP)
			printf("  -- %50s", AsmToCPP(rsp_stack_map[instruction.operands[1].mem.disp.value]).c_str());
		else if(instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP)
			printf("  -- %50s", AsmToCPP(rbp_stack_map[instruction.operands[1].mem.disp.value]).c_str());
		printf("\n");


		instruction = Decode(current_rip);
		i++;
	}
}

bool Disassembler::Init(uintptr_t address)
{
	current_rip = address;
	return true;
}
