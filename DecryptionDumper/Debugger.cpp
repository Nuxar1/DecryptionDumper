#include "Debugger.h"
#include "PatternScanner.h"
#include <iostream>
#include <stdio.h>
#include <inttypes.h>

Debugger::Debugger()
{
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

bool Debugger::Load_File(std::string exe_path)
{
	STARTUPINFOA startup_info = { 0 };
	startup_info.cb = sizeof(startup_info);
	PROCESS_INFORMATION process_info = { 0 };

	if (!CreateProcessA(exe_path.c_str(), NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &startup_info, &process_info))
	{
		printf("CreateProcess failed with error code: %#X\n", GetLastError());
		return false;
	}

	h_proc = process_info.hProcess;
	h_thread = process_info.hThread;
	process_id = process_info.dwProcessId;
	thread_id = process_info.dwThreadId;
	base_address = read<uintptr_t>(GetContext().Rdx + 0x10); //?? idk why
	return true;
}

CONTEXT Debugger::GetContext()
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(h_thread, &context))
	{
		return CONTEXT();
	}
	return context;
}

bool Debugger::SetContext(CONTEXT* context)
{
	return SetThreadContext(h_thread, context);
}

bool Debugger::SetRIP(uintptr_t address)
{
	CONTEXT c = GetContext();
	c.Rip = address;
	return SetContext(&c);
}

bool Debugger::SetTrapFlag()
{
	CONTEXT c = GetContext();
	c.EFlags |= 0x100;
	return SetContext(&c);
}

uintptr_t Debugger::SingleStep()
{
	SetTrapFlag();
	debug_flags = DebugFlag::step_single;
	Run();
	return GetContext().Rip;
}

uintptr_t Debugger::StepIn()
{
	return SingleStep();
}

uintptr_t Debugger::StepOver()
{
	CONTEXT c = GetContext();
	unsigned char instr[16];
	read_array(c.Rip, instr, 16);

	ZydisDecodedInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, instr, 16,
		&instruction))) {
		char DisassembledString[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);

		if (strstr(DisassembledString, "CALL") || strstr(DisassembledString, "REP") || strstr(DisassembledString, "PUSHF"))
		{
			SetRIP(c.Rip + instruction.length);
			debug_flags = DebugFlag::step_single;
			Run();
			return c.Rip + instruction.length;
		}
		else
			return SingleStep();
	}
}

void Debugger::Run()
{
	switch (debug_status)
	{
	case DebugStatus::suspended:
		ResumeThread(h_thread);
		break;
	case DebugStatus::interrupted:
		ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE);
		break;
	case DebugStatus::none:
	default:
		return;
	}
	DEBUG_EVENT dbg_event;
	while (WaitForDebugEvent(&dbg_event, INFINITE))
	{
		process_id = dbg_event.dwProcessId;
		thread_id = dbg_event.dwThreadId;
		if (DispatchDebugEvent(dbg_event))
			ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE);
		else
			break;
	}
}

bool Debugger::DispatchDebugEvent(const DEBUG_EVENT& debugEvent)
{
	switch (debugEvent.dwDebugEventCode)
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		OnCreateProcessEvent(&debugEvent.u.CreateProcessInfo);
		SetTrapFlag();
		debug_flags = DebugFlag::none;
		return true;
	case CREATE_THREAD_DEBUG_EVENT:
		return true;
		break;
	case LOAD_DLL_DEBUG_EVENT:
		return true;
		break;
	case UNLOAD_DLL_DEBUG_EVENT:
		return true;
		break;
	case EXIT_THREAD_DEBUG_EVENT:
		return true;
		break;
	case EXCEPTION_DEBUG_EVENT:
		//printf("[%i] debug event\n", debugEvent.dwThreadId);
		return OnExceptionEvent(&debugEvent.u.Exception);
		break;
	default:
		printf("unknown event: %#X\n", debugEvent.dwDebugEventCode);
		break;
	}
	return false;
}

bool Debugger::OnCreateProcessEvent(const CREATE_PROCESS_DEBUG_INFO* pInfo)
{
	h_proc = pInfo->hProcess;
	h_thread = pInfo->hThread;
	base_address = (uintptr_t)pInfo->lpBaseOfImage;
	printf("Debugger created! h_T[%#X] h_P[%#X] B[%p]\n", h_thread, h_proc, base_address);

	debug_flags = DebugFlag::none;

	if (pInfo->lpImageName)
		printf("Image Name: %s", pInfo->lpImageName);
	return true;
}

bool Debugger::OnExceptionEvent(const EXCEPTION_DEBUG_INFO* pInfo)
{
	switch (pInfo->ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
		printf("Breakpoint was hit!");
		return true;
		break;
	case 0xC0000005:
		exception_hit = true;
	default:
		debug_status = DebugStatus::interrupted;
		return false;
		break;
	}
}


bool Debugger::Init(std::string exe_path)
{
	Load_File(exe_path);
	Sleep(5000);
	if (!DebugActiveProcess(process_id))
	{
		printf("Failed to attach to process. Error code: %#X", GetLastError());
		debug_status = DebugStatus::none;
		return false;
	}
	printf("T[%#X] P[%#X] B[%p] launched and suspended.\n", thread_id, process_id, base_address);
	debug_status = DebugStatus::suspended;
	SingleStep();
	exception_hit = false;
	scanner = new PatternScanner(this);
	return true;
}

void Debugger::Dump_Process()
{
	IMAGE_DOS_HEADER dos_header = read<IMAGE_DOS_HEADER>(base_address);
	IMAGE_NT_HEADERS64 nt_headers = read<IMAGE_NT_HEADERS64>(base_address + dos_header.e_lfanew);

	// Dump the game binary from memory
	const size_t target_len = nt_headers.OptionalHeader.SizeOfImage;
	auto target = std::unique_ptr<uint8_t[]>(new uint8_t[target_len]);
	if (read_array(base_address, target.get(), target_len)) {
		// Fixup section headers...
		auto pnt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(target.get() + dos_header.e_lfanew);
		auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(
			target.get() +
			static_cast<size_t>(dos_header.e_lfanew) +
			static_cast<size_t>(FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)) +
			static_cast<size_t>(nt_headers.FileHeader.SizeOfOptionalHeader));
		for (size_t i = 0; i < nt_headers.FileHeader.NumberOfSections; i += 1) {
			auto& section = section_headers[i];
			// Rewrite the file offsets to the virtual addresses
			section.PointerToRawData = section.VirtualAddress;
			section.SizeOfRawData = section.Misc.VirtualSize;
			// Rewrite the base relocations to the ".reloc" section
			if (!memcmp(section.Name, ".reloc\0\0", 8)) {
				pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {
					section.VirtualAddress,
					section.Misc.VirtualSize,
				};
			}
		}

		const auto dump_file = CreateFileW(L"cod.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_COMPRESSED, NULL);
		if (dump_file != INVALID_HANDLE_VALUE) {
			if (!WriteFile(dump_file, target.get(), static_cast<DWORD>(target_len), NULL, NULL)) {
				printf("cod(%u) Error writing cod.bin: %u\n", process_id, GetLastError());
			}
			CloseHandle(dump_file);
		}
		else {
			printf("cod(%u) Error writing cod.bin: %u\n", process_id, GetLastError());
		}
		printf("cod(%u) Wrote cod.bin!\n", process_id);
	}
	else {
		printf("cod(%u) Error reading the image from memory!\n", process_id);
	}
}
